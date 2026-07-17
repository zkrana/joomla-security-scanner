<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Factory;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Component\ComponentHelper;

class MuruguardControllerScanner extends BaseController
{
    /**
     * Triggered by the "Run Scan" and "Re-scan" forms.
     * Runs the full filesystem + DB scan, stores results in the session,
     * then redirects back to the display view so the URL stays clean.
     */
public function scan()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app    = Factory::getApplication();
        $input  = $app->input;

        // Large sites (many extensions, big vendor/ trees) can genuinely
        // take longer than a host's default max_execution_time to scan.
        // Try to raise both -- @-suppressed because some hosts disable
        // ini_set entirely, in which case this silently no-ops rather
        // than fatal-ing on its own.
        @set_time_limit(300);
        @ini_set('memory_limit', '512M');

        // Persist the directory picker selection so both this scan and the
        // cached-result re-display honour it. Only overwrite when the gate
        // form actually submitted the picker (the "Re-scan now" button does
        // not, so it reuses the previous selection). An empty selection is
        // treated as "scan everything".
        if ($input->post->get('areas_submitted', 0, 'int') === 1) {
            $areas = $input->post->get('scan_areas', [], 'array');
            $areas = array_values(array_map('strval', $areas));
            $app->getSession()->set('muruguard.scan_areas', $areas);
        }

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');

        try {
            $model->runScan();
        } catch (\Throwable $e) {
            // Don't let a mid-scan failure produce a raw 500 -- redirect
            // back with a clear message instead, so the user gets a
            // working page (and a fresh CSRF token) rather than a dead end.
            $app->enqueueMessage(
                'Scan failed: ' . $e->getMessage() . '. This usually means the scan hit your host\'s PHP execution time or memory limit -- check your PHP error log, or ask your host to raise max_execution_time / memory_limit for this site.',
                'error'
            );
            $this->setRedirect('index.php?option=com_muruguard');
            return;
        }

        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Clears the cached scan result so the directory picker (scan gate)
     * reappears, keeping the previous selection pre-ticked.
     */
    public function reset()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $session = Factory::getApplication()->getSession();
        $session->set('muruguard.filefindings', null);
        $session->set('muruguard.filefindings_time', 0);

        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Delete selected flagged files/folders.
     */
    public function delete()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app     = Factory::getApplication();
        $targets = $app->input->post->get('targets', [], 'array');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->deleteTargets($targets);

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', 'info');
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Surgically clean selected flagged files instead of deleting them --
     * for a legitimate core/template file (index.php, administrator's own
     * index.php, a template's root index.php, a core library file, ...)
     * that has been infected, this strips just the injected code and
     * keeps the file in place, since deleting it would break the site.
     */
    public function cleancode()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app     = Factory::getApplication();
        $targets = $app->input->post->get('targets', [], 'array');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->cleanCodeFiles($targets);

        $combined = implode("\n", $flash);
        $type = 'message';
        if (stripos($combined, 'FAILED') !== false || stripos($combined, 'WARNING') !== false) {
            $type = 'error';
        } elseif (stripos($combined, 'SKIPPED') !== false) {
            $type = 'warning';
        }

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', $type);
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Surgically clean XSS from selected #__menu rows.
     */
    public function cleanmenu()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app = Factory::getApplication();
        $ids = $app->input->post->get('menu_xss_ids', [], 'array');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->cleanMenuXss($ids);

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', 'info');
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Delete selected rogue iconfont rows from #__sppagebuilder_assets.
     */
    public function deleteassets()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app = Factory::getApplication();
        $ids = $app->input->post->get('rogue_asset_ids', [], 'array');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->deleteRogueAssets($ids);

        $app->enqueueMessage('Rogue asset rows deleted.', 'message');
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Webcron entry point for scheduled scanning -- reached as
     * administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=...
     * so any cron system (server crontab via curl/wget, a host's Cron
     * Jobs control panel, or a free external cron service) can trigger a
     * scan without a logged-in admin session. There is deliberately no
     * Session::checkToken()/requireManageAccess() call here -- a cron
     * request has no Joomla session or CSRF token to present -- auth is
     * instead a shared secret (COM_MURUGUARD_CONFIG_CRON_TOKEN) compared
     * with hash_equals(), gated behind an explicit master switch
     * (COM_MURUGUARD_CONFIG_CRON_ENABLED) so disabling it doesn't require
     * clearing/losing the configured token and email. NEVER accepted when
     * the switch is off or either side of the token is empty, so
     * scheduled scanning is off by default.
     *
     * Responds with plain text (not the admin HTML template) and exits
     * immediately, matching how a cron/curl caller expects a response.
     */
    public function scheduledcheck()
    {
        $app = Factory::getApplication();
        $params = ComponentHelper::getParams('com_muruguard');
        $cronEnabled = (bool) $params->get('cron_enabled', 0);
        $configuredToken = trim((string) $params->get('cron_token', ''));
        $suppliedToken = (string) $app->input->getString('token', '');

        header('Content-Type: text/plain; charset=utf-8');

        if (!$cronEnabled || $configuredToken === '' || $suppliedToken === '' || !hash_equals($configuredToken, $suppliedToken)) {
            http_response_code(403);
            echo "Forbidden\n";
            $app->close();
        }

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $result = $model->runScheduledCheck();

        $alertEmail = trim((string) $params->get('alert_email', ''));
        $emailed = false;
        if (!$result['isFirstRun'] && $result['newCount'] > 0 && $alertEmail !== '') {
            $emailed = $this->sendScheduledAlertEmail($alertEmail, $result['newFindings'], $result['newCount']);
        }

        $status = $result['isFirstRun'] ? 'baseline recorded' : 'ok';
        echo "MuRu Guard: {$status}, total={$result['totalCount']} new={$result['newCount']} emailed=" . ($emailed ? 'yes' : 'no') . "\n";
        $app->close();
    }

    /**
     * Sends the "new findings since last scheduled check" alert email.
     * Never throws -- a mail-transport failure shouldn't turn a
     * successful scan into a confusing error response for the cron
     * caller, it should just report emailed=no in the plain-text status.
     */
    private function sendScheduledAlertEmail(string $to, array $newFindings, int $newCount): bool
    {
        $app = Factory::getApplication();
        $siteName = $app->get('sitename', 'your Joomla site');
        $subject = "[MuRu Guard] {$newCount} new suspicious finding" . ($newCount === 1 ? '' : 's') . " on {$siteName}";

        $lines   = [];
        $lines[] = "MuRu Guard found {$newCount} new suspicious file finding" . ($newCount === 1 ? '' : 's') . " since the last scheduled check on {$siteName}.";
        $lines[] = '';
        $shown = 0;
        foreach ($newFindings as $rel => $f) {
            if (++$shown > 25) {
                $lines[] = '… and ' . ($newCount - 25) . ' more -- see the full list in Components > MuRu Guard.';
                break;
            }
            $lines[] = "- [{$f['confidence']}] {$rel}";
            $lines[] = '  ' . $f['reason'];
        }
        $lines[] = '';
        $lines[] = 'Review and act on these in Components > MuRu Guard in your Joomla admin panel.';
        $body = implode("\n", $lines);

        try {
            $mailer = Factory::getMailer();
            $mailer->setSender([$app->get('mailfrom'), $app->get('fromname')]);
            $mailer->addRecipient($to);
            $mailer->setSubject($subject);
            $mailer->isHtml(false);
            $mailer->setBody($body);
            return (bool) $mailer->Send();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Saves the Settings panel's 3 scheduled-scanning fields, reached from
     * the scanner page itself rather than requiring a trip to System >
     * Global Configuration. Writes to the exact same storage Global
     * Configuration uses (see MuruguardModelScanner::saveScheduledSettings()),
     * so both stay in sync automatically.
     */
    public function savesettings()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireManageAccess();

        $app = Factory::getApplication();
        $input = $app->input;

        $cronEnabled = (bool) $input->getInt('cron_enabled', 0);
        $cronToken = trim($input->getString('cron_token', ''));
        $alertEmail = trim($input->getString('alert_email', ''));

        if ($alertEmail !== '' && !filter_var($alertEmail, FILTER_VALIDATE_EMAIL)) {
            $app->enqueueMessage('Settings NOT saved: "' . htmlspecialchars($alertEmail) . '" is not a valid email address.', 'error');
            $this->setRedirect('index.php?option=com_muruguard');
            return;
        }

        if ($cronEnabled && $cronToken === '') {
            $app->enqueueMessage('Settings NOT saved: scheduled scanning can\'t be enabled without a secret token -- set one first.', 'error');
            $this->setRedirect('index.php?option=com_muruguard');
            return;
        }

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->saveScheduledSettings($cronEnabled, $cronToken, $alertEmail);

        $app->enqueueMessage('Settings saved.', 'message');
        $this->setRedirect('index.php?option=com_muruguard');
    }
}
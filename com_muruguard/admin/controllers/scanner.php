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
     * Bulk selection forms (delete/clean actions) submit one checkbox per
     * row -- a large scan result (thousands of flagged files, or hundreds
     * of junk #__template_styles rows) can trip PHP's default
     * max_input_vars (1000) well before Joomla even gets a chance to look
     * at the request, silently truncating the POST body. Depending on
     * where in the field order the truncation lands, this can drop the
     * CSRF token field itself, surfacing as a confusing "invalid security
     * token" error that has nothing to do with the token actually being
     * wrong. The view's JS now consolidates every checked checkbox into a
     * single JSON-encoded hidden field (see muruConsolidateCheckboxes() in
     * default.php) BEFORE submit, so the request carries one field
     * regardless of how many rows are selected. This reads that field
     * first and only falls back to the legacy one-field-per-row array
     * (still emitted by the raw HTML for no-JS resilience) when it's
     * absent or invalid, so old cached page loads / JS-disabled browsers
     * still work exactly as before, just with the original scaling limit.
     */
    private function getBulkField(string $jsonName, string $arrayName): array
    {
        $input = Factory::getApplication()->input;
        $json  = $input->post->get($jsonName, '', 'raw');
        if ($json !== '') {
            $decoded = json_decode($json, true);
            if (is_array($decoded)) {
                return array_values(array_map('strval', $decoded));
            }
        }
        return $input->post->get($arrayName, [], 'array');
    }

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
                Text::sprintf('COM_MURUGUARD_SCAN_FAILED_MSG', $e->getMessage()),
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
        \MuruguardHelper::requireDeleteAccess();

        $app     = Factory::getApplication();
        $targets = $this->getBulkField('targets_json', 'targets');

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
        \MuruguardHelper::requireEditAccess();

        $app     = Factory::getApplication();
        $targets = $this->getBulkField('targets_json', 'targets');

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
        \MuruguardHelper::requireEditAccess();

        $app = Factory::getApplication();
        $ids = $this->getBulkField('menu_xss_ids_json', 'menu_xss_ids');

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
        \MuruguardHelper::requireDeleteAccess();

        $app = Factory::getApplication();
        $ids = $this->getBulkField('rogue_asset_ids_json', 'rogue_asset_ids');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->deleteRogueAssets($ids);

        $app->enqueueMessage(Text::_('COM_MURUGUARD_ASSETS_DELETED_MSG'), 'message');
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /**
     * Deletes selected #__template_styles rows that MuruguardModelScanner::
     * cleanTemplateDefacement() independently confirms as junk/injected.
     * Rows flagged only for defacement text are left for manual review --
     * see that method's docblock for why.
     */
    public function cleantemplatedefacement()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireDeleteAccess();

        $app = Factory::getApplication();
        $ids = $this->getBulkField('template_defacement_ids_json', 'template_defacement_ids');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->cleanTemplateDefacement($ids);

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', 'info');
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
        \MuruguardHelper::requireAdminAccess();

        $app = Factory::getApplication();
        $input = $app->input;

        $cronEnabled = (bool) $input->getInt('cron_enabled', 0);
        $cronToken = trim($input->getString('cron_token', ''));
        $alertEmail = trim($input->getString('alert_email', ''));

        if ($alertEmail !== '' && !filter_var($alertEmail, FILTER_VALIDATE_EMAIL)) {
            $app->enqueueMessage(Text::sprintf('COM_MURUGUARD_SETTINGS_INVALID_EMAIL', htmlspecialchars($alertEmail)), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }

        if ($cronEnabled && $cronToken === '') {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_SETTINGS_NEEDS_TOKEN'), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->saveScheduledSettings($cronEnabled, $cronToken, $alertEmail);

        $app->enqueueMessage(Text::_('COM_MURUGUARD_SETTINGS_SAVED_MSG'), 'message');
        $this->setRedirect($this->settingsRedirectUrl());
    }

    /**
     * Every Settings-saving action redirects here instead of a bare
     * 'index.php?option=com_muruguard' -- that used to drop the admin
     * back on the Dashboard panel entirely, and even when it did include
     * view_panel=settings, the settings sub-tab itself always reset to
     * whichever one is hardcoded "active" in the markup (Protection)
     * regardless of which tab the save actually came from. settings_tab
     * is filled in client-side right before submit (see the generic
     * form-submit listener in default.php) with whichever tab was open
     * at the time.
     */
    private function settingsRedirectUrl(): string
    {
        $tab = Factory::getApplication()->input->getCmd('settings_tab', '');
        $validTabs = ['protection', 'iplist', 'scheduled', 'guide'];
        $tab = in_array($tab, $validTabs, true) ? $tab : 'protection';
        return 'index.php?option=com_muruguard&view_panel=settings&settings_tab=' . $tab;
    }

    /**
     * Saves the Protection Mode settings the companion
     * plg_system_muruguardshield plugin reads on every request. Same
     * storage/permission level as savesettings() above -- this only
     * controls the plugin's behaviour, it does not check whether that
     * plugin is actually installed/enabled (the Settings panel surfaces
     * that separately so the admin isn't misled by a setting with no
     * effect).
     */
    public function saveshieldsettings()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        $app   = Factory::getApplication();
        $input = $app->input;

        $enabled          = (bool) $input->getInt('shield_enabled', 0);
        $blockPatterns    = (bool) $input->getInt('shield_block_patterns', 0);
        $blockBruteForce  = (bool) $input->getInt('shield_block_bruteforce', 0);
        $threshold        = $input->getInt('shield_bruteforce_threshold', 5);
        $window           = $input->getInt('shield_bruteforce_window', 15);
        $blockUserAgents  = (bool) $input->getInt('shield_block_useragents', 0);
        $blockCountries   = (bool) $input->getInt('shield_block_countries', 0);
        $blockedCountries = $input->getString('shield_blocked_countries', '');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->saveShieldSettings(
            $enabled,
            $blockPatterns,
            $blockBruteForce,
            $threshold,
            $window,
            $blockUserAgents,
            $blockCountries,
            $blockedCountries
        );

        $app->enqueueMessage(Text::_('COM_MURUGUARD_SETTINGS_SAVED_MSG'), 'message');
        $this->setRedirect($this->settingsRedirectUrl());
    }

    /**
     * MuRu Shield Hardening: activates the /administrator HTTP Basic
     * Auth gate. The password itself is never round-tripped back from
     * the server -- the "Generate securely" button fills the form
     * fields client-side, so the browser (and the admin looking at the
     * screen) already has it before this ever submits; the model
     * self-tests with real outbound requests and rolls back
     * automatically on any failure (see MuruguardHardeningHelper).
     */
    public function activatebackendauth()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        $app = Factory::getApplication();
        $username = trim($app->input->getString('backend_auth_username', ''));
        $password = (string) $app->input->get('backend_auth_password', '', 'raw');
        $repeat   = (string) $app->input->get('backend_auth_password_repeat', '', 'raw');

        if ($username === '' || $password === '') {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_MISSING_FIELDS_MSG'), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }
        if (strlen($password) < 8) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_PASSWORD_TOO_SHORT_MSG'), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }
        if ($password !== $repeat) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_PASSWORD_MISMATCH_MSG'), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }

        @ini_set('memory_limit', '256M');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $result = $model->activateBackendAuth($username, $password);

        if ($result['ok']) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_ACTIVATED_MSG'), 'message');
        } else {
            $app->enqueueMessage(Text::sprintf('COM_MURUGUARD_HARDENING_FAILED_MSG', $result['reason']), 'error');
        }
        $this->setRedirect($this->settingsRedirectUrl());
    }

    public function deactivatebackendauth()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->deactivateBackendAuth();

        Factory::getApplication()->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_DEACTIVATED_MSG'), 'message');
        $this->setRedirect($this->settingsRedirectUrl());
    }

    /**
     * Extends the SAME backend credentials to the whole site. Requires
     * re-typing the current backend password (never persisted in
     * plaintext -- see activateBackendAuth()'s docblock) so the model
     * can confirm it's actually correct before writing anything.
     */
    public function activateemergencymode()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        $app = Factory::getApplication();
        $username = trim($app->input->getString('emergency_username', ''));
        $password = (string) $app->input->get('emergency_password', '', 'raw');

        if ($username === '' || $password === '') {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_HARDENING_MISSING_FIELDS_MSG'), 'error');
            $this->setRedirect($this->settingsRedirectUrl());
            return;
        }

        @ini_set('memory_limit', '256M');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $result = $model->activateEmergencyMode($username, $password);

        if ($result['ok']) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_EMERGENCY_ACTIVATED_MSG'), 'message');
        } else {
            $app->enqueueMessage(Text::sprintf('COM_MURUGUARD_HARDENING_FAILED_MSG', $result['reason']), 'error');
        }
        $this->setRedirect($this->settingsRedirectUrl());
    }

    public function deactivateemergencymode()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->deactivateEmergencyMode();

        Factory::getApplication()->enqueueMessage(Text::_('COM_MURUGUARD_EMERGENCY_DEACTIVATED_MSG'), 'message');
        $this->setRedirect($this->settingsRedirectUrl());
    }

    /**
     * Adds one entry to the manual IP Access List (see
     * MuruguardHelper::addIpListEntry() for validation/storage). Same
     * admin-level permission as changing Protection Mode settings, since
     * a wrong entry here can lock an admin out of the site.
     */
    public function addipentry()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        $app   = Factory::getApplication();
        $input = $app->input;

        $value = $input->getString('ip_value', '');
        $mode  = $input->getString('ip_mode', 'block');
        $note  = $input->getString('ip_note', '');

        $result = \MuruguardHelper::addIpListEntry($value, $mode, $note);
        if ($result['ok']) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_IPLIST_ADDED_MSG'), 'message');
        } else {
            $app->enqueueMessage(htmlspecialchars($result['error']), 'error');
        }

        $this->setRedirect($this->settingsRedirectUrl());
    }

    /** Removes one entry from the manual IP Access List. */
    public function removeipentry()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        $id = Factory::getApplication()->input->getString('ip_id', '');
        if ($id !== '') {
            \MuruguardHelper::removeIpListEntry($id);
        }

        Factory::getApplication()->enqueueMessage(Text::_('COM_MURUGUARD_IPLIST_REMOVED_MSG'), 'message');
        $this->setRedirect($this->settingsRedirectUrl());
    }

    /**
     * Dismisses a single finding as a false positive ("Mark as Safe" on
     * its row) -- see MuruguardHelper::addFalsePositive()/
     * fingerprintReasons() for why this is keyed on the exact reasons
     * text, not just the path/row-id, so a later genuine compromise of
     * the same path/row isn't silently hidden by an old dismissal. Same
     * edit-level permission as Clean, since dismissing a security finding
     * is a comparable judgment call.
     */
    public function markfalsepositive()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireEditAccess();

        $app   = Factory::getApplication();
        $input = $app->input;

        $category    = $input->getCmd('fp_category', '');
        $identifier  = $input->getString('fp_identifier', '');
        $fingerprint = $input->getString('fp_fingerprint', '');
        $note        = $input->getString('fp_note', '');

        $result = \MuruguardHelper::addFalsePositive($category, $identifier, $fingerprint, $note);
        if ($result['ok']) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_FP_MARKED_MSG'), 'message');
            // The scan-results page reads from a 5-minute session cache, not
            // a fresh scan, on every load -- without invalidating it here,
            // a dismissal was saved correctly but the very next reload kept
            // showing the same stale pre-dismissal list, making it look like
            // nothing happened. Same cache-busting the delete/clean actions
            // already do after their own mutations.
            $session = $app->getSession();
            $session->set('muruguard.filefindings', null);
            $session->set('muruguard.filefindings_time', 0);
        } else {
            $app->enqueueMessage(htmlspecialchars($result['error']), 'error');
        }

        $this->setRedirect('index.php?option=com_muruguard');
    }

    /** Reverses a "Mark as Safe" dismissal, making the finding reappear on the next scan. */
    public function unmarkfalsepositive()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireEditAccess();

        $id = Factory::getApplication()->input->getString('fp_id', '');
        if ($id !== '') {
            \MuruguardHelper::removeFalsePositive($id);
        }

        // Same reasoning as markfalsepositive() above -- without this, an
        // un-dismissed finding wouldn't reappear until the cache happened
        // to expire or the user manually re-scanned.
        $session = Factory::getApplication()->getSession();
        $session->set('muruguard.filefindings', null);
        $session->set('muruguard.filefindings_time', 0);

        Factory::getApplication()->enqueueMessage(Text::_('COM_MURUGUARD_FP_UNMARKED_MSG'), 'message');
        $this->setRedirect('index.php?option=com_muruguard');
    }

    /** Submits the dashboard's "get security alerts & updates" banner. Edit access only -- same bar as changing any other Settings-adjacent option. */
    public function subscribenewsletter()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireEditAccess();

        $app   = Factory::getApplication();
        $name  = $app->input->getString('newsletter_name', '');
        $email = $app->input->getString('newsletter_email', '');

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        if ($model->subscribeToNewsletter($name, $email)) {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_NEWSLETTER_SUBSCRIBED_MSG'), 'message');
        } else {
            $app->enqueueMessage(Text::_('COM_MURUGUARD_NEWSLETTER_FAILED_MSG'), 'error');
        }

        $this->setRedirect('index.php?option=com_muruguard');
    }

    /** Dismisses the newsletter banner without subscribing -- never shown again on this site. */
    public function dismissnewsletter()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireEditAccess();

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->dismissNewsletterBanner();

        $this->setRedirect('index.php?option=com_muruguard');
    }

    /** Clears the Protection Log. Requires the same admin-level permission as changing settings, since it's destroying a security audit trail, not just tidying a scan result. */
    public function clearattacklog()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
        \MuruguardHelper::requireAdminAccess();

        \MuruguardHelper::clearAttackLog();

        Factory::getApplication()->enqueueMessage(Text::_('COM_MURUGUARD_ATTACK_LOG_CLEARED_MSG'), 'message');
        $this->setRedirect('index.php?option=com_muruguard');
    }
}
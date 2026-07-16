<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Factory;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Language\Text;

class SppbscanControllerScanner extends BaseController
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
            $app->getSession()->set('sppbscan.scan_areas', $areas);
        }

        /** @var SppbscanModelScanner $model */
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
            $this->setRedirect('index.php?option=com_sppbscan');
            return;
        }

        $this->setRedirect('index.php?option=com_sppbscan');
    }

    /**
     * Clears the cached scan result so the directory picker (scan gate)
     * reappears, keeping the previous selection pre-ticked.
     */
    public function reset()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $session = Factory::getApplication()->getSession();
        $session->set('sppbscan.filefindings', null);
        $session->set('sppbscan.filefindings_time', 0);

        $this->setRedirect('index.php?option=com_sppbscan');
    }

    /**
     * Delete selected flagged files/folders.
     */
    public function delete()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app     = Factory::getApplication();
        $targets = $app->input->post->get('targets', [], 'array');

        /** @var SppbscanModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->deleteTargets($targets);

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', 'info');
        $this->setRedirect('index.php?option=com_sppbscan');
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

        /** @var SppbscanModelScanner $model */
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
        $this->setRedirect('index.php?option=com_sppbscan');
    }

    /**
     * Surgically clean XSS from selected #__menu rows.
     */
    public function cleanmenu()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app = Factory::getApplication();
        $ids = $app->input->post->get('menu_xss_ids', [], 'array');

        /** @var SppbscanModelScanner $model */
        $model = $this->getModel('Scanner');
        $flash = $model->cleanMenuXss($ids);

        $app->enqueueMessage('<pre>' . implode("\n", array_map('htmlspecialchars', $flash)) . '</pre>', 'info');
        $this->setRedirect('index.php?option=com_sppbscan');
    }

    /**
     * Delete selected rogue iconfont rows from #__sppagebuilder_assets.
     */
    public function deleteassets()
    {
        Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));

        $app = Factory::getApplication();
        $ids = $app->input->post->get('rogue_asset_ids', [], 'array');

        /** @var SppbscanModelScanner $model */
        $model = $this->getModel('Scanner');
        $model->deleteRogueAssets($ids);

        $app->enqueueMessage('Rogue asset rows deleted.', 'message');
        $this->setRedirect('index.php?option=com_sppbscan');
    }
}
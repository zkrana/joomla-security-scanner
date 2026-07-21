<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Component\ComponentHelper;

require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';

class MuruguardViewScanner extends HtmlView
{
    public $fileFindings = [];
    public $dbFindings = [];
    public $highCount = 0;
    public $medCount = 0;
    public $scanned = false;
    public $scanStartedAt = 0;
    public $sppbWarning = null;
    public $scanAreas = [];
    public $selectedAreas = [];
    public $cronEnabled = false;
    public $cronToken = '';
    public $alertEmail = '';
    public $lastScheduledRun = null;
    public $canDelete = false;
    public $canEdit = false;
    public $canAdmin = false;
    public $shieldEnabled = false;
    public $shieldBlockPatterns = false;
    public $shieldBlockBruteForce = false;
    public $shieldThreshold = 5;
    public $shieldWindow = 15;
    public $shieldPluginActive = false;
    public $attackLog = [];

    public function display($tpl = null)
    {
        MuruguardHelper::requireManageAccess();

        $app     = Factory::getApplication();
        $session = $app->getSession();

        // What this specific user is authorised to DO, not just view -- the
        // template uses these to hide/disable Delete, Clean, and Settings
        // actions a user's ACL group doesn't grant, rather than showing a
        // button that would just 403 on click.
        $this->canDelete = MuruguardHelper::canDelete();
        $this->canEdit   = MuruguardHelper::canEdit();
        $this->canAdmin  = MuruguardHelper::canAdmin();

        /** @var MuruguardModelScanner $model */
        $model = $this->getModel('Scanner');

        // Show SPPB version warning
        $this->sppbWarning = $model->getSppbVersionWarning();

        // Directory-picker definitions + the user's last selection.
        $this->scanAreas     = MuruguardHelper::getScanAreas();
        $this->selectedAreas = (array) $session->get('muruguard.scan_areas', []);

        // Scheduled-scanning settings, for the in-page Settings panel --
        // the exact same storage System > Global Configuration reads/
        // writes, so both stay in sync with each other automatically.
        $cfgParams = ComponentHelper::getParams('com_muruguard');
        $this->cronEnabled = (bool) $cfgParams->get('cron_enabled', 0);
        $this->cronToken   = (string) $cfgParams->get('cron_token', '');
        $this->alertEmail  = (string) $cfgParams->get('alert_email', '');
        $this->lastScheduledRun = $model->getLastScheduledRunTime();

        // Protection Mode settings + audit log, for the in-page Settings
        // panel and the new Protection Log tab -- same params blob the
        // plg_system_muruguardshield plugin reads on every request.
        $this->shieldEnabled         = (bool) $cfgParams->get('shield_enabled', 0);
        $this->shieldBlockPatterns   = (bool) $cfgParams->get('shield_block_patterns', 0);
        $this->shieldBlockBruteForce = (bool) $cfgParams->get('shield_block_bruteforce', 0);
        $this->shieldThreshold       = (int) $cfgParams->get('shield_bruteforce_threshold', 5);
        $this->shieldWindow          = (int) $cfgParams->get('shield_bruteforce_window', 15);
        $this->shieldPluginActive    = $model->isShieldPluginActive();
        $this->attackLog             = MuruguardHelper::getAttackLog();

        // Restore cached scan results
        $cachedAt = (int) $session->get('muruguard.filefindings_time', 0);
        $hasCache = $cachedAt > 0 && (time() - $cachedAt) < 300;

        if ($hasCache) {
            $this->fileFindings = $model->getFileFindings();
            $this->dbFindings   = $model->getDbFindings();

            $this->highCount = count(array_filter(
                $this->fileFindings,
                function ($f) {
                    return isset($f['confidence']) && $f['confidence'] === 'high';
                }
            ));

            $this->medCount      = count($this->fileFindings) - $this->highCount;
            $this->scanned       = true;
            $this->scanStartedAt = $cachedAt;
        }

        $this->addToolbar();

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        ToolbarHelper::title(Text::_('COM_MURUGUARD_TITLE'), 'shield');

        // Show Preferences only if the helper supports it
        if (method_exists('ToolbarHelper', 'preferences')) {
            ToolbarHelper::preferences('com_muruguard');
        }

        // Help button intentionally omitted for Joomla 3/4/5/6 compatibility.
    }
}
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

    public function display($tpl = null)
    {
        MuruguardHelper::requireManageAccess();

        $app     = Factory::getApplication();
        $session = $app->getSession();

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
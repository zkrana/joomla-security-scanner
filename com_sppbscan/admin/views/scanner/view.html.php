<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

require_once JPATH_ADMINISTRATOR . '/components/com_sppbscan/helpers/sppbscan.php';

class SppbscanViewScanner extends HtmlView
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

    public function display($tpl = null)
    {
        SppbscanHelper::requireManageAccess();

        $app     = Factory::getApplication();
        $session = $app->getSession();

        /** @var SppbscanModelScanner $model */
        $model = $this->getModel('Scanner');

        // Show SPPB version warning
        $this->sppbWarning = $model->getSppbVersionWarning();

        // Directory-picker definitions + the user's last selection.
        $this->scanAreas     = SppbscanHelper::getScanAreas();
        $this->selectedAreas = (array) $session->get('sppbscan.scan_areas', []);

        // Restore cached scan results
        $cachedAt = (int) $session->get('sppbscan.filefindings_time', 0);
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
        ToolbarHelper::title(Text::_('COM_SPPBSCAN_TITLE'), 'shield');

        // Show Preferences only if the helper supports it
        if (method_exists('ToolbarHelper', 'preferences')) {
            ToolbarHelper::preferences('com_sppbscan');
        }

        // Help button intentionally omitted for Joomla 3/4/5/6 compatibility.
    }
}
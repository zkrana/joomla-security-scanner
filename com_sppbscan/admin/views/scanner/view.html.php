<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Factory;

require_once JPATH_ADMINISTRATOR . '/components/com_sppbscan/helpers/sppbscan.php';

class SppbscanViewScanner extends HtmlView
{
    public $fileFindings;
    public $dbFindings;
    public $highCount;
    public $medCount;
    public $scanned       = false;
    public $scanStartedAt = 0;
    public $sppbWarning   = null;

    public function display($tpl = null)
    {
        SppbscanHelper::requireManageAccess();

        $app     = Factory::getApplication();
        $session = $app->getSession();

        // Always load the model — needed for getSppbVersionWarning()
        // regardless of whether a scan cache exists.
        /** @var SppbscanModelScanner $model */
        $model = $this->getModel('Scanner');

        // SPPB version warning is shown on every page load, not just after a scan.
        $this->sppbWarning = $model->getSppbVersionWarning();

        // Only populate scan results when a valid cache exists.
        // The "Run Scan" button (task=scanner.scan) populates the cache;
        // without it we just show the splash screen.
        $cachedAt = (int) $session->get('sppbscan.filefindings_time', 0);
        $hasCache = $cachedAt > 0 && (time() - $cachedAt) < 300;

        if ($hasCache) {
            $this->fileFindings  = $model->getFileFindings();
            $this->dbFindings    = $model->getDbFindings();
            $this->highCount     = count(array_filter($this->fileFindings, fn($f) => $f['confidence'] === 'high'));
            $this->medCount      = count($this->fileFindings) - $this->highCount;
            $this->scanned       = true;
            $this->scanStartedAt = $cachedAt;
        }

        $this->addToolbar();
        parent::display($tpl);
    }

    protected function addToolbar(): void
    {
        ToolbarHelper::title(Text::_('COM_SPPBSCAN_TITLE'), 'shield');
    }
}
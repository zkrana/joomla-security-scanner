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
    public ?array $registeredTemplates = null;
    public array $htaccess = [];
    public $shieldBlockUserAgents = false;
    public $shieldBlockCountries = false;
    public $shieldBlockedCountries = '';
    public array $ipList = [];
    public array $falsePositives = [];
    public string $componentVersion = '';
    public string $activePanel = 'dashboard';

    public function display($tpl = null)
    {
        MuruguardHelper::requireManageAccess();

        // Read straight from the manifest on disk rather than the DB's
        // manifest_cache -- accurate even if files were ever overwritten
        // outside Joomla's own installer/updater flow (manifest_cache
        // only refreshes on an actual install/update through Joomla).
        $manifestPath = JPATH_ADMINISTRATOR . '/components/com_muruguard/muruguard.xml';
        if (is_file($manifestPath)) {
            $manifestXml = @simplexml_load_file($manifestPath);
            if ($manifestXml !== false) {
                $this->componentVersion = (string) $manifestXml->version;
            }
        }

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

        // .htaccess hardening advisor -- read-only, cheap (one file read +
        // a handful of regexes), so it's always available regardless of
        // whether a scan has been run yet.
        $this->htaccess = MuruguardHelper::getHtaccessSuggestions(JPATH_ROOT);

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
        $this->shieldBlockUserAgents = (bool) $cfgParams->get('shield_block_useragents', 0);
        $this->shieldBlockCountries  = (bool) $cfgParams->get('shield_block_countries', 0);
        $this->shieldBlockedCountries = (string) $cfgParams->get('shield_blocked_countries', '');
        $this->ipList                = MuruguardHelper::getIpList();
        $this->falsePositives        = MuruguardHelper::getFalsePositives();

        // Restore cached scan results
        $cachedAt = (int) $session->get('muruguard.filefindings_time', 0);
        $hasCache = $cachedAt > 0 && (time() - $cachedAt) < 300;

        if ($hasCache) {
            $this->fileFindings = $model->getFileFindings();
            $this->dbFindings   = $model->getDbFindings();

            // Same #__extensions registry cross-check scanFilesystem()/
            // deleteTargets() already use server-side (see
            // getRegisteredTemplates()) -- the template needs it too so
            // the Suspicious-vs-Cleanable tab routing for a template-root
            // index.php finding uses the strongest available signal, not
            // just the weaker on-disk manifest check.
            $this->registeredTemplates = $model->getRegisteredTemplates();

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

        // Which panel the left sidebar submenu (see addSubmenu()) should
        // land on -- a plain custom query param rather than Joomla's
        // reserved &layout=, since there's deliberately no separate
        // tmpl/settings.php / tmpl/support.php file: this component is
        // still one page with everything on it, the submenu just jumps
        // straight to the right part of it (auto-opening the existing
        // Settings panel / Support section client-side) rather than a
        // full page reload into isolated views, which would mean
        // duplicating the scan-results header/stats across three
        // separate templates for no real benefit.
        $requestedPanel = $app->input->getCmd('view_panel', 'dashboard');
        $this->activePanel = in_array($requestedPanel, ['dashboard', 'settings', 'support'], true) ? $requestedPanel : 'dashboard';

        $this->addToolbar();
        $this->addSubmenu();

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

    /**
     * Left-sidebar submenu (Dashboard / Settings / Support), the same
     * mechanism com_content/com_banners/... and third-party components
     * like SP Page Builder use for their own multi-page navigation.
     */
    protected function addSubmenu(): void
    {
        \Joomla\CMS\HTML\HTMLHelper::_(
            'sidebar.addEntry',
            Text::_('COM_MURUGUARD_SUBMENU_DASHBOARD'),
            'index.php?option=com_muruguard&view_panel=dashboard',
            $this->activePanel === 'dashboard'
        );
        \Joomla\CMS\HTML\HTMLHelper::_(
            'sidebar.addEntry',
            Text::_('COM_MURUGUARD_SUBMENU_SETTINGS'),
            'index.php?option=com_muruguard&view_panel=settings',
            $this->activePanel === 'settings'
        );
        \Joomla\CMS\HTML\HTMLHelper::_(
            'sidebar.addEntry',
            Text::_('COM_MURUGUARD_SUBMENU_SUPPORT'),
            'index.php?option=com_muruguard&view_panel=support',
            $this->activePanel === 'support'
        );
    }
}
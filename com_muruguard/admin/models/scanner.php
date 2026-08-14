<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Model\BaseDatabaseModel;
use Joomla\CMS\Factory;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Language\Text;

require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';

/**
 * Internal control-flow signal only -- thrown from inside scanFilesystem()'s
 * walkDir() callback when a chunked scan's wall-clock deadline is reached
 * mid-directory, caught one level up around that single area's walk so the
 * area is marked truncated and the next chunk request can move on to the
 * next area instead of the whole HTTP request running past a host's
 * execution-time limit. Never escapes scanFilesystem() itself.
 */
class MuruguardScanChunkTimeout extends \RuntimeException
{
}

class MuruguardModelScanner extends BaseDatabaseModel
{
    protected string $root;
    protected array $fileFindings = [];
    protected array $dbFindings = [
        'superusers' => [], 'menu_xss' => [], 'sppb_assets' => [],
        'rogue_iconfont' => [], 'template_defacement' => [],
    ];
    protected array $seenAbs = [];
    protected ?array $registeredTemplatesCache = null;
    protected ?array $registeredPluginsCache = null;
    protected ?array $registeredComponentsCache = null;
    // Areas whose walk was cut off by a chunk deadline mid-directory rather
    // than finishing naturally -- see MuruguardScanChunkTimeout. Surfaced by
    // runScanChunk() so a pathologically large single folder is reported
    // honestly as "scanned up to the time budget" instead of silently
    // passing as complete.
    protected array $truncatedAreas = [];

    public function __construct($config = [])
    {
        parent::__construct($config);
        $this->root = JPATH_ROOT;
    }

    /**
     * Joomla's own #__extensions table is the actual source of truth for
     * "is this template really installed" -- a real, in-the-wild attack
     * seen on a live site faked EVERY filesystem-level signal at once
     * (the template folder, a templateDetails.xml manifest inside it, and
     * a matching #__template_styles row), so a check based purely on
     * what's sitting on disk can be, and was, fully spoofed. It could not,
     * however, make its faked #__extensions rows enabled -- every one of
     * them was left at enabled=0, unlike every genuinely-installed
     * template. Returns ['<client_id>|<element lowercase>' => enabled
     * (bool)] for every row of type "template", built once per request
     * and shared by both scanFilesystem() and scanDatabase() so a single
     * DB scan (in runScheduledCheck()) only queries this once. Public so
     * the view layer can also cross-reference it when deciding which tab
     * (Suspicious vs Cleanable) a template-root index.php finding
     * belongs in -- see default.php's $notDeletable closure.
     */
    public function getRegisteredTemplates(): ?array
    {
        if ($this->registeredTemplatesCache !== null) {
            return $this->registeredTemplatesCache;
        }

        try {
            $registry = [];
            $db = $this->getDatabase();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['element', 'client_id', 'enabled']))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('template'));
            $db->setQuery($query);
            foreach ($db->loadAssocList() ?: [] as $row) {
                $key = ((int) $row['client_id']) . '|' . strtolower((string) $row['element']);
                $registry[$key] = (bool) $row['enabled'];
            }
        } catch (\Throwable $e) {
            // Query failed for some reason -- return null (not an empty
            // array) so callers fall back to weaker filesystem-only
            // signals instead of treating a failed query as "definitely no
            // templates are registered", which would flood false positives.
            return null;
        }

        return $this->registeredTemplatesCache = $registry;
    }

    /**
     * Same idea as getRegisteredTemplates(), for plugins -- a real, live
     * compromise dropped fake plugin folders (plugins/system/data,
     * plugins/system/loader, plugins/system/core, ...) each holding a
     * self-decoding backdoor, WITH matching #__extensions rows.
     *
     * IMPORTANT: unlike templates, "enabled=0" is NOT a reliable fake
     * signal for plugins on its own -- a stock Joomla install ships
     * several genuinely core plugins disabled by default (e.g.
     * plg_authentication_ldap, plg_api-authentication_basic), so a naive
     * "disabled = suspicious" check flags every real site running with
     * Joomla's own defaults. Only a completely MISSING #__extensions row
     * (checkJunkExtensionFolder() checks array_key_exists against this
     * map) is used as the structural signal; "enabled" is still returned
     * here for callers that want it, but is deliberately not treated as
     * suspicious by itself. Components were also faked in that attack but
     * with enabled=1 -- see getRegisteredComponents() for why that needs
     * yet another signal (manifest_cache, not enabled). Returns
     * ['<folder>|<element lowercase>' => enabled (bool)] for every row of
     * type "plugin" (folder = the plugin group, e.g. "system"; element =
     * the plugin name, e.g. "log" -- together they match a
     * plugins/<folder>/<element> path).
     */
    protected function getRegisteredPlugins(): ?array
    {
        if ($this->registeredPluginsCache !== null) {
            return $this->registeredPluginsCache;
        }

        try {
            $registry = [];
            $db = $this->getDatabase();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['element', 'folder', 'enabled']))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'));
            $db->setQuery($query);
            foreach ($db->loadAssocList() ?: [] as $row) {
                $key = strtolower((string) $row['folder']) . '|' . strtolower((string) $row['element']);
                $registry[$key] = (bool) $row['enabled'];
            }
        } catch (\Throwable $e) {
            return null;
        }

        return $this->registeredPluginsCache = $registry;
    }

    /**
     * Components equivalent of getRegisteredTemplates()/getRegisteredPlugins()
     * -- but keyed on a DIFFERENT signal. A real, live compromise faked
     * components/com_feed, com_stat, com_base, com_track, com_util with
     * matching #__extensions rows left ENABLED (unlike the disabled fake
     * template/plugin rows), so "enabled" doesn't discriminate here at
     * all. What a raw SQL-inserted fake row realistically won't have is a
     * populated manifest_cache -- Joomla's installer generates this JSON
     * blob (name, version, description, ...) from the extension's XML
     * manifest at install time for every genuinely-installed extension,
     * including every core component; an attacker forging a single
     * #__extensions row directly has no reason to also hand-craft a
     * matching manifest_cache blob. Returns ['<element lowercase>' =>
     * hasManifestCache (bool)] for every row of type "component".
     */
    protected function getRegisteredComponents(): ?array
    {
        if ($this->registeredComponentsCache !== null) {
            return $this->registeredComponentsCache;
        }

        try {
            $registry = [];
            $db = $this->getDatabase();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['element', 'manifest_cache']))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('component'));
            $db->setQuery($query);
            foreach ($db->loadAssocList() ?: [] as $row) {
                $key = strtolower((string) $row['element']);
                $cache = trim((string) $row['manifest_cache']);
                $registry[$key] = $cache !== '' && $cache !== '{}' && strtolower($cache) !== 'null';
            }
        } catch (\Throwable $e) {
            return null;
        }

        return $this->registeredComponentsCache = $registry;
    }

    /**
     * The scan areas the user ticked in the pre-scan directory picker.
     * Stored in the session so both the fresh scan and the cached-result
     * re-display honour the same selection. An empty selection means
     * "scan everything" (backwards-compatible default).
     */
    protected function selectedAreas(): array
    {
        return (array) Factory::getApplication()->getSession()->get('muruguard.scan_areas', []);
    }

    /** True if $key was selected (or if nothing was explicitly selected). */
    protected function isAreaSelected(string $key): bool
    {
        $sel = $this->selectedAreas();
        return empty($sel) || in_array($key, $sel, true);
    }

    // ------------------------------------------------------------------
    // Public accessors used by the view
    // ------------------------------------------------------------------

    public function getFileFindings(): array
    {
        $session = Factory::getApplication()->getSession();
        $forceRescan = Factory::getApplication()->input->getBool('rescan', false);

        if (!$forceRescan) {
            $cached = $session->get('muruguard.filefindings');
            $cachedAt = $session->get('muruguard.filefindings_time', 0);
            if (is_array($cached) && (time() - $cachedAt) < 300) {
                $this->fileFindings = $cached;
                return $this->fileFindings;
            }
        }

        $this->scanFilesystem();
        $session->set('muruguard.filefindings', $this->fileFindings);
        $session->set('muruguard.filefindings_time', time());
        return $this->fileFindings;
    }

    public function getDbFindings(): array
    {
        $this->scanDatabase();
        return $this->dbFindings;
    }

    /** True if a scan result is already sitting in the session cache. */
    public function hasCachedScan(): bool
    {
        $cached = Factory::getApplication()->getSession()->get('muruguard.filefindings');
        return is_array($cached);
    }

    /**
     * Called by the controller's scan() task.
     * Forces a fresh filesystem walk, stores result in session, returns time.
     */
    public function runScan(): int
    {
        $session = Factory::getApplication()->getSession();
        $this->scanFilesystem();
        $now = time();
        $session->set('muruguard.filefindings', $this->fileFindings);
        $session->set('muruguard.filefindings_time', $now);
        return $now;
    }

    /**
     * Full scan + diff-against-last-run, for the scheduled/webcron entry
     * point (see ScannerController::scheduledcheck()). There's no HTTP
     * session in a cron context, so the set of finding keys from the
     * PREVIOUS run is persisted in a small JSON file this component owns
     * (see loadLastScanKeys()/saveLastScanKeys() below) rather than the
     * session -- no new DB table, and deliberately NOT the component's
     * config params (see scanHistoryFilePath() for why).
     *
     * Deliberately never sends anything itself -- it only decides WHAT is
     * new, so the Joomla-Mailer-specific code stays in the controller.
     * On the very first run ever (no previous snapshot exists yet) this
     * only records a baseline and reports isFirstRun = true, so the
     * caller can skip alerting on a site's entire pre-existing finding
     * list the first time this ever runs.
     */
    public function runScheduledCheck(): array
    {
        $this->scanFilesystem();
        $this->scanDatabase();

        $currentKeys = array_keys($this->fileFindings);
        sort($currentKeys);

        $previousKeys = $this->loadLastScanKeys();
        $this->saveLastScanKeys($currentKeys);

        $newKeys = $previousKeys === null ? [] : array_values(array_diff($currentKeys, $previousKeys));
        $newFindings = [];
        foreach ($newKeys as $rel) {
            if (isset($this->fileFindings[$rel])) $newFindings[$rel] = $this->fileFindings[$rel];
        }

        return [
            'newFindings' => $newFindings,
            'newCount'    => count($newFindings),
            'totalCount'  => count($this->fileFindings),
            'isFirstRun'  => $previousKeys === null,
        ];
    }

    /**
     * Deliberately a plain JSON file under this component's own data/
     * folder, NOT a key inside #__extensions.params -- Joomla's own
     * Global Configuration save for this component replaces that whole
     * params blob with just the config.xml-declared fields, which would
     * silently wipe an internal bookkeeping key living there every time
     * an admin saves Options, with no error or warning. A dedicated file
     * is immune to that entirely and needs no schema/migration.
     */
    private function scanHistoryFilePath(): string
    {
        $new = JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/scan-history.php';
        MuruguardHelper::migrateLegacyDataFile(JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/scan-history.json', $new);
        return $new;
    }

    /** Null means the scheduled check has never run on this site. For the Settings panel's "Last run" indicator. */
    public function getLastScheduledRunTime(): ?int
    {
        $path = $this->scanHistoryFilePath();
        if (!is_file($path)) return null;

        $contents = @file_get_contents($path);
        if ($contents === false) return null;

        $decoded = json_decode(MuruguardHelper::stripDataFileStub($contents), true);
        return is_array($decoded) && isset($decoded['saved_at']) ? (int) $decoded['saved_at'] : null;
    }

    /** Null means "never run before" (as opposed to an empty array, which means the last run found nothing). */
    private function loadLastScanKeys(): ?array
    {
        $path = $this->scanHistoryFilePath();
        if (!is_file($path)) return null;

        $contents = @file_get_contents($path);
        if ($contents === false) return null;

        $decoded = json_decode(MuruguardHelper::stripDataFileStub($contents), true);
        if (!is_array($decoded) || !isset($decoded['keys']) || !is_array($decoded['keys'])) return null;
        return $decoded['keys'];
    }

    private function saveLastScanKeys(array $keys): void
    {
        $path = $this->scanHistoryFilePath();
        @file_put_contents($path, MuruguardHelper::dataFileStubPrefix() . json_encode(['keys' => $keys, 'saved_at' => time()]));
    }

    // ------------------------------------------------------------------
    // Chunked / resumable scanning
    //
    // A single "Run a Scan" click used to run the entire filesystem+DB
    // scan inside one HTTP request -- fine for a small site, but a large
    // one (many extensions, big vendor/media trees) could genuinely
    // outrun a host's max_execution_time before finishing, which surfaced
    // to the admin as a bare "500 - Whoops" with no results at all. Each
    // call to runScanChunk() below instead does AS MUCH work as fits in a
    // fixed wall-clock budget (one SCAN_CONFIG directory at a time, plus
    // the webroot/core-entry checks and the DB scan as their own single
    // items), persists progress to a small data file, and returns
    // immediately -- the scanner.php view's JS then calls it again, and
    // again, until it reports done. No single request can ever run longer
    // than the budget, regardless of how large the site is.
    // ------------------------------------------------------------------

    /** Wall-clock budget per HTTP request/chunk call -- comfortably inside even a conservative host's default execution-time limit. */
    private const CHUNK_TIME_BUDGET_SECONDS = 20;
    public const CHUNK_WEBROOT_CORE_KEY = '__webroot_core__';
    public const CHUNK_DATABASE_KEY = '__database__';

    /** Ordered list of chunk-queue items, respecting the user's current area selection -- same selection getFileFindings()/runScan() already honour. */
    private function buildChunkQueue(): array
    {
        $sig = MuruguardHelper::getSignatures();
        $queue = [];
        foreach (array_keys($sig['SCAN_CONFIG']) as $relDir) {
            if ($this->isAreaSelected($relDir)) $queue[] = $relDir;
        }
        if ($this->isAreaSelected('webroot') || $this->isAreaSelected('core_entry')) {
            $queue[] = self::CHUNK_WEBROOT_CORE_KEY;
        }
        if ($this->isAreaSelected('database')) {
            $queue[] = self::CHUNK_DATABASE_KEY;
        }
        return $queue;
    }

    /**
     * Deliberately the same stub-protected data-file technique as
     * scanHistoryFilePath() (see that method's own comment for why this
     * is never session-only or component-params) -- a chunked scan of a
     * genuinely huge site can span several minutes across many chunk
     * calls, longer than it's safe to assume a session survives, and
     * Global Configuration saves would otherwise be able to wipe it.
     */
    private function scanProgressFilePath(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/scan-progress.php';
    }

    private function loadScanProgress(): ?array
    {
        $path = $this->scanProgressFilePath();
        if (!is_file($path)) return null;
        $contents = @file_get_contents($path);
        if ($contents === false) return null;
        $decoded = json_decode(MuruguardHelper::stripDataFileStub($contents), true);
        return is_array($decoded) ? $decoded : null;
    }

    private function saveScanProgress(array $progress): void
    {
        @file_put_contents($this->scanProgressFilePath(), MuruguardHelper::dataFileStubPrefix() . json_encode($progress));
    }

    /**
     * Runs one chunk's worth of work (bounded by CHUNK_TIME_BUDGET_SECONDS)
     * and returns progress for the calling AJAX loop.
     *
     * @param bool $reset Start a brand-new scan, abandoning any in-progress
     *   chunked scan -- passed true only by the very first call of a fresh
     *   "Run a Scan" click; every follow-up call from the same run passes
     *   false so it continues the existing queue instead of restarting it.
     * @return array{done:bool,completedCount:int,totalCount:int,currentArea:?string,truncated:list<string>}
     */
    public function runScanChunk(bool $reset = false): array
    {
        $progress = $reset ? null : $this->loadScanProgress();

        if ($progress === null || !empty($progress['done'])) {
            $queue = $this->buildChunkQueue();
            $progress = [
                'queue'      => $queue,
                'completed'  => [],
                'findings'   => [],
                'dbFindings' => $this->dbFindings,
                'truncated'  => [],
                'totalItems' => count($queue),
                'startedAt'  => time(),
                'updatedAt'  => time(),
                'done'       => false,
            ];
        }

        $deadline = microtime(true) + self::CHUNK_TIME_BUDGET_SECONDS;

        while (!empty($progress['queue']) && microtime(true) < $deadline) {
            $item = array_shift($progress['queue']);

            if ($item === self::CHUNK_DATABASE_KEY) {
                $this->scanDatabase();
                foreach ($this->dbFindings as $category => $rows) {
                    $progress['dbFindings'][$category] = $rows;
                }
            } elseif ($item === self::CHUNK_WEBROOT_CORE_KEY) {
                $this->fileFindings = [];
                $this->truncatedAreas = [];
                $this->scanFilesystem([], true, $deadline);
                $progress['findings'] = array_merge($progress['findings'], $this->fileFindings);
                $progress['truncated'] = array_merge($progress['truncated'], array_keys($this->truncatedAreas));
            } else {
                $this->fileFindings = [];
                $this->truncatedAreas = [];
                $this->scanFilesystem([$item], false, $deadline);
                $progress['findings'] = array_merge($progress['findings'], $this->fileFindings);
                $progress['truncated'] = array_merge($progress['truncated'], array_keys($this->truncatedAreas));
            }

            $progress['completed'][] = $item;
        }

        $progress['updatedAt'] = time();
        $progress['done'] = empty($progress['queue']);

        if ($progress['done']) {
            // Publish through the exact same session keys the unchunked
            // runScan()/getFileFindings() path already uses, so the results
            // view renders identically regardless of which path produced
            // them -- chunking only changes HOW the scan runs, never the
            // shape of its output.
            $session = Factory::getApplication()->getSession();
            $session->set('muruguard.filefindings', $progress['findings']);
            $session->set('muruguard.filefindings_time', time());
            $this->fileFindings = $progress['findings'];
            $this->dbFindings   = $progress['dbFindings'];
        }

        $this->saveScanProgress($progress);

        return [
            'done'           => $progress['done'],
            'completedCount' => count($progress['completed']),
            'totalCount'     => $progress['totalItems'],
            'currentArea'    => $progress['done'] ? null : ($progress['queue'][0] ?? null),
            'truncated'      => array_values(array_unique($progress['truncated'])),
        ];
    }

    /**
     * Persists the 3 scheduled-scanning settings into this component's
     * own extension params -- the same storage Global Configuration reads
     * from, so the in-page Settings panel and System > Global
     * Configuration > MuRu Guard always agree with each other. Safe
     * from the wipe risk documented on scanHistoryFilePath() because it
     * ONLY ever touches these 3 known keys, never the internal scan
     * history (which deliberately never lives in this params blob at
     * all anymore).
     */
    public function saveScheduledSettings(bool $enabled, string $token, string $email): void
    {
        $table = new \Joomla\CMS\Table\Extension($this->getDatabase());
        if (!$table->load(['element' => 'com_muruguard', 'type' => 'component'])) return;

        $params = json_decode((string) $table->params, true);
        if (!is_array($params)) $params = [];
        $params['cron_enabled'] = $enabled ? 1 : 0;
        $params['cron_token'] = $token;
        $params['alert_email'] = $email;
        $table->params = json_encode($params);
        $table->store();
    }

    /**
     * Same storage the plg_system_muruguardshield plugin reads from on
     * every request via ComponentHelper::getParams('com_muruguard') --
     * this is the only place that plugin's behaviour is actually
     * configured, there is no separate plugin-side settings screen.
     */
    public function saveShieldSettings(
        bool $enabled,
        bool $blockPatterns,
        bool $blockBruteForce,
        int $threshold,
        int $window,
        bool $blockUserAgents = false,
        bool $blockCountries = false,
        string $blockedCountries = ''
    ): void {
        $table = new \Joomla\CMS\Table\Extension($this->getDatabase());
        if (!$table->load(['element' => 'com_muruguard', 'type' => 'component'])) return;

        $params = json_decode((string) $table->params, true);
        if (!is_array($params)) $params = [];
        $params['shield_enabled'] = $enabled ? 1 : 0;
        $params['shield_block_patterns'] = $blockPatterns ? 1 : 0;
        $params['shield_block_bruteforce'] = $blockBruteForce ? 1 : 0;
        $params['shield_bruteforce_threshold'] = max(2, min(50, $threshold));
        $params['shield_bruteforce_window'] = max(1, min(1440, $window));
        $params['shield_block_useragents'] = $blockUserAgents ? 1 : 0;
        $params['shield_block_countries'] = $blockCountries ? 1 : 0;
        // Normalise to a clean, de-duplicated, comma-separated list of
        // 2-letter codes -- whatever stray formatting an admin pastes in
        // (extra spaces, lowercase, trailing commas) still works.
        $codes = array_unique(array_filter(array_map(
            fn($c) => strtoupper(trim($c)),
            explode(',', $blockedCountries)
        ), fn($c) => preg_match('/^[A-Z]{2}$/', $c)));
        $params['shield_blocked_countries'] = implode(',', $codes);
        $table->params = json_encode($params);
        $table->store();
    }

    private function saveHardeningParams(array $set): void
    {
        $table = new \Joomla\CMS\Table\Extension($this->getDatabase());
        if (!$table->load(['element' => 'com_muruguard', 'type' => 'component'])) return;
        $params = json_decode((string) $table->params, true);
        if (!is_array($params)) $params = [];
        foreach ($set as $key => $value) {
            $params[$key] = $value;
        }
        $table->params = json_encode($params);
        $table->store();
    }

    /**
     * MuRu Shield Hardening: activates the /administrator HTTP Basic
     * Auth gate. Only ever persists username + a bcrypt hash + an
     * activation timestamp -- never the plaintext password, which is
     * returned to the caller exactly once so it can be shown to the
     * admin, and is not retrievable again afterward (matching every
     * other secret in this codebase -- see maskLicenseKey()'s docblock
     * for the same "never echo a secret back" discipline).
     */
    public function activateBackendAuth(string $username, string $password): array
    {
        $testUrl = \Joomla\CMS\Uri\Uri::root() . 'administrator/index.php';
        $result = \MuruguardHardeningHelper::activateBackendAuth(JPATH_ADMINISTRATOR, $testUrl, $username, $password);
        if ($result['ok']) {
            $this->saveHardeningParams([
                'backend_auth_enabled'    => 1,
                'backend_auth_username'   => $username,
                'backend_auth_activated'  => time(),
            ]);
        } elseif (!$this->isShieldPluginActive()) {
            // The single most common reason the self-test fails on a non-
            // Apache host: plg_system_muruguardshield is what actually
            // enforces this at the PHP layer there (see its
            // checkBasicAuthGate()) -- .htaccess-only enforcement only
            // ever works on Apache. If it's not installed/enabled, no
            // amount of retrying will help, so say so explicitly instead
            // of leaving the admin to guess between three generic causes.
            $result['reason'] = 'The MuRu Guard Shield plugin (System > Plugins > "System - MuRu Guard Shield") is not installed or enabled. '
                . 'On any server other than Apache, this plugin is what actually enforces Backend Access -- install/enable it, then try again. '
                . 'Original error: ' . $result['reason'];
        }
        return $result;
    }

    public function deactivateBackendAuth(): void
    {
        \MuruguardHardeningHelper::deactivateBackendAuth(JPATH_ADMINISTRATOR);
        // Emergency Mode reuses backend auth's .htpasswd -- it cannot be
        // left active pointing at a file that just got deleted.
        \MuruguardHardeningHelper::deactivateEmergencyMode($this->root);
        $this->saveHardeningParams([
            'backend_auth_enabled'   => 0,
            'backend_auth_username'  => '',
            'backend_auth_activated' => 0,
            'emergency_mode_enabled' => 0,
        ]);
    }

    public function activateEmergencyMode(string $username, string $password): array
    {
        // The plaintext password is never persisted once backend auth is
        // active (see activateBackendAuth()'s docblock) -- Emergency Mode
        // reuses those same credentials rather than minting new ones, so
        // the admin re-supplies the password here and it's checked
        // against the already-active .htpasswd BEFORE anything is
        // written, refusing outright rather than writing an Emergency
        // Mode block self-tested with a password that turns out wrong.
        if (!\MuruguardHardeningHelper::verifyBackendPassword(JPATH_ADMINISTRATOR, $username, $password)) {
            return ['ok' => false, 'reason' => 'That username/password doesn\'t match your currently-active backend access credentials.'];
        }

        $testUrl = \Joomla\CMS\Uri\Uri::root();
        $result = \MuruguardHardeningHelper::activateEmergencyMode($this->root, JPATH_ADMINISTRATOR, $testUrl, $username, $password);
        if ($result['ok']) {
            $this->saveHardeningParams(['emergency_mode_enabled' => 1, 'emergency_mode_activated' => time()]);
        } elseif (!$this->isShieldPluginActive()) {
            // Same reasoning as activateBackendAuth() above -- on any
            // non-Apache host, plg_system_muruguardshield's
            // checkBasicAuthGate() is what actually enforces this.
            $result['reason'] = 'The MuRu Guard Shield plugin (System > Plugins > "System - MuRu Guard Shield") is not installed or enabled. '
                . 'On any server other than Apache, this plugin is what actually enforces this. '
                . 'Original error: ' . $result['reason'];
        }
        return $result;
    }

    public function deactivateEmergencyMode(): void
    {
        \MuruguardHardeningHelper::deactivateEmergencyMode($this->root);
        $this->saveHardeningParams(['emergency_mode_enabled' => 0, 'emergency_mode_activated' => 0]);
    }

    /** Dismisses the "get security alerts & updates" dashboard banner without subscribing. */
    public function dismissNewsletterBanner(): void
    {
        $this->saveHardeningParams(['newsletter_banner_dismissed' => 1]);
    }

    /**
     * Submits the banner's name/email to the dashboard's public opt-in
     * endpoint (see MuruguardHelper::submitNewsletterOptIn()) and, only on
     * success, marks the banner as both subscribed and dismissed so it
     * never shows again -- a failed submission leaves it showing so the
     * admin can retry, rather than silently losing the lead.
     */
    public function subscribeToNewsletter(string $name, string $email): bool
    {
        $ok = \MuruguardHelper::submitNewsletterOptIn($name, $email);
        if ($ok) {
            $this->saveHardeningParams(['newsletter_subscribed' => 1, 'newsletter_banner_dismissed' => 1]);
        }
        return $ok;
    }

    /**
     * True only if plg_system_muruguardshield is both installed AND
     * enabled -- the Settings panel uses this to warn when the shield
     * toggles are turned on but have no extension actually reading them,
     * since that combination looks configured but silently does nothing.
     */
    public function isShieldPluginActive(): bool
    {
        $db    = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select($db->quoteName('enabled'))
            ->from($db->quoteName('#__extensions'))
            ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
            ->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
            ->where($db->quoteName('element') . ' = ' . $db->quote('muruguardshield'));

        $db->setQuery($query);
        return (bool) $db->loadResult();
    }

    // ------------------------------------------------------------------
    // Filesystem scan
    // ------------------------------------------------------------------

    /**
     * @param ?array $onlyDirs Restricts the SCAN_CONFIG directory walk to
     *   just these relative-dir keys (e.g. ['media']) -- null (default)
     *   walks every selected SCAN_CONFIG dir, same as before this param
     *   existed. Pass [] to skip the directory walk entirely while still
     *   running the webroot/core-entry checks below, if $includeWebrootCore.
     * @param bool $includeWebrootCore Whether to run the shallow webroot
     *   scan and core-entry-point checks in this call. Defaults true (full
     *   scan, unchanged behaviour); a per-directory chunk call passes false
     *   so those cheap-but-redundant checks only run once per chunked scan,
     *   not once per chunk.
     * @param ?float $deadline Wall-clock microtime(true) cutoff. When set,
     *   a directory walk that's still running past it is cut short (see
     *   MuruguardScanChunkTimeout) instead of letting one huge folder blow
     *   through an entire chunked-scan HTTP request's time budget.
     */
    public function scanFilesystem(?array $onlyDirs = null, bool $includeWebrootCore = true, ?float $deadline = null): void
    {
        $sig = MuruguardHelper::getSignatures();
        $params = ComponentHelper::getParams('com_muruguard');
        $maxSize = (int) ($params->get('max_file_scan_size', 2 * 1024 * 1024));

        $extraRootDirs = array_filter(array_map('trim', explode(',', (string) $params->get('extra_root_dirs', ''))));
        $sig['KNOWN_ROOT_DIRS'] = array_merge($sig['KNOWN_ROOT_DIRS'], $extraRootDirs);

        $ignoredPaths = array_filter(array_map('trim', explode("\n", (string) $params->get('ignored_paths', ''))));
        $isIgnored = function (string $relPath) use ($ignoredPaths): bool {
            foreach ($ignoredPaths as $pattern) {
                if ($pattern === '') continue;
                if (fnmatch($pattern, $relPath, FNM_PATHNAME)) return true;
            }
            return false;
        };

        $selfLogPattern  = '/^\.muruguard-[a-f0-9]{16}\.(log|lock)$/i';
        $googleVerifyPattern = '/^google[a-f0-9]{16,}\.html$/i';
        // Safety-backup copies this scanner's own "Clean code" action
        // writes before overwriting an infected file -- deliberately kept
        // on disk for manual review/rollback, so they shouldn't re-appear
        // as a "new" finding on the next scan (they still contain the
        // original malicious content by design, that's the whole point).
        $selfBackupPattern = '/\.muruguard-\d{8}-\d{6}\.bak$/i';
        $registeredTemplates = $this->getRegisteredTemplates();
        $registeredPlugins = $this->getRegisteredPlugins();
        $registeredComponents = $this->getRegisteredComponents();
        $falsePositives = MuruguardHelper::getFalsePositiveLookup();

        foreach ($sig['SCAN_CONFIG'] as $relDir => $mode) {
            if ($onlyDirs !== null && !in_array($relDir, $onlyDirs, true)) continue;
            if (!$this->isAreaSelected($relDir)) continue;
            if ($deadline !== null && microtime(true) > $deadline) {
                // Budget already spent before even starting this area (only
                // reachable when $onlyDirs covers more than one area) --
                // leave it for the next chunk rather than starting it.
                $this->truncatedAreas[$relDir] = true;
                break;
            }
            $dir = $this->root . '/' . $relDir;
            if (!is_dir($dir)) continue;

            try {
                MuruguardHelper::walkDir($dir, function (string $path, bool $isDir) use ($sig, $mode, $maxSize, $isIgnored, $selfBackupPattern, $registeredTemplates, $registeredPlugins, $registeredComponents, $falsePositives, $deadline) {
                if ($deadline !== null && microtime(true) > $deadline) {
                    throw new MuruguardScanChunkTimeout();
                }
                foreach ($sig['SAFE_COMPONENT_PATHS'] as $safeFrag) {
                    if (stripos($path, $safeFrag) !== false) return;
                }
                if (preg_match('#/tmp/install_[a-z0-9]+(/|$)#i', $path)) {
                    return; // Joomla's own installer extraction folder — transient, not user-uploadable
                }
                if (!$isDir && preg_match($selfBackupPattern, basename($path))) return;
                if (isset($this->seenAbs[$path])) return;

                $basename = basename($path);
                $relCheck = ltrim(str_replace($this->root, '', $path), '/');
                if ($isIgnored($relCheck)) return;
                $isKnownSafeEntry = !$isDir && in_array($relCheck, $sig['KNOWN_SAFE_RELATIVE_FILES'], true);
                $flagged = false;
                $reasons = [];

                // iconfont strict allow-list -- file TYPE is checked at
                // ANY depth inside an iconfont/ tree (icomoon/, css/,
                // fonts/, or any other allowed subfolder), not just its
                // immediate children. A subfolder name being on the
                // allow-list (e.g. "icomoon", IcoMoon's own export/build
                // tool name -- a legitimate, common icon-font vendor
                // folder) only means the FOLDER itself isn't flagged as
                // unrecognized; it is never a free pass for what's placed
                // inside it -- every file there still has its own
                // extension checked against the allow-list below, on top
                // of the depth-independent executable check and the
                // ordinary content-signature scan every file gets
                // regardless of location.
                if (stripos($path, '/iconfont/') !== false) {
                    $parentBase = strtolower(basename(dirname($path)));
                    if ($isDir) {
                        if ($parentBase === 'iconfont' && !in_array(strtolower($basename), $sig['ICONFONT_ALLOWED_DIRNAMES'], true)) {
                            $flagged = true;
                            $reasons[] = 'Unrecognized folder inside icon-font asset directory.';
                        }
                    } else {
                        $extL = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                        if (in_array($extL, $sig['EXEC_EXTS'], true)) {
                            $flagged = true;
                            $reasons[] = 'Executable file inside icon-font asset folder.';
                        } else {
                            $baseNoExt = strtolower(pathinfo($basename, PATHINFO_FILENAME));
                            if (!in_array($extL, $sig['ICONFONT_ALLOWED_EXTENSIONS'], true)
                                && !($extL === '' && in_array($baseNoExt, $sig['ICONFONT_ALLOWED_BARE_NAMES'], true))) {
                                $flagged = true;
                                $reasons[] = 'Unrecognized file type inside icon-font asset directory.';
                            }
                        }
                    }
                }

                // JCE upload strict allow-list
                if (!$isDir && !$flagged) {
                    foreach ($sig['JCE_UPLOAD_PATH_FRAGMENTS'] as $frag) {
                        if (stripos($path, $frag) === false) continue;
                        $extL = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                        if (in_array($extL, $sig['EXEC_EXTS'], true)) {
                            $flagged = true;
                            $reasons[] = 'Executable file inside JCE file-browser upload path.';
                        } elseif ($extL !== '' && !in_array($extL, $sig['JCE_UPLOAD_ALLOWED_EXTENSIONS'], true)) {
                            $flagged = true;
                            $reasons[] = 'Unrecognized file type inside JCE file-browser upload path.';
                        }
                        break;
                    }
                }

                // 'upload' mode strict structural checks
                if ($mode === 'upload') {
                    if ($isDir) {
                        if (preg_match('/^\d+$/', $basename) && !MuruguardHelper::isDateLikeNumericFolderName($basename)) {
                            $flagged = true;
                            $reasons[] = "Folder name is purely numeric (\"{$basename}\") and isn't a normal date/ID component — a common automated-malware-drop pattern.";
                        }
                    } else {
                        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                        $isBlankStub = false;
                        if ($ext === 'php' && strcasecmp($basename, 'index.php') === 0) {
                            $stubContents = @file_get_contents($path, false, null, 0, 4096);
                            if ($stubContents !== false && MuruguardHelper::isStandardJoomlaStub($stubContents)) {
                                $isBlankStub = true;
                            }
                        }
                        $isJoomlaCacheFile = $ext === 'php'
                            && strpos($relCheck, 'cache/') === 0
                            && (bool) preg_match($sig['JOOMLA_CACHE_FILE_RE'], $basename);
                        $isRegisteredExtensionSnapshot = $ext === 'php'
                            && strpos($relCheck, 'tmp/joomtower_snapshots/') === 0
                            && MuruguardHelper::isRegisteredExtensionSnapshotPath($relCheck, $registeredPlugins, $registeredComponents, $registeredTemplates);
                        if (!$isKnownSafeEntry && !$isBlankStub && !$isJoomlaCacheFile && !$isRegisteredExtensionSnapshot && in_array($ext, $sig['EXEC_EXTS'], true)) {
                            $flagged = true;
                            $reasons[] = "Executable file (.$ext) inside an upload directory — these should never contain runnable code.";
                        }
                        if ($basename === '.htaccess') {
                            $contents = @file_get_contents($path, false, null, 0, 4096);
                            if ($contents !== false
                                && preg_match('/Allow\s+from\s+all|Require\s+all\s+granted|RewriteEngine\s+Off/i', $contents)
                                && !preg_match('/FilesMatch.*php/i', $contents)) {
                                $flagged = true;
                                $reasons[] = 'Suspicious .htaccess: permissively allows access in an upload folder.';
                            }
                        }
                    }
                }

                // content signature scan runs in both modes, files only
                if (!$isDir) {
                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    if (MuruguardHelper::scanFileContent($path, $ext, $sig, $maxSize, $reasons)) {
                        // Strip only this scanner's own narrow, known,
                        // per-file self-matches (see
                        // SELF_CONTENT_SIGNATURE_EXEMPTIONS) -- never a
                        // blanket skip, so an actually-injected backdoor
                        // in this scanner's own files is still caught.
                        $reasons = MuruguardHelper::filterSelfSignatureExemptions($relCheck, $sig, $reasons);
                        // Narrow, per-file, per-signature exemption for
                        // known-legitimate third-party libraries (see
                        // KNOWN_LIBRARY_SIGNATURE_EXEMPTIONS) -- same
                        // "never blanket-skip a path" reasoning as above.
                        $reasons = MuruguardHelper::filterKnownLibrarySignatureExemptions($relCheck, $sig, $reasons);
                        if (!empty($reasons)) {
                            $flagged = true;
                        }
                    }
                }

                // known-malicious filename pattern (location-independent, runs both modes --
                // malware doesn't respect the upload-vs-code folder distinction)
                if (!$isDir && !$isKnownSafeEntry) {
                    foreach ($sig['SUSPICIOUS_FILENAME_REGEXES'] as $re) {
                        if (preg_match($re, $basename)) { $flagged = true; $reasons[] = 'Filename matches known malicious pattern.'; break; }
                    }
                }

                // .htaccess rewriting a non-PHP extension to execute as PHP
                // (location-independent, runs both modes) -- confirmed real
                // backdoor technique: pairs with a *.php.json-style dropped
                // file (see SUSPICIOUS_FILENAME_REGEXES above) to defeat any
                // filter that only blocks the .php extension itself.
                if (!$isDir && !$isKnownSafeEntry && $basename === '.htaccess') {
                    $htaccessContents = @file_get_contents($path, false, null, 0, 8192);
                    if ($htaccessContents !== false) {
                        $handlerHijack = MuruguardHelper::checkMaliciousHtaccessHandler($htaccessContents);
                        if ($handlerHijack !== null) { $flagged = true; $reasons[] = $handlerHijack; }
                    }
                }

                // core-path masquerade check (location-based, runs both modes)
                $masq = MuruguardHelper::checkCoreMasquerade($relCheck, $isDir, $sig, $path);
                if ($masq !== null) { $flagged = true; $reasons[] = $masq; }

                // junk auto-generated template folder check (location-based, runs both modes)
                $junkTpl = MuruguardHelper::checkJunkTemplateFolder($relCheck, $sig, $path, $registeredTemplates);
                if ($junkTpl !== null) { $flagged = true; $reasons[] = $junkTpl; }

                // junk module/plugin/component folder check (location-based, runs both modes)
                $junkExt = MuruguardHelper::checkJunkExtensionFolder($relCheck, $sig, $registeredPlugins, $registeredComponents, $path);
                if ($junkExt !== null) { $flagged = true; $reasons[] = $junkExt; }

                // stray index.php structural check (location-based, runs both modes)
                if (!$isDir && !$isKnownSafeEntry) {
                    $strayIdx = MuruguardHelper::checkStrayIndexPhp($relCheck, $path, $sig);
                    if ($strayIdx !== null) { $flagged = true; $reasons[] = $strayIdx; }
                }

                if ($flagged) {
                    $this->seenAbs[$path] = true;
                    // Admin-dismissed false positives (see the "Mark as
                    // Safe" button on each finding row) are keyed on the
                    // exact reasons text, not just the path -- if this
                    // exact same file later matches something DIFFERENT
                    // (e.g. an attacker overwrites a previously-dismissed
                    // path with a real backdoor, which trips a different/
                    // additional signature), the fingerprint no longer
                    // matches and it reappears as a fresh finding rather
                    // than staying silently suppressed forever.
                    $fingerprint = MuruguardHelper::fingerprintReasons($reasons);
                    if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $relCheck, $fingerprint)) {
                        MuruguardHelper::recordFinding($this->fileFindings, $path, $this->root, $reasons, $isDir);
                    }
                }
                });
            } catch (MuruguardScanChunkTimeout $e) {
                // Whatever this area's walk found before hitting the
                // deadline is already recorded in $this->fileFindings above
                // -- kept as a partial result rather than discarded, with
                // the area marked truncated so runScanChunk() can report it
                // honestly instead of implying a complete scan.
                $this->truncatedAreas[$relDir] = true;
                break;
            }
        }

        // Shallow webroot scan
        $rootItems = ($includeWebrootCore && $this->isAreaSelected('webroot')) ? (@scandir($this->root) ?: []) : [];
        foreach ($rootItems as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $this->root . '/' . $it;
            if (isset($this->seenAbs[$p])) continue;
            if (preg_match($selfLogPattern, $it)) continue;
            if (preg_match($selfBackupPattern, $it)) continue;
            if (preg_match($googleVerifyPattern, $it)) continue;
            if ($isIgnored($it)) continue;

            if (is_dir($p)) {
                if (in_array(strtolower($it), array_map('strtolower', $sig['KNOWN_ROOT_DIRS']), true)) {
                    continue;
                }

                if (MuruguardHelper::isKnownExtensionDataFolder($it, $sig, $registeredComponents)) {
                    // Recognized companion data folder of an installed
                    // extension (e.g. ConvertForms' own convertforms_<alias>
                    // custom-code folders) -- not itself suspicious, but
                    // still content-scanned file by file so malware planted
                    // here later doesn't get a free pass just because the
                    // folder name matches a known convention.
                    $this->seenAbs[$p] = true;
                    MuruguardHelper::walkDir($p, function (string $innerPath, bool $innerIsDir) use ($sig, $maxSize, $falsePositives) {
                        if ($innerIsDir || isset($this->seenAbs[$innerPath])) return;
                        $this->seenAbs[$innerPath] = true;
                        $innerExt = strtolower(pathinfo($innerPath, PATHINFO_EXTENSION));
                        $innerReasons = [];
                        MuruguardHelper::scanFileContent($innerPath, $innerExt, $sig, $maxSize, $innerReasons);
                        if (!empty($innerReasons)) {
                            $innerRel = ltrim(str_replace($this->root, '', $innerPath), '/');
                            $innerFp = MuruguardHelper::fingerprintReasons($innerReasons);
                            if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $innerRel, $innerFp)) {
                                MuruguardHelper::recordFinding($this->fileFindings, $innerPath, $this->root, $innerReasons, false);
                            }
                        }
                    });
                    continue;
                }

                // Unrecognized directory -- flagged, unless it's made up
                // ENTIRELY of static assets (fonts/images/css/...), a
                // common, legitimate custom template/page-builder asset
                // folder, not a malware staging area. Confirmed real false
                // positive, twice: first a top-level /fonts folder was
                // flagged High identically to a dropped-shell folder
                // purely because the reason text contained the word
                // "unrecognized"; downgrading it to Medium instead of
                // removing the flag entirely was STILL reported back as a
                // false positive needing individual per-file dismissal.
                // An asset-only folder now gets the exact same treatment
                // as a known extension's own data folder just above: no
                // structural flag at all, but every file inside is still
                // fully content-scanned, so an actual payload disguised
                // with one of these extensions (a script-bearing .svg or
                // .html, for instance) is still caught on its own merits.
                $this->seenAbs[$p] = true;
                $innerFiles = [];
                $hasNonAssetContent = false;
                MuruguardHelper::walkDir($p, function (string $innerPath, bool $innerIsDir) use (&$innerFiles, &$hasNonAssetContent, $sig) {
                    if ($innerIsDir) return;
                    $innerFiles[] = $innerPath;
                    $innerExt = strtolower(pathinfo($innerPath, PATHINFO_EXTENSION));
                    if (!in_array($innerExt, $sig['ICONFONT_ALLOWED_EXTENSIONS'], true)) $hasNonAssetContent = true;
                });

                if (!$hasNonAssetContent) {
                    foreach ($innerFiles as $innerPath) {
                        if (isset($this->seenAbs[$innerPath])) continue;
                        $this->seenAbs[$innerPath] = true;
                        $innerExt = strtolower(pathinfo($innerPath, PATHINFO_EXTENSION));
                        $innerReasons = [];
                        MuruguardHelper::scanFileContent($innerPath, $innerExt, $sig, $maxSize, $innerReasons);
                        if (!empty($innerReasons)) {
                            $innerRel = ltrim(str_replace($this->root, '', $innerPath), '/');
                            $innerFp = MuruguardHelper::fingerprintReasons($innerReasons);
                            if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $innerRel, $innerFp)) {
                                MuruguardHelper::recordFinding($this->fileFindings, $innerPath, $this->root, $innerReasons, false);
                            }
                        }
                    }
                    continue;
                }

                $dirReason = 'Unrecognized directory directly in the Joomla webroot — not part of a standard install.';
                $dirFp = MuruguardHelper::fingerprintReasons([$dirReason]);
                if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $it, $dirFp)) {
                    MuruguardHelper::recordFinding($this->fileFindings, $p, $this->root, $dirReason, true);
                }

                $innerReasonText = 'Inside an unrecognized top-level webroot directory.';
                $innerFp = MuruguardHelper::fingerprintReasons([$innerReasonText]);
                foreach ($innerFiles as $innerPath) {
                    if (isset($this->seenAbs[$innerPath])) continue;
                    $this->seenAbs[$innerPath] = true;
                    $innerRel = ltrim(str_replace($this->root, '', $innerPath), '/');
                    if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $innerRel, $innerFp)) {
                        MuruguardHelper::recordFinding($this->fileFindings, $innerPath, $this->root, $innerReasonText, false);
                    }
                }
                continue;
            }

            if (!is_file($p)) continue;
            if (in_array(strtolower($it), array_map('strtolower', $sig['KNOWN_ROOT_FILES']), true)) continue;
            $relCheck = ltrim(str_replace($this->root, '', $p), '/');
            if (in_array($relCheck, $sig['KNOWN_SAFE_RELATIVE_FILES'], true)) continue;

            $flaggedRoot = false;
            $reasonsRoot = [];
            foreach ($sig['SUSPICIOUS_FILENAME_REGEXES'] as $re) {
                if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Filename matches known malicious pattern.'; break; }
            }
            foreach ($sig['ROOT_SUSPICIOUS_FILENAME_REGEXES'] as $re) {
                if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Filename resembles a known dropped-shell naming pattern.'; break; }
            }
            foreach ($sig['CONFIG_BACKUP_PATTERNS'] as $re) {
                if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Backup/duplicate configuration file — leaks the same credentials as configuration.php.'; break; }
            }

            $masqRoot = MuruguardHelper::checkCoreMasquerade($relCheck, false, $sig, $p);
            if ($masqRoot !== null) { $flaggedRoot = true; $reasonsRoot[] = $masqRoot; }

            $dotfileRoot = MuruguardHelper::checkRootLevelDotfile($it);
            if ($dotfileRoot !== null) { $flaggedRoot = true; $reasonsRoot[] = $dotfileRoot; }

            $extR = strtolower(pathinfo($p, PATHINFO_EXTENSION));
            MuruguardHelper::scanFileContent($p, $extR, $sig, $maxSize, $reasonsRoot);
            if (count($reasonsRoot) > ($flaggedRoot ? 1 : 0)) $flaggedRoot = true;

            $benignStaticExts = ['css', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp', 'woff', 'woff2', 'ttf', 'eot', 'map'];
            if (!$flaggedRoot && !in_array($extR, $benignStaticExts, true)) {
                $flaggedRoot = true;
                $reasonsRoot[] = 'Unrecognized file directly in the Joomla webroot — not part of a standard install.';
            }

            if ($flaggedRoot) {
                $this->seenAbs[$p] = true;
                $rootFp = MuruguardHelper::fingerprintReasons($reasonsRoot);
                if (!MuruguardHelper::isFalsePositive($falsePositives, 'file', $relCheck, $rootFp)) {
                    MuruguardHelper::recordFinding($this->fileFindings, $p, $this->root, $reasonsRoot, false);
                }
            }
        }

        // Core entry-point integrity + content-signature scan, plus (when
        // the site's exact Joomla version is covered by the bundled
        // manifest) a byte-for-byte checksum comparison against the
        // official release -- unambiguous proof of tampering, independent
        // of and stronger than every heuristic check here.
        $joomlaVersion = MuruguardHelper::getInstalledJoomlaVersion($this->root);
        $checksumManifest = MuruguardHelper::getCoreChecksumManifest();

        $coreEntries = ($includeWebrootCore && $this->isAreaSelected('core_entry')) ? $sig['CORE_ENTRY_POINTS'] : [];
        foreach ($coreEntries as $relEntry) {
            $absEntry = $this->root . '/' . $relEntry;
            if (!is_file($absEntry)) continue;
            $size = @filesize($absEntry);
            if ($size === false || $size > $maxSize) continue;
            $contents = @file_get_contents($absEntry);
            if ($contents === false) continue;

            $reasonsEntry = [];
            $issue = MuruguardHelper::checkCoreIndexIntegrity($contents);
            if ($issue !== null) $reasonsEntry[] = $issue;

            $ext = strtolower(pathinfo($absEntry, PATHINFO_EXTENSION));
            MuruguardHelper::scanFileContent($absEntry, $ext, $sig, $maxSize, $reasonsEntry);

            $checksumIssue = MuruguardHelper::checkCoreFileChecksum($relEntry, $absEntry, $joomlaVersion, $checksumManifest);
            if ($checksumIssue !== null) $reasonsEntry[] = $checksumIssue;

            if (!empty($reasonsEntry)) {
                $this->seenAbs[$absEntry] = true;
                MuruguardHelper::recordFinding($this->fileFindings, $absEntry, $this->root, $reasonsEntry, false);
            }
        }

        // Checksum-only pass for the remaining manifest-covered static
        // files (includes/framework.php, robots.txt.dist, htaccess.txt,
        // web.config.txt) -- none of these paths are reached by any other
        // scan pass above, so there's no risk of a second recordFinding()
        // call on the same file silently overwriting an earlier finding.
        if ($includeWebrootCore && $this->isAreaSelected('core_entry') && $joomlaVersion !== null && isset($checksumManifest[$joomlaVersion])) {
            $staticCoreFiles = ['includes/framework.php', 'robots.txt.dist', 'htaccess.txt', 'web.config.txt'];
            foreach ($staticCoreFiles as $relEntry) {
                $absEntry = $this->root . '/' . $relEntry;
                if (isset($this->seenAbs[$absEntry]) || !is_file($absEntry)) continue;

                $checksumIssue = MuruguardHelper::checkCoreFileChecksum($relEntry, $absEntry, $joomlaVersion, $checksumManifest);
                if ($checksumIssue !== null) {
                    $this->seenAbs[$absEntry] = true;
                    MuruguardHelper::recordFinding($this->fileFindings, $absEntry, $this->root, [$checksumIssue], false);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Database scan
    // ------------------------------------------------------------------

    public function scanDatabase(): void
    {
        if (!$this->isAreaSelected('database')) return;

        $db  = $this->getDatabase();
        $sig = MuruguardHelper::getSignatures();
        $falsePositives = MuruguardHelper::getFalsePositiveLookup();

        try {
            $query = $db->getQuery(true)
                ->select('u.id, u.name, u.username, u.email, u.registerDate, u.lastvisitDate')
                ->from($db->quoteName('#__users', 'u'))
                ->join('INNER', $db->quoteName('#__user_usergroup_map', 'm') . ' ON ' . $db->quoteName('m.user_id') . ' = ' . $db->quoteName('u.id'))
                ->where($db->quoteName('m.group_id') . ' IN (SELECT id FROM ' . $db->quoteName('#__usergroups') . ' WHERE title IN (' . $db->quote('Super Users') . ',' . $db->quote('Super User') . '))')
                ->order($db->quoteName('u.registerDate') . ' DESC');
            $db->setQuery($query);
            $rows = $db->loadAssocList() ?: [];
            foreach ($rows as $row) {
                $suspicious = false;
                $why = [];
                if (stripos($row['email'], 'secure.local') !== false) { $suspicious = true; $why[] = 'email domain: secure.local (known attacker marker)'; }
                if (preg_match('/webmanager\d+|codex|sppb/i', $row['username'])) { $suspicious = true; $why[] = 'username matches known attacker pattern'; }
                // Only a "suspicious" row is ever a candidate for dismissal
                // -- an already-normal row has nothing to suppress.
                if ($suspicious) {
                    $fingerprint = MuruguardHelper::fingerprintReasons($why);
                    if (MuruguardHelper::isFalsePositive($falsePositives, 'superusers', (string) $row['id'], $fingerprint)) {
                        $suspicious = false;
                        $why = [];
                    }
                }
                $this->dbFindings['superusers'][] = [
                    'id' => $row['id'], 'name' => $row['name'], 'username' => $row['username'],
                    'email' => $row['email'], 'registered' => $row['registerDate'], 'lastvisit' => $row['lastvisitDate'],
                    'suspicious' => $suspicious, 'why' => implode('; ', $why), 'why_list' => $why,
                ];
            }
        } catch (\Throwable $e) { /* table missing or query failed -- non-fatal */ }

        try {
            $query = $db->getQuery(true)->select('id, title, link, params')->from($db->quoteName('#__menu'));
            $db->setQuery($query);
            $rows = $db->loadAssocList() ?: [];
            foreach ($rows as $row) {
                $params = (string) ($row['params'] ?? '');
                $matches = [];
                foreach ($sig['MENU_XSS_PATTERNS'] as $label => $re) {
                    if (preg_match($re, $params)) $matches[] = $label;
                }
                if (!empty($matches)) {
                    $fingerprint = MuruguardHelper::fingerprintReasons($matches);
                    if (!MuruguardHelper::isFalsePositive($falsePositives, 'menu_xss', (string) $row['id'], $fingerprint)) {
                        $this->dbFindings['menu_xss'][] = [
                            'id' => $row['id'], 'title' => $row['title'], 'link' => $row['link'], 'matches' => $matches,
                        ];
                    }
                }
            }
        } catch (\Throwable $e) { /* non-fatal */ }

       try {

    $this->dbFindings['sppb_assets'] = [];
    $this->dbFindings['rogue_iconfont'] = [];

    // Load all SP Page Builder assets
    $query = $db->getQuery(true)
        ->select('*')
        ->from($db->quoteName('#__sppagebuilder_assets'))
        ->order($db->quoteName('id') . ' DESC');

    $db->setQuery($query);
    $rows = $db->loadAssocList() ?: [];


    foreach ($rows as $row) {

        $reasons = [];

        // The real #__sppagebuilder_assets column is "assets" (a JSON/text
        // blob of the actual icon-font/asset definition) -- NOT
        // "asset_value", which doesn't exist in this table at all and was
        // silently always empty, meaning every payload check below matched
        // against '' on every real install regardless of what this row
        // actually contained. css_path is checked too: it's the other
        // attacker-controllable text field here, and should only ever
        // reference a real .css file -- never inline code, never a PHP path.
        $assetValue = (string) ($row['assets'] ?? '');
        $cssPath    = (string) ($row['css_path'] ?? '');
        $type       = strtolower((string) ($row['type'] ?? ''));
        $name       = strtolower((string) ($row['name'] ?? ''));
        $createdBy  = (int) ($row['created_by'] ?? 0);


        /*
         * Payload detection -- runs against every row regardless of type or
         * name. A "known good" iconfont name (icofont, icomoon, ...) is
         * only ever a name -- it is never a substitute for actually
         * checking what this row's content contains, since nothing stops
         * an attacker from naming a malicious row "icofont" too.
         */
        foreach ([$assetValue, $cssPath] as $content) {
            if (stripos($content, 'xss.report') !== false) {
                $reasons[] = 'Contains xss.report';
            }

            if (stripos($content, 'base64_decode') !== false) {
                $reasons[] = 'Contains base64_decode()';
            }

            if (stripos($content, 'eval(') !== false) {
                $reasons[] = 'Contains eval()';
            }

            if (stripos($content, '<script') !== false) {
                $reasons[] = 'Contains script tag';
            }

            if (preg_match('/on(load|error|click|mouseover)\s*=/i', $content)) {
                $reasons[] = 'Contains JavaScript event handler';
            }

            if (preg_match('/<\?php|<\?=\s*[\$A-Za-z_(]/i', $content)) {
                $reasons[] = 'Contains a PHP open tag';
            }
        }

        // css_path should only ever point at a real stylesheet -- a path
        // ending in .php/.phtml/etc. (or any other executable extension)
        // is a direct way to smuggle a runnable file reference through a
        // field nobody expects to hold one.
        if ($cssPath !== '') {
            $cssExt = strtolower(pathinfo(parse_url($cssPath, PHP_URL_PATH) ?: $cssPath, PATHINFO_EXTENSION));
            if (in_array($cssExt, $sig['EXEC_EXTS'], true)) {
                $reasons[] = "css_path references an executable file (.{$cssExt}), not a stylesheet";
            }
        }


        /*
         * Iconfont detection -- a secondary, name-based signal ON TOP OF
         * the content checks above, not a replacement for them. A row
         * named exactly "icofont" (SP Page Builder's own bundled default)
         * still goes through every content check above; this block only
         * adds an extra reason when the name itself doesn't match that
         * one known-legitimate default.
         */
        if ($type === 'iconfont') {

            // Ignore known-legitimate iconfont names (see
            // KNOWN_GOOD_ICONFONT_NAMES's docblock for why this is only
            // a secondary signal, not a substitute for the content checks
            // above).
            if (!in_array($name, $sig['KNOWN_GOOD_ICONFONT_NAMES'], true)) {

                $iconfontReasons = ['Non-default iconfont'];
                if ($createdBy === 0) {
                    $iconfontReasons[] = 'Created by Guest/System';
                }
                $reasons = array_merge($reasons, $iconfontReasons);

                $rogueFingerprint = MuruguardHelper::fingerprintReasons($iconfontReasons);
                if (!MuruguardHelper::isFalsePositive($falsePositives, 'rogue_iconfont', (string) $row['id'], $rogueFingerprint)) {
                    $rogueRow = $row;
                    $rogueRow['scan_reasons'] = $iconfontReasons;
                    $this->dbFindings['rogue_iconfont'][] = $rogueRow;
                }
            }
        }


        /*
         * Only store suspicious rows
         */
        if (!empty($reasons)) {

            $row['scan_reasons'] = array_values(array_unique($reasons));

            $sppbFingerprint = MuruguardHelper::fingerprintReasons($row['scan_reasons']);
            if (!MuruguardHelper::isFalsePositive($falsePositives, 'sppb_assets', (string) $row['id'], $sppbFingerprint)) {
                $this->dbFindings['sppb_assets'][] = $row;
            }
        }
    }


} catch (\Throwable $e) {

    // table missing or query failed
    $this->dbFindings['sppb_assets'] = [];
    $this->dbFindings['rogue_iconfont'] = [];

}

        try {
            $query = $db->getQuery(true)->select('id, template, title, params, client_id')->from($db->quoteName('#__template_styles'));
            $db->setQuery($query);
            $rows = $db->loadAssocList() ?: [];
            $registeredTemplates = $this->getRegisteredTemplates();
            foreach ($rows as $row) {
                $matches = [];
                foreach ($sig['DEFACEMENT_PATTERNS'] as $pattern) {
                    if (preg_match($pattern, (string) $row['params'], $m)) $matches[] = $m[0];
                }

                $templateName = (string) $row['template'];
                $clientId     = (int) $row['client_id'];
                $isSystemTemplate = in_array(strtolower($templateName), $sig['TEMPLATE_SYSTEM_FOLDER_NAMES'], true);

                if ($templateName !== '' && !$isSystemTemplate) {
                    // Strongest, hardest-to-fake signal first: cross-reference
                    // Joomla's own #__extensions registry -- see
                    // getRegisteredTemplates()/checkJunkTemplateFolder() for
                    // why this is checked ahead of the on-disk manifest
                    // check below. A real attack faked the folder AND its
                    // templateDetails.xml AND even a matching #__extensions
                    // row, but every faked #__extensions row was left
                    // disabled -- unlike every genuinely-installed template.
                    if ($registeredTemplates !== null) {
                        $key = $clientId . '|' . strtolower($templateName);
                        if (!array_key_exists($key, $registeredTemplates)) {
                            $matches[] = "No matching #__extensions row of type \"template\" exists for \"{$templateName}\" -- Joomla never actually installed this as a real template";
                        } elseif (!$registeredTemplates[$key]) {
                            $matches[] = "Matching #__extensions row for \"{$templateName}\" exists but is disabled (enabled = 0) -- a strong sign of an injected row rather than a real, active template";
                        }
                    }

                    // Independent, on-disk corroborating signals -- still
                    // checked even when the registry already flagged the
                    // row above, and still useful on their own when the
                    // registry itself is unavailable (see getRegisteredTemplates()).
                    $templateDir = $clientId === 1
                        ? JPATH_ADMINISTRATOR . '/templates/' . $templateName
                        : $this->root . '/templates/' . $templateName;
                    $noManifest = !is_file($templateDir . '/templateDetails.xml');
                    $junkName   = (bool) preg_match($sig['TEMPLATE_STYLE_JUNK_NAME_RE'], $templateName);

                    if ($noManifest) {
                        $matches[] = is_dir($templateDir)
                            ? "Template folder \"{$templateName}\" exists but has no templateDetails.xml manifest -- was never actually installed as a real template, orphaned or injected row"
                            : "Template folder not found on disk ({$templateName}) -- orphaned or injected row";
                    }
                    if ($junkName) {
                        $matches[] = 'Auto-generated junk name pattern (tmpl_xxxxxx)';
                    }
                }

                if (!empty($matches)) {
                    $fingerprint = MuruguardHelper::fingerprintReasons($matches);
                    if (!MuruguardHelper::isFalsePositive($falsePositives, 'template_defacement', (string) $row['id'], $fingerprint)) {
                        $this->dbFindings['template_defacement'][] = [
                            'id' => $row['id'], 'template' => $row['template'], 'title' => $row['title'], 'matches' => $matches,
                        ];
                    }
                }
            }
        } catch (\Throwable $e) { /* non-fatal */ }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    public function deleteTargets(array $targets): array
    {
        $this->fileFindings = $this->getFileFindings();
        $sig = MuruguardHelper::getSignatures();
        $rootReal = realpath($this->root);
        $protectedAbs = array_map(fn($d) => $rootReal . DIRECTORY_SEPARATOR . $d, $sig['PROTECTED_TOP_DIRS']);
        $registeredTemplates = $this->getRegisteredTemplates();
        $flash = [];

        foreach ($targets as $relPath) {
            $relPath = (string) $relPath;
            if (!isset($this->fileFindings[$relPath])) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NOT_FLAGGED', $relPath); continue; }
            $abs = realpath($this->root . '/' . $relPath);
            if ($abs === false) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_VANISHED', $relPath); continue; }
            if (strpos($abs, $rootReal . DIRECTORY_SEPARATOR) !== 0) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_OUTSIDE_ROOT', $relPath); continue; }
            if (basename($abs) === 'configuration.php') { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_PROTECTED', $relPath); continue; }
            if (in_array($abs, $protectedAbs, true) || $abs === $rootReal) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_PROTECTED_DIR', $relPath); continue; }

            if (MuruguardHelper::isProtectedEntryPath($relPath, $sig, $abs, $registeredTemplates)) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_REQUIRED_ENTRY', $relPath);
                continue;
            }

            if (is_dir($abs)) {
                $flash[] = MuruguardHelper::deleteRecursive($abs) ? Text::sprintf('COM_MURUGUARD_FLASH_DELETED_FOLDER', $relPath) : Text::sprintf('COM_MURUGUARD_FLASH_FAILED_PERMISSIONS', $relPath);
            } elseif (is_file($abs)) {
                $flash[] = @unlink($abs) ? Text::sprintf('COM_MURUGUARD_FLASH_DELETED', $relPath) : Text::sprintf('COM_MURUGUARD_FLASH_FAILED_PERMISSIONS', $relPath);
            }
        }

        Factory::getApplication()->getSession()->set('muruguard.filefindings', null);
        return $flash;
    }

    /**
     * Surgically repairs selected files instead of deleting them -- for
     * the well-bounded injection patterns this scanner can safely fix
     * (a payload prepended before Joomla's bootstrap/access guard, or a
     * <script> block injected right after <head>) the exact malicious
     * region is known, so it can be stripped while leaving the rest of
     * the file -- a genuinely legitimate Joomla core/template file --
     * completely untouched. A timestamped backup of the original is
     * always written first so the change can be reviewed or reverted.
     */
    public function cleanCodeFiles(array $targets): array
    {
        $this->fileFindings = $this->getFileFindings();
        $rootReal = realpath($this->root);
        $cleanableExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'html', 'htm'];
        $flash = [];

        foreach ($targets as $relPath) {
            $relPath = (string) $relPath;
            if (!isset($this->fileFindings[$relPath])) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NOT_FLAGGED', $relPath); continue; }

            $abs = realpath($this->root . '/' . $relPath);
            if ($abs === false || !is_file($abs)) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_VANISHED', $relPath); continue; }
            if (strpos($abs, $rootReal . DIRECTORY_SEPARATOR) !== 0) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_OUTSIDE_ROOT', $relPath); continue; }

            $ext = strtolower(pathinfo($abs, PATHINFO_EXTENSION));
            if (!in_array($ext, $cleanableExts, true)) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NOT_CLEANABLE_TYPE', $relPath);
                continue;
            }

            // Checked explicitly (rather than only relying on
            // file_put_contents()'s return value) so a permissions
            // problem -- the single most common real-world reason a
            // "successful" clean silently doesn't stick on shared
            // hosting -- gets its own clear, actionable message.
            if (!is_writable($abs)) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NOT_WRITABLE', $relPath);
                continue;
            }

            $contents = @file_get_contents($abs);
            if ($contents === false) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_UNREADABLE', $relPath); continue; }

            $result = MuruguardHelper::cleanPrependedPayload($contents);
            if (!$result['changed']) {
                $result = MuruguardHelper::cleanHeadTagInjection($contents);
            }
            if (!$result['changed']) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NO_PATTERN', $relPath);
                continue;
            }

            $backup = $abs . '.muruguard-' . date('Ymd-His') . '.bak';
            if (@copy($abs, $backup) === false) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NO_BACKUP', $relPath);
                continue;
            }
            if (@file_put_contents($abs, $result['cleaned']) === false) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_FAILED_WRITE', basename($backup), $relPath);
                continue;
            }

            // Verify the write actually stuck by re-reading the file from
            // disk and confirming the same issue no longer matches --
            // catches caching layers, race conditions, or any other way a
            // "successful" write could fail to actually take effect,
            // instead of just trusting file_put_contents()'s return value.
            clearstatcache(true, $abs);
            $verifyContents = @file_get_contents($abs);
            $stillInfected = $verifyContents !== false && (
                MuruguardHelper::cleanPrependedPayload($verifyContents)['changed']
                || MuruguardHelper::cleanHeadTagInjection($verifyContents)['changed']
            );
            if ($stillInfected) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_WARNING_REVERTED', basename($backup), $relPath);
                continue;
            }

            $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_CLEANED', $result['removed_preview'], basename($backup), $relPath);
        }

        Factory::getApplication()->getSession()->set('muruguard.filefindings', null);
        return $flash;
    }

    public function cleanMenuXss(array $ids): array
    {
        $db = $this->getDatabase();
        $sig = MuruguardHelper::getSignatures();
        $flash = [];

        foreach ($ids as $id) {
            $id = (int) $id;
            $query = $db->getQuery(true)->select('params')->from($db->quoteName('#__menu'))->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($query);
            $paramsJson = $db->loadResult();
            if ($paramsJson === null) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_ROW_NOT_FOUND', $id); continue; }

            $result = MuruguardHelper::cleanMenuParamsXss((string) $paramsJson, array_values($sig['MENU_XSS_PATTERNS']));
            if (!$result['changed']) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_UNPARSEABLE', $id); continue; }

            $update = $db->getQuery(true)->update($db->quoteName('#__menu'))
                ->set($db->quoteName('params') . ' = ' . $db->quote($result['cleaned']))
                ->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($update);
            $db->execute();
            $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_CLEANED_MENU', $id);
        }
        return $flash;
    }

    /** Deletes selected rogue SP Page Builder asset rows. */
    public function deleteRogueAssets(array $ids): void
    {
        if (empty($ids)) return;
        $db = $this->getDatabase();
        $ids = array_map('intval', $ids);
        $query = $db->getQuery(true)->delete($db->quoteName('#__sppagebuilder_assets'))
            ->where($db->quoteName('id') . ' IN (' . implode(',', $ids) . ')');
        $db->setQuery($query);
        $db->execute();
    }

    /**
     * Deletes selected #__template_styles rows, but only the ones
     * independently confirmed as junk/injected -- an orphaned template
     * reference (folder not found on disk) or an auto-generated
     * tmpl_xxxxxx name. Rows flagged only for classic defacement TEXT are
     * left alone and reported as skipped: a text match alone isn't a
     * reliable enough signal to safely auto-delete a row that might
     * otherwise be a legitimate style (false positives are more likely
     * there than for the junk-name/orphaned-folder checks). Re-derives
     * each row's flags fresh from the DB rather than trusting the cached
     * scan result, same as cleanMenuXss() above.
     */
    public function cleanTemplateDefacement(array $ids): array
    {
        $db  = $this->getDatabase();
        $sig = MuruguardHelper::getSignatures();
        $flash = [];

        // Same registry cross-reference scanDatabase() already reports
        // against (see getRegisteredTemplates()) -- without this, a row
        // flagged ONLY because its #__extensions record is missing/
        // disabled (manifest present, name not junk-patterned) would show
        // up as a template_defacement finding but then get skipped here
        // every time, since neither $noManifest nor $junkName alone would
        // be true for it.
        $registeredTemplates = $this->getRegisteredTemplates();

        foreach ($ids as $id) {
            $id = (int) $id;
            $query = $db->getQuery(true)->select('id, template, client_id')
                ->from($db->quoteName('#__template_styles'))
                ->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($query);
            $row = $db->loadAssoc();
            if ($row === null) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_ROW_NOT_FOUND', $id);
                continue;
            }

            $templateDir = ((int) $row['client_id']) === 1
                ? JPATH_ADMINISTRATOR . '/templates/' . $row['template']
                : $this->root . '/templates/' . $row['template'];
            $isSystemTemplate = in_array(strtolower((string) $row['template']), $sig['TEMPLATE_SYSTEM_FOLDER_NAMES'], true);
            $noManifest = !$isSystemTemplate && $row['template'] !== '' && !is_file($templateDir . '/templateDetails.xml');
            $junkName   = (bool) preg_match($sig['TEMPLATE_STYLE_JUNK_NAME_RE'], (string) $row['template']);

            $registryProblem = false;
            if (!$isSystemTemplate && $row['template'] !== '' && $registeredTemplates !== null) {
                $key = ((int) $row['client_id']) . '|' . strtolower((string) $row['template']);
                $registryProblem = !array_key_exists($key, $registeredTemplates) || !$registeredTemplates[$key];
            }

            if (!$noManifest && !$junkName && !$registryProblem) {
                $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_REVIEW_DEFACEMENT', $id);
                continue;
            }

            $delete = $db->getQuery(true)->delete($db->quoteName('#__template_styles'))
                ->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($delete);
            $db->execute();
            $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_DELETED_DEFACEMENT', $id);
        }

        return $flash;
    }

    /**
     * Checks the installed SP Page Builder version from #__extensions and
     * returns a warning array if it is a vulnerable build.
     */
    public function getSppbVersionWarning(): ?array
    {
        try {
            $db    = $this->getDatabase();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['manifest_cache', 'enabled']))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('element') . ' = ' . $db->quote('com_sppagebuilder'))
                ->where($db->quoteName('type')    . ' = ' . $db->quote('component'));
            $db->setQuery($query);
            $row = $db->loadAssoc();
        } catch (\Throwable $e) {
            return null;
        }

        if (empty($row)) return null;

        $manifest = json_decode($row['manifest_cache'] ?? '{}', true);
        $version  = trim($manifest['version'] ?? '');

        if ($version === '') {
            return ['safe' => null, 'version' => 'unknown', 'major' => 0, 'enabled' => (bool) $row['enabled']];
        }

        $parts = array_map('intval', explode('.', $version));
        $major = $parts[0] ?? 0;
        $minor = $parts[1] ?? 0;
        $patch = $parts[2] ?? 0;

        $isSafe = ($major > 6)
            || ($major === 6 && $minor > 6)
            || ($major === 6 && $minor === 6 && $patch >= 2);

        return [
            'safe'    => $isSafe,
            'version' => $version,
            'major'   => $major,
            'enabled' => (bool) $row['enabled'],
        ];
    }
}
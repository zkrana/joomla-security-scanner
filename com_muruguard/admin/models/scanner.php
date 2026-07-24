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

class MuruguardModelScanner extends BaseDatabaseModel
{
    protected string $root;
    protected array $fileFindings = [];
    protected array $dbFindings = [
        'superusers' => [], 'menu_xss' => [], 'sppb_assets' => [],
        'rogue_iconfont' => [], 'template_defacement' => [],
    ];
    protected array $seenAbs = [];

    public function __construct($config = [])
    {
        parent::__construct($config);
        $this->root = JPATH_ROOT;
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
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/scan-history.json';
    }

    /** Null means the scheduled check has never run on this site. For the Settings panel's "Last run" indicator. */
    public function getLastScheduledRunTime(): ?int
    {
        $path = $this->scanHistoryFilePath();
        if (!is_file($path)) return null;

        $contents = @file_get_contents($path);
        if ($contents === false) return null;

        $decoded = json_decode($contents, true);
        return is_array($decoded) && isset($decoded['saved_at']) ? (int) $decoded['saved_at'] : null;
    }

    /** Null means "never run before" (as opposed to an empty array, which means the last run found nothing). */
    private function loadLastScanKeys(): ?array
    {
        $path = $this->scanHistoryFilePath();
        if (!is_file($path)) return null;

        $contents = @file_get_contents($path);
        if ($contents === false) return null;

        $decoded = json_decode($contents, true);
        if (!is_array($decoded) || !isset($decoded['keys']) || !is_array($decoded['keys'])) return null;
        return $decoded['keys'];
    }

    private function saveLastScanKeys(array $keys): void
    {
        $path = $this->scanHistoryFilePath();
        @file_put_contents($path, json_encode(['keys' => $keys, 'saved_at' => time()]));
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
    public function saveShieldSettings(bool $enabled, bool $blockPatterns, bool $blockBruteForce, int $threshold, int $window): void
    {
        $table = new \Joomla\CMS\Table\Extension($this->getDatabase());
        if (!$table->load(['element' => 'com_muruguard', 'type' => 'component'])) return;

        $params = json_decode((string) $table->params, true);
        if (!is_array($params)) $params = [];
        $params['shield_enabled'] = $enabled ? 1 : 0;
        $params['shield_block_patterns'] = $blockPatterns ? 1 : 0;
        $params['shield_block_bruteforce'] = $blockBruteForce ? 1 : 0;
        $params['shield_bruteforce_threshold'] = max(2, min(50, $threshold));
        $params['shield_bruteforce_window'] = max(1, min(1440, $window));
        $table->params = json_encode($params);
        $table->store();
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

    public function scanFilesystem(): void
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

        foreach ($sig['SCAN_CONFIG'] as $relDir => $mode) {
            if (!$this->isAreaSelected($relDir)) continue;
            $dir = $this->root . '/' . $relDir;
            if (!is_dir($dir)) continue;

            MuruguardHelper::walkDir($dir, function (string $path, bool $isDir) use ($sig, $mode, $maxSize, $isIgnored, $selfBackupPattern) {
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

                // iconfont strict allow-list
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
                        } elseif ($parentBase === 'iconfont') {
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
                        if (!$isKnownSafeEntry && !$isBlankStub && in_array($ext, $sig['EXEC_EXTS'], true)) {
                            $flagged = true;
                            $reasons[] = "Executable file (.$ext) inside an upload directory — these should never contain runnable code.";
                        }
                        if (!$isKnownSafeEntry) {
                            foreach ($sig['SUSPICIOUS_FILENAME_REGEXES'] as $re) {
                                if (preg_match($re, $basename)) { $flagged = true; $reasons[] = 'Filename matches known malicious pattern.'; break; }
                            }
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
                        $flagged = true;
                    }
                }

                // core-path masquerade check (location-based, runs both modes)
                $masq = MuruguardHelper::checkCoreMasquerade($relCheck, $isDir, $sig, $path);
                if ($masq !== null) { $flagged = true; $reasons[] = $masq; }

                // junk auto-generated template folder check (location-based, runs both modes)
                $junkTpl = MuruguardHelper::checkJunkTemplateFolder($relCheck, $sig);
                if ($junkTpl !== null) { $flagged = true; $reasons[] = $junkTpl; }

                // stray index.php structural check (location-based, runs both modes)
                if (!$isDir && !$isKnownSafeEntry) {
                    $strayIdx = MuruguardHelper::checkStrayIndexPhp($relCheck, $path, $sig);
                    if ($strayIdx !== null) { $flagged = true; $reasons[] = $strayIdx; }
                }

                if ($flagged) {
                    $this->seenAbs[$path] = true;
                    MuruguardHelper::recordFinding($this->fileFindings, $path, $this->root, $reasons, $isDir);
                }
            });
        }

        // Shallow webroot scan
        $rootItems = $this->isAreaSelected('webroot') ? (@scandir($this->root) ?: []) : [];
        foreach ($rootItems as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $this->root . '/' . $it;
            if (isset($this->seenAbs[$p])) continue;
            if (preg_match($selfLogPattern, $it)) continue;
            if (preg_match($selfBackupPattern, $it)) continue;
            if (preg_match($googleVerifyPattern, $it)) continue;
            if ($isIgnored($it)) continue;

            if (is_dir($p)) {
                if (!in_array(strtolower($it), array_map('strtolower', $sig['KNOWN_ROOT_DIRS']), true)) {
                    $this->seenAbs[$p] = true;
                    MuruguardHelper::recordFinding($this->fileFindings, $p, $this->root,
                        'Unrecognized directory directly in the Joomla webroot — not part of a standard install.', true);
                    MuruguardHelper::walkDir($p, function (string $innerPath, bool $innerIsDir) {
                        if ($innerIsDir || isset($this->seenAbs[$innerPath])) return;
                        $this->seenAbs[$innerPath] = true;
                        MuruguardHelper::recordFinding($this->fileFindings, $innerPath, $this->root,
                            'Inside an unrecognized top-level webroot directory.', false);
                    });
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
                MuruguardHelper::recordFinding($this->fileFindings, $p, $this->root, $reasonsRoot, false);
            }
        }

        // Core entry-point integrity + content-signature scan, plus (when
        // the site's exact Joomla version is covered by the bundled
        // manifest) a byte-for-byte checksum comparison against the
        // official release -- unambiguous proof of tampering, independent
        // of and stronger than every heuristic check here.
        $joomlaVersion = MuruguardHelper::getInstalledJoomlaVersion($this->root);
        $checksumManifest = MuruguardHelper::getCoreChecksumManifest();

        $coreEntries = $this->isAreaSelected('core_entry') ? $sig['CORE_ENTRY_POINTS'] : [];
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
        if ($this->isAreaSelected('core_entry') && $joomlaVersion !== null && isset($checksumManifest[$joomlaVersion])) {
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
                $this->dbFindings['superusers'][] = [
                    'id' => $row['id'], 'name' => $row['name'], 'username' => $row['username'],
                    'email' => $row['email'], 'registered' => $row['registerDate'], 'lastvisit' => $row['lastvisitDate'],
                    'suspicious' => $suspicious, 'why' => implode('; ', $why),
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
                    $this->dbFindings['menu_xss'][] = [
                        'id' => $row['id'], 'title' => $row['title'], 'link' => $row['link'], 'matches' => $matches,
                    ];
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

            // Ignore official IcoFont
            if ($name !== 'icofont') {

                $reasons[] = 'Non-default iconfont';

                if ($createdBy === 0) {
                    $reasons[] = 'Created by Guest/System';
                }

                // Separate delete candidates
                $this->dbFindings['rogue_iconfont'][] = $row;
            }
        }


        /*
         * Only store suspicious rows
         */
        if (!empty($reasons)) {

            $row['scan_reasons'] = array_values(array_unique($reasons));

            $this->dbFindings['sppb_assets'][] = $row;
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
            foreach ($rows as $row) {
                $matches = [];
                foreach ($sig['DEFACEMENT_PATTERNS'] as $pattern) {
                    if (preg_match($pattern, (string) $row['params'], $m)) $matches[] = $m[0];
                }

                // Second, independent check: junk/injected rows rather than
                // classic defacement text. A legitimate #__template_styles
                // row's "template" column always names a template that's
                // actually installed -- Joomla itself has no code path that
                // creates a style row pointing at a non-existent template
                // folder. A row that does is either leftover cruft from an
                // uninstalled template (rare, and rare enough to accept as
                // an occasional false positive) or, combined with the
                // auto-generated tmpl_xxxxxx naming pattern seen in real
                // compromises, injected junk data.
                $templateDir = ((int) $row['client_id']) === 1
                    ? JPATH_ADMINISTRATOR . '/templates/' . $row['template']
                    : $this->root . '/templates/' . $row['template'];
                $folderMissing = $row['template'] !== '' && !is_dir($templateDir);
                $junkName      = (bool) preg_match($sig['TEMPLATE_STYLE_JUNK_NAME_RE'], (string) $row['template']);

                if ($folderMissing) {
                    $matches[] = "Template folder not found on disk ({$row['template']}) -- orphaned or injected row";
                }
                if ($junkName) {
                    $matches[] = 'Auto-generated junk name pattern (tmpl_xxxxxx)';
                }

                if (!empty($matches)) {
                    $this->dbFindings['template_defacement'][] = [
                        'id' => $row['id'], 'template' => $row['template'], 'title' => $row['title'], 'matches' => $matches,
                    ];
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
        $flash = [];

        foreach ($targets as $relPath) {
            $relPath = (string) $relPath;
            if (!isset($this->fileFindings[$relPath])) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_NOT_FLAGGED', $relPath); continue; }
            $abs = realpath($this->root . '/' . $relPath);
            if ($abs === false) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_VANISHED', $relPath); continue; }
            if (strpos($abs, $rootReal . DIRECTORY_SEPARATOR) !== 0) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_OUTSIDE_ROOT', $relPath); continue; }
            if (basename($abs) === 'configuration.php') { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_PROTECTED', $relPath); continue; }
            if (in_array($abs, $protectedAbs, true) || $abs === $rootReal) { $flash[] = Text::sprintf('COM_MURUGUARD_FLASH_SKIPPED_PROTECTED_DIR', $relPath); continue; }

            if (MuruguardHelper::isProtectedEntryPath($relPath, $sig)) {
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
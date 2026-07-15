<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Model\BaseDatabaseModel;
use Joomla\CMS\Factory;
use Joomla\CMS\Component\ComponentHelper;

require_once JPATH_ADMINISTRATOR . '/components/com_sppbscan/helpers/sppbscan.php';

class SppbscanModelScanner extends BaseDatabaseModel
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
        return (array) Factory::getApplication()->getSession()->get('sppbscan.scan_areas', []);
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
            $cached = $session->get('sppbscan.filefindings');
            $cachedAt = $session->get('sppbscan.filefindings_time', 0);
            if (is_array($cached) && (time() - $cachedAt) < 300) {
                $this->fileFindings = $cached;
                return $this->fileFindings;
            }
        }

        $this->scanFilesystem();
        $session->set('sppbscan.filefindings', $this->fileFindings);
        $session->set('sppbscan.filefindings_time', time());
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
        $cached = Factory::getApplication()->getSession()->get('sppbscan.filefindings');
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
        $session->set('sppbscan.filefindings', $this->fileFindings);
        $session->set('sppbscan.filefindings_time', $now);
        return $now;
    }

    // ------------------------------------------------------------------
    // Filesystem scan
    // ------------------------------------------------------------------

    public function scanFilesystem(): void
    {
        $sig = SppbscanHelper::getSignatures();
        $params = ComponentHelper::getParams('com_sppbscan');
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

        $selfLogPattern  = '/^\.sppbscan-[a-f0-9]{16}\.(log|lock)$/i';
        $googleVerifyPattern = '/^google[a-f0-9]{16,}\.html$/i';

        foreach ($sig['SCAN_CONFIG'] as $relDir => $mode) {
            if (!$this->isAreaSelected($relDir)) continue;
            $dir = $this->root . '/' . $relDir;
            if (!is_dir($dir)) continue;

            SppbscanHelper::walkDir($dir, function (string $path, bool $isDir) use ($sig, $mode, $maxSize, $isIgnored) {
                foreach ($sig['SAFE_COMPONENT_PATHS'] as $safeFrag) {
                    if (stripos($path, $safeFrag) !== false) return;
                }
                if (preg_match('#/tmp/install_[a-z0-9]+(/|$)#i', $path)) {
                    return; // Joomla's own installer extraction folder — transient, not user-uploadable
                }
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
                        if (preg_match('/^\d+$/', $basename) && !SppbscanHelper::isDateLikeNumericFolderName($basename)) {
                            $flagged = true;
                            $reasons[] = "Folder name is purely numeric (\"{$basename}\") and isn't a normal date/ID component — a common automated-malware-drop pattern.";
                        }
                    } else {
                        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                        $isBlankStub = false;
                        if ($ext === 'php' && strcasecmp($basename, 'index.php') === 0) {
                            $stubContents = @file_get_contents($path, false, null, 0, 4096);
                            if ($stubContents !== false && SppbscanHelper::isStandardJoomlaStub($stubContents)) {
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
                    if (SppbscanHelper::scanFileContent($path, $ext, $sig, $maxSize, $reasons)) {
                        $flagged = true;
                    }
                }

                // core-path masquerade check (location-based, runs both modes)
                $masq = SppbscanHelper::checkCoreMasquerade($relCheck, $isDir, $sig);
                if ($masq !== null) { $flagged = true; $reasons[] = $masq; }

                if ($flagged) {
                    $this->seenAbs[$path] = true;
                    SppbscanHelper::recordFinding($this->fileFindings, $path, $this->root, implode(' | ', array_unique($reasons)), $isDir);
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
            if (preg_match($googleVerifyPattern, $it)) continue;
            if ($isIgnored($it)) continue;

            if (is_dir($p)) {
                if (!in_array(strtolower($it), array_map('strtolower', $sig['KNOWN_ROOT_DIRS']), true)) {
                    $this->seenAbs[$p] = true;
                    SppbscanHelper::recordFinding($this->fileFindings, $p, $this->root,
                        'Unrecognized directory directly in the Joomla webroot — not part of a standard install.', true);
                    SppbscanHelper::walkDir($p, function (string $innerPath, bool $innerIsDir) {
                        if ($innerIsDir || isset($this->seenAbs[$innerPath])) return;
                        $this->seenAbs[$innerPath] = true;
                        SppbscanHelper::recordFinding($this->fileFindings, $innerPath, $this->root,
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

            $masqRoot = SppbscanHelper::checkCoreMasquerade($relCheck, false, $sig);
            if ($masqRoot !== null) { $flaggedRoot = true; $reasonsRoot[] = $masqRoot; }

            $extR = strtolower(pathinfo($p, PATHINFO_EXTENSION));
            SppbscanHelper::scanFileContent($p, $extR, $sig, $maxSize, $reasonsRoot);
            if (count($reasonsRoot) > ($flaggedRoot ? 1 : 0)) $flaggedRoot = true;

            $benignStaticExts = ['css', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp', 'woff', 'woff2', 'ttf', 'eot', 'map'];
            if (!$flaggedRoot && !in_array($extR, $benignStaticExts, true)) {
                $flaggedRoot = true;
                $reasonsRoot[] = 'Unrecognized file directly in the Joomla webroot — not part of a standard install.';
            }

            if ($flaggedRoot) {
                $this->seenAbs[$p] = true;
                SppbscanHelper::recordFinding($this->fileFindings, $p, $this->root, implode(' | ', array_unique($reasonsRoot)), false);
            }
        }

        // Core entry-point integrity + content-signature scan
        $coreEntries = $this->isAreaSelected('core_entry') ? $sig['CORE_ENTRY_POINTS'] : [];
        foreach ($coreEntries as $relEntry) {
            $absEntry = $this->root . '/' . $relEntry;
            if (!is_file($absEntry)) continue;
            $size = @filesize($absEntry);
            if ($size === false || $size > $maxSize) continue;
            $contents = @file_get_contents($absEntry);
            if ($contents === false) continue;

            $reasonsEntry = [];
            $issue = SppbscanHelper::checkCoreIndexIntegrity($contents);
            if ($issue !== null) $reasonsEntry[] = $issue;

            $ext = strtolower(pathinfo($absEntry, PATHINFO_EXTENSION));
            SppbscanHelper::scanFileContent($absEntry, $ext, $sig, $maxSize, $reasonsEntry);

            if (!empty($reasonsEntry)) {
                $this->seenAbs[$absEntry] = true;
                SppbscanHelper::recordFinding($this->fileFindings, $absEntry, $this->root, implode(' | ', array_unique($reasonsEntry)), false);
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
        $sig = SppbscanHelper::getSignatures();

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

        $assetValue = (string) ($row['asset_value'] ?? '');
        $type       = strtolower((string) ($row['type'] ?? ''));
        $name       = strtolower((string) ($row['name'] ?? ''));
        $createdBy  = (int) ($row['created_by'] ?? 0);


        /*
         * Payload detection
         */
        if (stripos($assetValue, 'xss.report') !== false) {
            $reasons[] = 'Contains xss.report';
        }

        if (stripos($assetValue, 'base64_decode') !== false) {
            $reasons[] = 'Contains base64_decode()';
        }

        if (stripos($assetValue, 'eval(') !== false) {
            $reasons[] = 'Contains eval()';
        }

        if (stripos($assetValue, '<script') !== false) {
            $reasons[] = 'Contains script tag';
        }

        if (preg_match('/on(load|error|click|mouseover)\s*=/i', $assetValue)) {
            $reasons[] = 'Contains JavaScript event handler';
        }


        /*
         * Iconfont detection
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
            $query = $db->getQuery(true)->select('id, template, title, params')->from($db->quoteName('#__template_styles'));
            $db->setQuery($query);
            $rows = $db->loadAssocList() ?: [];
            foreach ($rows as $row) {
                $matches = [];
                foreach ($sig['DEFACEMENT_PATTERNS'] as $pattern) {
                    if (preg_match($pattern, $row['params'], $m)) $matches[] = $m[0];
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
        $sig = SppbscanHelper::getSignatures();
        $rootReal = realpath($this->root);
        $protectedAbs = array_map(fn($d) => $rootReal . DIRECTORY_SEPARATOR . $d, $sig['PROTECTED_TOP_DIRS']);
        $flash = [];

        foreach ($targets as $relPath) {
            $relPath = (string) $relPath;
            if (!isset($this->fileFindings[$relPath])) { $flash[] = "SKIPPED (not flagged): $relPath"; continue; }
            $abs = realpath($this->root . '/' . $relPath);
            if ($abs === false) { $flash[] = "SKIPPED (file vanished): $relPath"; continue; }
            if (strpos($abs, $rootReal . DIRECTORY_SEPARATOR) !== 0) { $flash[] = "SKIPPED (outside root): $relPath"; continue; }
            if (basename($abs) === 'configuration.php') { $flash[] = "SKIPPED (protected): $relPath"; continue; }
            if (in_array($abs, $protectedAbs, true) || $abs === $rootReal) { $flash[] = "SKIPPED (protected top-level directory): $relPath"; continue; }

            if (is_dir($abs)) {
                $flash[] = SppbscanHelper::deleteRecursive($abs) ? "DELETED (folder): $relPath" : "FAILED (permissions?): $relPath";
            } elseif (is_file($abs)) {
                $flash[] = @unlink($abs) ? "DELETED: $relPath" : "FAILED (permissions?): $relPath";
            }
        }

        Factory::getApplication()->getSession()->set('sppbscan.filefindings', null);
        return $flash;
    }

    public function cleanMenuXss(array $ids): array
    {
        $db = $this->getDatabase();
        $sig = SppbscanHelper::getSignatures();
        $flash = [];

        foreach ($ids as $id) {
            $id = (int) $id;
            $query = $db->getQuery(true)->select('params')->from($db->quoteName('#__menu'))->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($query);
            $paramsJson = $db->loadResult();
            if ($paramsJson === null) { $flash[] = "SKIPPED (row not found): id $id"; continue; }

            $result = SppbscanHelper::cleanMenuParamsXss((string) $paramsJson, array_values($sig['MENU_XSS_PATTERNS']));
            if (!$result['changed']) { $flash[] = "SKIPPED (couldn't safely parse params — clean manually): id $id"; continue; }

            $update = $db->getQuery(true)->update($db->quoteName('#__menu'))
                ->set($db->quoteName('params') . ' = ' . $db->quote($result['cleaned']))
                ->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($update);
            $db->execute();
            $flash[] = "CLEANED injection from params, rest of settings kept: id $id";
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
<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 *
 * Pure detection/cleaning logic, ported near-verbatim from the standalone
 * scanner script. None of this is Joomla-specific -- it is the same
 * regex/filesystem heuristics as before, just wrapped as static methods
 * so the model can call them. Signature arrays live in getSignatures().
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

class SppbscanHelper
{
    /**
     * Ensures the request is from a logged-in backend user with manage rights.
     * Call from entry point, controllers, views, and destructive model methods.
     */
    public static function requireManageAccess(): void
    {
        $user = Factory::getApplication()->getIdentity();

        if ($user->guest || (int) $user->id <= 0) {
            throw new \Joomla\CMS\Exception\NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }

        if (!$user->authorise('core.manage', 'com_sppbscan')) {
            throw new \Joomla\CMS\Exception\NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }
    }

    /** Central place for every pattern list used across the scan. */
    public static function getSignatures(): array
    {
        return [
            'EXEC_EXTS' => ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pht', 'shtml'],

            'SUSPICIOUS_FILENAME_REGEXES' => [
                '/^codex-sppb-[a-f0-9]+\.php$/i',
                '/^codex_sppb.*\.php$/i',
                '/queue_\d+\.php$/i',
                '/\.php\.gif$/i',
                '/\.xml\.php$/i',
                '/^x\.xml$/i',
            ],

            'ROOT_SUSPICIOUS_FILENAME_REGEXES' => [
                '/^wp-[a-z0-9_-]*\.(php|txt|html?)$/i',
                '/file[-_]?ma[nr]+ger2?\.php$/i',
                '/^[a-z0-9]{1,3}\.php$/i',
                '/^\d{1,8}\.php$/i',
                '/^[a-z]{2,8}\.txt$/i',
            ],

            'CONFIG_BACKUP_PATTERNS' => [
                '/^configuration[\._\-]?bak\.php$/i',
                '/^configuration[\._\-]?old\.php$/i',
                '/^configuration\.php\.(bak|old|orig|save|swp|~)$/i',
                '/^config[\._\-]?backup\.php$/i',
                '/^configuration\d*\.php\.(txt|bak)$/i',
            ],

            // Each signature carries its own severity + a plain-language
            // explanation of why it's flagged, rather than one blanket
            // "any content signature match = High" rule. Signatures with a
            // plausible legitimate explanation (obfuscated-but-legal
            // commercial extension code, a legit extension using zip://
            // for archive handling, a dev-config placeholder domain, ...)
            // are scored 'medium' -- worth a human look, not an automatic
            // high-confidence verdict -- so a real webshell isn't diluted
            // down to "just another medium finding" next to false alarms.
            'CONTENT_SIGNATURES' => [
                'eval_base64_post'   => ['re' => '/eval\s*\(\s*(?:@)?base64_decode\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
                    'severity' => 'high', 'why' => 'Executes attacker-supplied POST/REQUEST/GET data via base64-decoded eval() — the canonical one-line PHP webshell pattern, no legitimate use.'],
                'cookie_gated_eval'  => ['re' => '/md5\s*\(\s*(?:@)?\$_COOKIE\[[\'"][^\'"]+[\'"]\]\s*\)\s*==\s*[\'"][a-f0-9]{32}[\'"]/i',
                    'severity' => 'high', 'why' => 'Gates hidden behavior behind a secret cookie value matched by MD5 hash — a common backdoor-access-control pattern.'],
                'assert_backdoor'    => ['re' => '/assert\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
                    'severity' => 'high', 'why' => 'Passes attacker-supplied request data directly into assert(), which historically executes its string argument as PHP code — a known backdoor technique.'],
                'gsocket_indicator'  => ['re' => '/GS_ARGS|gsocket/i',
                    'severity' => 'high', 'why' => 'References gsocket, a reverse-shell/tunneling tool used to give an attacker an interactive shell on the server.'],
                'shell_exec_chain'   => ['re' => '/shell_exec\s*\(\s*\$_(POST|REQUEST|GET)/i',
                    'severity' => 'high', 'why' => 'Runs attacker-supplied request data as an OS shell command via shell_exec() — direct remote command execution.'],
                'xss_report_payload' => ['re' => '/xss\.report|_hu_inject/i',
                    'severity' => 'high', 'why' => 'Matches the known xss.report / _hu_inject marker used by the Helix Ultimate mega-menu XSS campaign tied to this SPPB compromise.'],
                'webshell_generic'   => ['re' => '/FilesMan|c99shell|r57shell|WSO\s*Web\s*Shell/i',
                    'severity' => 'high', 'why' => 'Matches the signature banner of a well-known, widely-distributed PHP webshell kit.'],
                'self_replicating_dropper' => ['re' => '/glob\s*\(.{0,40}GLOB_ONLYDIR.{0,200}?file_put_contents\s*\(.{0,400}?md5\s*\(\s*\$\w+\s*\)\s*==\s*md5\s*\(\s*file_get_contents/is',
                    'severity' => 'high', 'why' => 'Walks directories and rewrites files only when their content differs from a reference copy — a self-replicating/self-healing dropper pattern, not something legitimate code does.'],
                'noop_comment_padding' => ['re' => '/(;\s*\/\*\s*\w{3,12}\s*\*\/\s*;\s*){8,}/i',
                    'severity' => 'high', 'why' => 'Long chain of no-op statements padded with comments — a scanner-evasion technique to break up detectable strings, not something a compiler or formatter produces.'],
                'secure_local_marker' => ['re' => '/secure\.local/i',
                    'severity' => 'medium', 'why' => 'Matches the "secure.local" marker seen in this campaign\'s rogue accounts/payloads, but this string can also appear in ordinary dev/staging config examples — verify the surrounding code before treating as confirmed.'],
                'stream_wrapper_payload' => ['re' => '/require(?:_once)?\s*\(?\s*\$?\w*\s*\)?\s*;?.{0,200}?(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//is',
                    'severity' => 'medium', 'why' => 'Loads code through a zip://phar://compress.*:// stream wrapper near a require -- a known payload-loading trick, but some legitimate extensions (backup/restore tools, archive handlers) use these wrappers for real archive access. Check what is actually being loaded.'],
                'chr_byte_array_decode' => ['re' => '/\$\w+\s*=\s*array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)\s*;.{0,300}?chr\s*\(\s*\$\w+\[\$?\w+\]\s*\)/is',
                    'severity' => 'medium', 'why' => 'Reconstructs a string from a numeric byte array via chr() — common in obfuscated payloads, but also seen in some legitimately-obfuscated (not malicious) commercial extension license checks. Review what the reconstructed string does.'],
                'string_lookup_obfuscation' => ['re' => '/\$_?\w+\s*=\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}[\'"]\s*\)\s*;.{0,80}?\$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]/is',
                    'severity' => 'medium', 'why' => 'Decodes a long base64 blob then rebuilds identifiers via string-index lookups — a common obfuscation shape, but also used by some legitimate obfuscated/licensed commercial extensions. Review what the rebuilt identifiers resolve to.'],
                'opcache_reset_only' => ['re' => '/^\s*<\?php\s*opcache_reset\s*\(\s*\)\s*;\s*\?>\s*$/i',
                    'severity' => 'medium', 'why' => 'A file whose entire content is just opcache_reset() is functionally harmless by itself, but matches a known dropper self-cleanup helper used to force PHP to immediately pick up newly-written malicious files elsewhere.'],
            ],

            'MENU_XSS_PATTERNS' => [
                'xss.report domain'            => '/xss\.report/i',
                '_hu_inject marker'            => '/_hu_?inject/i',
                'secure.local marker'          => '/secure\.local/i',
                'onerror/onload event handler' => '/on(error|load|mouseover|focus)\s*=/i',
                'inline <script> tag'          => '/<script[\s>]/i',
                'localStorage exfil/inject'    => '/localStorage\s*\.\s*(setItem|getItem)/i',
                'sessionStorage exfil/inject'  => '/sessionStorage\s*\.\s*(setItem|getItem)/i',
                'sessionStorage _hxd marker'   => '/sessionStorage\s*\.\s*_hxd/i',
                'MutationObserver persistence' => '/MutationObserver/i',
                'img src=x XSS payload'        => '/<img[^>]+src\s*=\s*["\']?x["\']?/i',
                'script element creation'      => '/document\s*\.\s*createElement\s*\(\s*[\'"]script[\'"]\s*\)/i',
                'self-invoking IIFE wrapper'   => '/\(\s*function\s*\(\s*\)\s*\{\s*[\'"]use strict[\'"]/i',
            ],

            'DEFACEMENT_PATTERNS' => [
                '/Hacked\s+by/i', '/Owned\s+by/i', '/Pwned\s+by/i', '/Defaced\s+by/i',
                '/H4cked/i', '/0wned/i', '/w4s\s+here/i', '/was\s+here/i',
                '/greetz\s+to/i', '/shell\s+by/i', '/r00ted/i',
            ],

            'NON_PHP_EXTS_THAT_MUST_STAY_CLEAN' => ['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg', 'bmp'],
            // <?php is 5 literal bytes -- vanishingly unlikely to occur by
            // chance in binary image data. The <?= short tag is only 3
            // bytes, which DOES turn up by pure random chance in the
            // megabytes of high-entropy compressed pixel data a large
            // photo can contain -- so it's required to be followed by a
            // plausible PHP token (optionally preceded by whitespace), not
            // matched bare, to avoid flagging ordinary large photos.
            'PHP_OPEN_TAG_RE' => '/<\?php|<\?=\s*[\$A-Za-z_(]/i',

            'CORE_ENTRY_POINTS' => ['index.php', 'administrator/index.php', 'api/index.php', 'includes/app.php'],

            'KNOWN_ROOT_FILES' => [
                'index.php', 'configuration.php', 'htaccess.txt', 'web.config.txt', 'robots.txt.dist',
                'robots.txt', 'LICENSE.txt', 'README.txt', 'joomla.xml', 'htaccess.bak',
                'php.ini', 'php.ini.bak', '.user.ini', '.htaccess', '.htaccess.bak', 'sitemap.xml', 'sitemap.xml.gz',
            ],

            'KNOWN_SAFE_RELATIVE_FILES' => [
                'index.php', 'administrator/index.php', '', 'api/index.php',
                'includes/app.php', 'includes/framework.php', 'cli/joomla.php',
                'files/index.html', 'images/index.html', 'media/index.html',
            ],

            'SAFE_COMPONENT_PATHS' => [
                '/administrator/components/com_sppbscan/',
                '/administrator/components/com_rsfirewall/',
                '/administrator/components/com_htprotect/',
                '/administrator/components/com_akeeba/',
                '/administrator/components/com_admintools/',
            ],

            'ICONFONT_ALLOWED_DIRNAMES'   => ['css', 'font', 'fonts', 'demo', 'docs', 'demo-files'],
            'ICONFONT_ALLOWED_EXTENSIONS' => ['woff', 'woff2', 'ttf', 'eot', 'otf', 'svg', 'css', 'json', 'html', 'htm', 'txt', 'md'],
            'ICONFONT_ALLOWED_BARE_NAMES' => ['license', 'readme', 'changelog'],

            'JCE_UPLOAD_PATH_FRAGMENTS'      => ['/media/com_jce/editor/tiny_mce/plugins/filemanager/'],
            'JCE_UPLOAD_ALLOWED_EXTENSIONS'  => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'css', 'js', 'json', 'html', 'htm'],

            'KNOWN_ROOT_DIRS' => [
                'administrator', 'api', 'bin', 'cache', 'cli', 'components', 'includes',
                'language', 'layouts', 'libraries', 'media', 'modules', 'plugins',
                'templates', 'tmp', 'images', 'files', 'node_modules', '.well-known', 'logs',
            ],

            'PROTECTED_TOP_DIRS' => [
                'administrator', 'components', 'libraries', 'media', 'images', 'templates',
                'plugins', 'modules', 'language', 'cache', 'tmp', 'layouts', 'includes', 'api', 'cli',
            ],

            // Directories scanned recursively, and in which mode.
            // 'upload' = strict structural checks (no exec files, no numeric drop folders).
            // 'code'   = signature-only (this is real extension code, .php is expected).
            'SCAN_CONFIG' => [
                'media' => 'upload', 'images' => 'upload', 'tmp' => 'upload',
                'cache' => 'upload', 'files' => 'upload',
                'components' => 'code', 'administrator/components' => 'code',
                'modules' => 'code', 'administrator/modules' => 'code',
                'plugins' => 'code', 'administrator/includes' => 'code',
                'libraries' => 'code', 'templates' => 'code', 'administrator/templates' => 'code',
                'cli' => 'code', 'bin' => 'code',
            ],

            // Exact relative paths seen in real-world attacks where the
            // attacker names a dropped file to LOOK like a plausible core
            // Joomla file (blending into a legitimate-looking directory
            // structure) even though no such core file actually exists.
            // Grow this list every time a new masquerade path is found.
            'CORE_MASQUERADE_EXACT_PATHS' => [
                'libraries/system.php',
                'bin/cms.php',
                'cli/cli.php',
                'templates/system/network.php',
                'templates/system/online.php',
                'options.php',
                'plugins/content/joomla/content.php',
            ],

            // Third-party-template masquerade paths, matched against ANY
            // template name (not a fixed template like the core-path list
            // above). No clean install of any known Joomla template ships
            // a top-level "features" folder with an index.php inside it --
            // flagged on location alone, regardless of file content, since
            // an attacker can trivially make the payload look like a
            // blank access-guard stub to dodge a content-only check.
            // Grow this list every time a new masquerade path is found.
            'TEMPLATE_FOLDER_MASQUERADE_PATTERNS' => [
                '#^(administrator/)?templates/[^/]+/features/index\.php$#i',
            ],

            // Folders where real Joomla core only ever places a small,
            // fixed set of loose files directly at the top level -- any
            // OTHER file sitting directly there (not nested in a real
            // subfolder like libraries/src/ or libraries/vendor/) is
            // almost certainly a payload disguised with a core-sounding
            // path, which is a stealthier pattern than a randomly-named
            // webshell since the filename itself looks legitimate.
            'CORE_LOOSE_FILE_ALLOWLIST' => [
                'libraries' => [
                    'bootstrap.php', 'loader.php', 'classmap.php', 'namespacemap.php',
                    'import.php', 'import.legacy.php', 'platform.php', 'fof30.autoload.php',
                ],
                'cli' => [
                    'joomla.php', 'import.php', 'update_cron.php', 'deletefiles.php', 'garbagecron.php',
                ],
                'bin' => [],
                // templates/system is Joomla's built-in system/error template.
                // Its top-level loose files are a small, fixed set; anything
                // else there (network.php, online.php, ...) is a disguise.
                'templates/system' => [
                    'index.php', 'error.php', 'error.full.php', 'offline.php', 'component.php',
                ],
            ],
        ];
    }

    /**
     * Canonical, user-selectable scan areas grouped for the pre-scan
     * directory picker. Filesystem keys match SCAN_CONFIG relative dirs so
     * the model can filter directly; the pseudo-keys core_entry / webroot /
     * database gate the non-SCAN_CONFIG passes.
     */
    public static function getScanAreas(): array
    {
        return [
            'Upload & media directories' => [
                'media'  => 'media/',
                'images' => 'images/',
                'tmp'    => 'tmp/',
                'cache'  => 'cache/',
                'files'  => 'files/',
            ],
            'Extension & template code' => [
                'components'                => 'components/',
                'administrator/components'  => 'administrator/components/',
                'modules'                   => 'modules/',
                'administrator/modules'     => 'administrator/modules/',
                'plugins'                   => 'plugins/',
                'libraries'                 => 'libraries/',
                'templates'                 => 'templates/',
                'administrator/templates'   => 'administrator/templates/',
                'administrator/includes'    => 'administrator/includes/',
                'cli'                       => 'cli/',
                'bin'                       => 'bin/',
            ],
            'Core &amp; webroot' => [
                'core_entry' => 'Core entry points (index.php, administrator/index.php, api/index.php)',
                'webroot'    => 'Webroot top-level files &amp; unknown folders',
            ],
            'Database' => [
                'database' => 'Users, menu XSS, SP Page Builder assets, template styles',
            ],
        ];
    }

    /**
     * Detects files whose PATH masquerades as legitimate Joomla core even
     * though no such file exists in a clean install -- the stealthiest
     * dropper pattern, because the filename itself looks trustworthy.
     * Complements the content-signature scan (which only fires on payload
     * text): a masquerade file can be flagged on its location alone.
     *
     * Returns a human-readable reason string, or null if nothing matched.
     */
    public static function checkCoreMasquerade(string $relPath, bool $isDir, array $sig): ?string
    {
        $relPath = ltrim(str_replace('\\', '/', $relPath), '/');
        if ($relPath === '') return null;

        $base = basename($relPath);
        $ext  = strtolower(pathinfo($base, PATHINFO_EXTENSION));

        // 1. Exact known-masquerade relative paths.
        if (!$isDir && in_array($relPath, $sig['CORE_MASQUERADE_EXACT_PATHS'], true)) {
            return 'Path masquerades as a legitimate Joomla core file, but no such file exists in a clean Joomla install — a stealthy dropper disguise.';
        }

        // 2. Hidden dot-file carrying an executable extension, anywhere.
        //    Joomla never stores runnable code in a hidden file (e.g.
        //    administrator/.../toolbar/.module.php).
        if (!$isDir && $base !== '' && $base[0] === '.' && in_array($ext, $sig['EXEC_EXTS'], true)) {
            return "Hidden dot-file with an executable extension (\"{$base}\") — legitimate Joomla code is never stored in hidden executable files.";
        }

        // 3. File placed directly (loosely) in a core directory whose full
        //    set of top-level files is known and small. Executable files by
        //    an unknown name are the classic disguise; unusual non-code
        //    extensions (e.g. a ".lock" marker) dropped there are almost
        //    always attacker toolkit artifacts too. Legitimate Joomla stub
        //    files (index.html, web.config.txt, .htaccess, ...) are allowed.
        if (!$isDir) {
            $dir = strtolower(dirname($relPath));
            if ($dir === '.') $dir = '';
            if (isset($sig['CORE_LOOSE_FILE_ALLOWLIST'][$dir])) {
                $allowed   = array_map('strtolower', $sig['CORE_LOOSE_FILE_ALLOWLIST'][$dir]);
                $stubExts  = ['html', 'htm', 'xml', 'txt', 'ini', 'json', 'md', 'dist', 'htaccess'];
                $baseLower = strtolower($base);
                if (!in_array($baseLower, $allowed, true)) {
                    if (in_array($ext, $sig['EXEC_EXTS'], true)) {
                        return "Executable file placed directly in the core \"{$dir}/\" directory, which never holds a file by this name in a clean Joomla install — a core-path disguise.";
                    }
                    if ($ext !== '' && !in_array($ext, $stubExts, true) && $baseLower !== '.htaccess') {
                        return "Unexpected file (\"{$base}\") loose in the core \"{$dir}/\" directory — clean Joomla never ships this file, a common malware toolkit artifact.";
                    }
                }
            }
        }

        return null;
    }

    /**
     * Any index.php file OUTSIDE a template's own top-level root should be
     * nothing more than Joomla's standard blank "no direct access" stub --
     * this convention holds almost universally across the ENTIRE Joomla
     * tree (components, modules, plugins, libraries, and every nested
     * template subfolder like a "features" or "layouts" directory).
     * Only a template's own root index.php (templates/<name>/index.php)
     * legitimately contains real rendering code. A non-stub index.php
     * anywhere else is a strong sign of a webshell hiding behind the
     * single most innocuous-looking filename in the whole codebase --
     * exactly the kind of file a plain executable-extension check inside
     * "code" mode directories (where .php is otherwise expected and
     * unremarkable) would never catch.
     *
     * A known-masquerade LOCATION (see TEMPLATE_FOLDER_MASQUERADE_PATTERNS)
     * is checked first and flagged unconditionally, before even looking at
     * content -- an attacker can trivially make a dropped file's content
     * look like a blank stub specifically to dodge a content-only check,
     * so a folder that shouldn't exist in any clean template at all is
     * flagged purely on where it sits, not what it contains.
     */
    public static function checkStrayIndexPhp(string $relPath, string $absPath, array $sig): ?string
    {
        $relPath = ltrim(str_replace('\\', '/', $relPath), '/');
        if (strcasecmp(basename($relPath), 'index.php') !== 0) return null;

        foreach ($sig['TEMPLATE_FOLDER_MASQUERADE_PATTERNS'] as $re) {
            if (preg_match($re, $relPath)) {
                return 'Path masquerades as a template asset folder that does not exist in a clean install of any known Joomla template — flagged regardless of file content (even a blank stub here is a known real-world compromise artifact).';
            }
        }

        if (preg_match('#^(administrator/)?templates/[^/]+/index\.php$#i', $relPath)) return null;

        $contents = @file_get_contents($absPath, false, null, 0, 4096);
        if ($contents === false) return null;
        if (self::isStandardJoomlaStub($contents)) return null;

        return 'Non-standard index.php — Joomla only ever places a blank "no direct access" stub here (outside a template\'s own root layout file); this one contains extra code, a common disguise for a webshell.';
    }

    public static function humanSize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < 3) { $bytes /= 1024; $i++; }
        return round($bytes, 1) . ' ' . $units[$i];
    }

    public static function walkDir(string $dir, callable $callback, array $skipDirNames = ['node_modules', '.git']): void
    {
        if (!is_dir($dir)) return;
        $items = @scandir($dir);
        if ($items === false) return;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if (in_array($item, $skipDirNames, true)) continue;
            $path = $dir . '/' . $item;
            $isDir = is_dir($path);
            $callback($path, $isDir);
            if ($isDir) self::walkDir($path, $callback, $skipDirNames);
        }
    }

    public static function dirSize(string $dir): int
    {
        $total = 0;
        $items = @scandir($dir);
        if (!$items) return 0;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $dir . '/' . $it;
            if (is_dir($p)) $total += self::dirSize($p);
            elseif (is_file($p)) $total += (int) @filesize($p);
        }
        return $total;
    }

    public static function deleteRecursive(string $path): bool
    {
        if (is_link($path)) return @unlink($path);
        if (is_file($path)) return @unlink($path);
        if (!is_dir($path)) return true;
        $items = @scandir($path);
        if ($items === false) return false;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if (!self::deleteRecursive($path . '/' . $item)) return false;
        }
        return @rmdir($path);
    }

    public static function isDateLikeNumericFolderName(string $name): bool
    {
        return (bool) preg_match('/^\d{1,4}$/', $name);
    }

    /**
     * True if $contents is (after stripping comments/whitespace) nothing
     * more than Joomla's standard "no direct access" guard. Joomla and
     * countless legitimate extensions place this blank stub in every
     * subfolder by convention -- an index.php existing somewhere is normal
     * and NOT a threat on its own, even inside an "upload" directory like
     * media/ or images/. Only flag a stub file if it contains more than
     * this guard.
     */
    public static function isStandardJoomlaStub(string $contents): bool
    {
        $trimmed = trim($contents);
        if ($trimmed === '') return true; // some older stubs are just blank files

        $noBlockComments = preg_replace('#/\*.*?\*/#s', '', $trimmed);
        $noLineComments  = preg_replace('#//[^\n]*#', '', $noBlockComments);
        $normalized = trim(preg_replace('/\s+/', ' ', $noLineComments));

        $guardPatterns = [
            '/<\?php\s*defined\(\s*[\'"]_JEXEC[\'"]\s*\)\s*or\s*die(\s*\(\s*[\'"]?.*?[\'"]?\s*\))?\s*;?/i',
            '/<\?php\s*\?>/i',
            '/<\?php/i',
            '/\?>/',
        ];
        $stripped = $normalized;
        foreach ($guardPatterns as $p) {
            $stripped = preg_replace($p, '', $stripped);
        }
        $stripped = trim($stripped);

        // After removing the guard, comments, and PHP tags, almost nothing
        // should remain. Allow a small margin (e.g. a trailing "exit;").
        return strlen($stripped) <= 12;
    }

    /**
     * Joomla's real root index.php never executes anything before defining
     * _JEXEC. Any code before that point is a strong sign of a prepended
     * payload -- the exact `$db = array(122,105,...); require zip://...`
     * pattern seen in real Joomla compromises.
     */
    public static function checkCoreIndexIntegrity(string $contents): ?string
    {
        $openTagPos = stripos($contents, '<?php');
        if ($openTagPos === false) return null;

        $bootstrapPattern = '/(?:\\\\?\bdefine\s*\(\s*[\'"]_JEXEC[\'"]\s*,\s*1\s*\)|\bconst\s+_JEXEC\s*=\s*1)\s*;/i';
        if (!preg_match($bootstrapPattern, $contents, $m, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $prefix = substr($contents, $openTagPos + 5, $m[0][1] - ($openTagPos + 5));

        $suspiciousPatterns = [
            'stream-wrapper reference (zip://, phar://, etc.)' => '/(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//i',
            'numeric byte-array (chr() decode obfuscation)'    => '/array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)/i',
            'eval()'                                            => '/\beval\s*\(/i',
            'base64_decode()'                                   => '/base64_decode\s*\(/i',
            'assert()'                                           => '/\bassert\s*\(/i',
            'shell/process execution function'                  => '/\b(system|exec|shell_exec|passthru|proc_open)\s*\(/i',
        ];

        foreach ($suspiciousPatterns as $label => $re) {
            if (preg_match($re, $prefix)) {
                $preview = trim(preg_replace('/\s+/', ' ', $prefix));
                $preview = strlen($preview) > 160 ? substr($preview, 0, 160) . '…' : $preview;
                return "Core entry-point file contains suspicious code before the Joomla bootstrap (_JEXEC) — {$label} detected. Offending code: {$preview}";
            }
        }
        return null;
    }

    public static function checkHeadTagInjection(string $contents): ?string
    {
        if (stripos($contents, '<head') === false) return null;

        $patterns = [
            '/<head[^>]*>\s*(?:<[^>]*>)*?\s*<script[^>]*>(?:.*?(?:base64|atob|eval|String\.fromCharCode|document\.write).*?)<\/script/is',
            '/<head[^>]*>\s*<script[^>]*>(?:[\s\S]{200,}?)<\/script/is',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $contents, $matches)) {
                $preview = trim(preg_replace('/\s+/', ' ', $matches[0]));
                $preview = strlen($preview) > 200 ? substr($preview, 0, 200) . '…' : $preview;
                return "Suspicious obfuscated script injected right after <head> tag. Preview: {$preview}";
            }
        }
        return null;
    }

    /**
     * Verifies a file claiming to be an image (by extension) actually
     * contains real image data. getimagesize() is the ground truth here --
     * it sniffs the real format from content and is deliberately used
     * INSTEAD of a strict per-extension magic-byte match, because a real
     * image saved or served under a mismatched extension is common and
     * harmless (image-optimizer plugins/CDNs frequently rewrite JPGs to
     * WebP data while keeping the original .jpg filename for compatibility;
     * a tiny thumbnail can also legitimately have a minimal/nonstandard
     * header). Flagging on extension-vs-magic-byte mismatch alone produced
     * false positives on ordinary resized thumbnails -- so a successful
     * getimagesize() decode of ANY image format is accepted as proof this
     * is a real image, regardless of extension.
     *
     * Only once getimagesize() fails outright do we fall back to checking
     * magic bytes (again, against any known image format, not just the
     * extension's) to distinguish "not image data at all" (a webshell
     * simply renamed with an image extension -- high confidence) from
     * "looks like it starts as an image but the body won't decode"
     * (corrupted/truncated file, or a polyglot with data appended after
     * genuine image bytes -- lower confidence, worth a manual look).
     */
    public static function checkImageIntegrity(string $path, string $ext, string $contents): ?string
    {
        $checkedExts = ['png', 'jpg', 'jpeg', 'gif', 'webp'];
        if (!in_array($ext, $checkedExts, true)) return null;
        if ($contents === '') return null;

        if (@getimagesize($path) !== false) {
            return null;
        }

        $anyImageMagic = [
            "\x89PNG\r\n\x1a\n", "\xFF\xD8\xFF", "GIF87a", "GIF89a", "RIFF", "BM", "II*\x00", "MM\x00*",
        ];
        $looksLikeAnyImage = false;
        foreach ($anyImageMagic as $magic) {
            if (strncmp($contents, $magic, strlen($magic)) === 0) { $looksLikeAnyImage = true; break; }
        }

        if (!$looksLikeAnyImage) {
            return "File has a .$ext extension but its content does not match any known image file signature and fails to decode as an image — a strong sign of a webshell simply renamed/disguised with an image extension.";
        }

        return "File starts with a recognizable image header but the image data fails to fully decode — could be a corrupted/truncated file; worth a manual look if unexpected.";
    }

    /**
     * Builds a short, human-readable preview of a regex match plus a
     * little surrounding context, so a flagged finding shows exactly what
     * triggered it in the actual file instead of just a bare signature
     * name -- lets a human quickly judge for themselves whether it's a
     * real threat or a false positive, without opening the file.
     */
    private static function previewMatch(string $text, array $match, int $context = 30, int $maxLen = 180): string
    {
        $matchedText = $match[0][0] ?? '';
        $offset      = $match[0][1] ?? 0;
        $start       = max(0, $offset - $context);
        $length      = ($offset - $start) + strlen($matchedText) + $context;
        $snippet     = substr($text, $start, $length);
        $snippet     = trim(preg_replace('/\s+/', ' ', $snippet));
        return strlen($snippet) > $maxLen ? substr($snippet, 0, $maxLen) . '…' : $snippet;
    }

    /** Runs content-signature + polyglot checks. Used in both scan modes. */
    public static function scanFileContent(string $path, string $ext, array $sig, int $maxSize, array &$reasons): bool
    {
        if (!is_file($path) || @filesize($path) === false || @filesize($path) > $maxSize) return false;
        $textLikeExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pht', 'js', 'html', 'htm', 'txt', 'css', 'xml', 'gif', 'png', 'jpg', 'jpeg'];
        if (!in_array($ext, $textLikeExts, true) && $ext !== '') return false;
        $contents = @file_get_contents($path);
        if ($contents === false || $contents === '') return false;

        $flagged = false;

        // A legitimate image (especially a phone photo) can be several MB
        // of mostly-compressed, high-entropy pixel data. Scanning that
        // whole blob against short text signatures produces false
        // positives purely from random byte collisions -- the risk grows
        // with file size, which is exactly why large photos were getting
        // flagged. Real polyglot payloads are always prepended or appended
        // to the valid image bytes, never buried mid-stream inside them,
        // so signature scanning on image extensions is restricted to a
        // head+tail window instead of the full file. Actual code files
        // (php/js/html/...) are unaffected and still scanned in full.
        $isImageExt = in_array($ext, $sig['NON_PHP_EXTS_THAT_MUST_STAY_CLEAN'], true);
        $scanText = $isImageExt
            ? substr($contents, 0, 4096) . "\n" . substr($contents, -8192)
            : $contents;

        // Each signature carries its own severity + a plain-language "why"
        // (see getSignatures()). A high-severity match is unambiguous
        // enough on its own to mark the whole file High confidence; a
        // medium one names something that has a plausible benign
        // explanation and is surfaced for human review instead of an
        // automatic verdict. Either way the actual matched code is quoted
        // so the reason is verifiable, not just a signature label.
        foreach ($sig['CONTENT_SIGNATURES'] as $sigName => $def) {
            if (preg_match($def['re'], $scanText, $m, PREG_OFFSET_CAPTURE)) {
                $flagged = true;
                $preview = self::previewMatch($scanText, $m);
                $tag = $def['severity'] === 'high' ? 'high-confidence exploit pattern' : 'needs manual review';
                $reasons[] = "Content signature: {$sigName} ({$tag}) — {$def['why']} Matched code: {$preview}";
            }
        }
        if ($isImageExt && preg_match($sig['PHP_OPEN_TAG_RE'], $scanText, $m, PREG_OFFSET_CAPTURE)) {
            $flagged = true;
            $preview = self::previewMatch($scanText, $m);
            $reasons[] = "Content signature: php_tag_in_image_file (polyglot shell disguised with an image extension) — Matched code: {$preview}";
        }

        $imageIssue = self::checkImageIntegrity($path, $ext, $contents);
        if ($imageIssue !== null) { $flagged = true; $reasons[] = $imageIssue; }

        $headIssue = self::checkHeadTagInjection($contents);
        if ($headIssue !== null) { $flagged = true; $reasons[] = $headIssue; }

        return $flagged;
    }

    /**
     * @param string|array $reasons Either the already-joined display string
     *                              (legacy callers) or the raw list of
     *                              individual reason strings -- passing the
     *                              raw list also preserves each one
     *                              separately in 'reasons' for the
     *                              per-finding code-analysis modal in the UI.
     */
    public static function recordFinding(array &$arr, string $absPath, string $root, $reasons, bool $isDir = false): void
    {
        $reasonsList = is_array($reasons) ? array_values(array_unique($reasons)) : [(string) $reasons];
        $reasonText  = implode(' | ', $reasonsList);

        $rel = ltrim(str_replace($root, '', $absPath), '/');
        $size = $isDir ? self::dirSize($absPath) : (is_file($absPath) ? (int) @filesize($absPath) : 0);
        $highSignals = [
            'high-confidence exploit pattern', 'icon-font', 'malicious pattern', 'unrecognized', 'numeric',
            'non-standard index.php', 'core entry-point', 'stream-wrapper', 'backup/duplicate', 'bootstrap',
            'masquerade', 'disguise', 'polyglot',
        ];
        $confidence = 'medium';
        foreach ($highSignals as $sigName) {
            if (stripos($reasonText, $sigName) !== false) { $confidence = 'high'; break; }
        }
        $arr[$rel] = [
            'rel' => $rel, 'abs' => $absPath, 'reason' => $reasonText, 'reasons' => $reasonsList,
            'type' => $isDir ? 'dir' : 'file', 'confidence' => $confidence,
            'size' => $size, 'mtime' => (int) @filemtime($absPath),
        ];
    }

    /**
     * Splits a reason string into a lead sentence + an optional code
     * snippet (the "Matched code:" / "Offending code:" / "Preview:"
     * suffix that several checks append), and renders both as safe,
     * pre-escaped HTML for the code-analysis modal. Kept server-side so
     * the client never has to parse free text -- it just injects
     * ready-made HTML.
     */
    public static function formatReasonForDisplay(string $reason): string
    {
        if (preg_match('/^(.*?)(Matched code:|Offending code:|Preview:)\s*(.*)$/s', $reason, $m)) {
            $lead  = trim($m[1]);
            $label = trim($m[2], ': ');
            $code  = trim($m[3]);
            return '<div class="sppb-reason-block"><p>' . htmlspecialchars($lead) . '</p>'
                 . '<div class="sppb-reason-code-label">' . htmlspecialchars($label) . '</div>'
                 . '<pre class="sppb-reason-code">' . htmlspecialchars($code) . '</pre></div>';
        }
        return '<div class="sppb-reason-block"><p>' . htmlspecialchars($reason) . '</p></div>';
    }

    /** A short, single-line summary for the table row (full detail lives in the modal). */
    public static function shortReasonLabel(array $reasonsList): string
    {
        if (empty($reasonsList)) return '';
        $first = preg_replace('/\s*(Matched code:|Offending code:|Preview:).*$/s', '', $reasonsList[0]);
        $first = trim($first);
        if (strlen($first) > 90) $first = substr($first, 0, 90) . '…';
        $extra = count($reasonsList) - 1;
        return $extra > 0 ? "{$first} (+{$extra} more)" : $first;
    }

    /**
     * Surgically strips known XSS injection markers out of a Joomla menu
     * "params" JSON blob, preserving every other legitimate setting.
     *
     * Handles two shapes of nested value:
     *  1. A string that itself decodes as valid JSON (Helix Ultimate stores
     *     layout data as JSON-encoded strings, sometimes nested several
     *     levels deep) -- these are recursed into normally.
     *  2. A string that LOOKS like it was meant to be a JSON container
     *     (starts with '{' or '[') but FAILS to json_decode -- this happens
     *     when the attacker's own injected payload contains an unescaped
     *     quote that breaks JSON syntax. This is handled by
     *     regexStripMalformed(), which now ALSO applies a fail-safe:
     *     after targeted removal, if any signature still matches (or the
     *     tell-tale "(function(){'use strict'" scaffold survives), the
     *     entire value is blanked rather than left as a hollowed-out but
     *     still-present script skeleton.
     *
     * item_id is enforced as a plain integer unconditionally when reached
     * as a proper leaf (not gated behind pattern matching).
     */
    public static function cleanMenuParamsXss(string $paramsJson, array $patterns): array
    {
        $decoded = json_decode($paramsJson, true);
        if ($decoded === null && trim($paramsJson) !== 'null') {
            return ['cleaned' => $paramsJson, 'changed' => false];
        }
        $changed = false;

        $sanitizeLeaf = function (string $key, string $value) use ($patterns, &$changed): string {
            if (strcasecmp($key, 'item_id') === 0) {
                if (preg_match('/^\d+$/', trim($value))) return $value;
                $changed = true;
                return '';
            }

            $hit = false;
            foreach ($patterns as $re) { if (preg_match($re, $value)) { $hit = true; break; } }
            if (!$hit) return $value;
            $changed = true;

            $clean = $value;
            $clean = preg_replace('/<script\b[^>]*>.*?<\/script\s*>/is', '', $clean);
            $clean = preg_replace('/<img\b[^>]*>/is', '', $clean);
            $clean = preg_replace('/\bon[a-z]+\s*=\s*(".*?"|\'.*?\'|[^\s>]+)/is', '', $clean);
            $clean = preg_replace('/javascript\s*:/i', '', $clean);
            $clean = preg_replace('/localStorage\s*\.\s*(setItem|getItem)\s*\([^)]*\)/i', '', $clean);
            $clean = preg_replace('/sessionStorage\s*\.\s*(setItem|getItem)\s*\([^)]*\)/i', '', $clean);
            $clean = preg_replace('/MutationObserver/i', '', $clean);
            $clean = preg_replace('/xss\.report[^\s\'"<>]*/i', '', $clean);
            $clean = preg_replace('/_hu_?inject[^\s\'"<>]*/i', '', $clean);
            $clean = preg_replace('/document\s*\.\s*createElement\s*\(\s*[\'"]script[\'"]\s*\)/i', '', $clean);

            foreach ($patterns as $re) {
                if (preg_match($re, $clean)) return '';
            }
            if (preg_match('/\(\s*function\s*\(\s*\)\s*\{/i', $clean)) {
                return '';
            }
            return $clean;
        };

        // For strings that look like a JSON container but fail to parse --
        // regex-strip the malicious content directly instead of discarding
        // the whole field, with a fail-safe blank-out if residue survives.
        $regexStripMalformed = function (string $raw) use ($patterns, &$changed): string {
            $hit = false;
            foreach ($patterns as $re) { if (preg_match($re, $raw)) { $hit = true; break; } }
            if (!$hit) return $raw;
            $changed = true;

            // Blank any item_id value outright -- these should only ever
            // hold a plain numeric module/item ID, never markup or script.
            $raw = preg_replace('/"item_id"\s*:\s*"(?:[^"\\\\]|\\\\.)*"/is', '"item_id":""', $raw);

            // Targeted removal pass.
            $raw = preg_replace('/<script\b[^>]*>.*?<\/script\s*>/is', '', $raw);
            $raw = preg_replace('/<img\b[^>]*>/is', '', $raw);
            $raw = preg_replace('/\bon[a-z]+\s*=\s*(".*?"|\'.*?\'|[^\s>]+|`[^`]*`)/is', '', $raw);
            $raw = preg_replace('/javascript\s*:/i', '', $raw);
            $raw = preg_replace('/localStorage\s*\.\s*(setItem|getItem)\s*\([^)]*\)/i', '', $raw);
            $raw = preg_replace('/sessionStorage\s*\.\s*(setItem|getItem)\s*\([^)]*\)/i', '', $raw);
            $raw = preg_replace('/MutationObserver/i', '', $raw);
            $raw = preg_replace('/xss\.report[^\s\'"<>`]*/i', '', $raw);
            $raw = preg_replace('/_hu_?inject[^\s\'"<>`]*/i', '', $raw);
            $raw = preg_replace('/document\s*\.\s*createElement\s*\(\s*[\'"]script[\'"]\s*\)/i', '', $raw);

            // Fail-safe: targeted removal only deletes the specific tokens
            // matched above, but attacker payloads come in endless variants
            // (different function/variable names, different wrapper shape).
            // If ANY signature still matches after the targeted pass -- or
            // the tell-tale "(function(){'use strict'" scaffold is still
            // present -- the remaining text is unresolved malicious residue,
            // not a false positive. Blank the whole value rather than ship
            // a hollowed-out-but-still-present script skeleton.
            $stillDangerous = false;
            foreach ($patterns as $re) {
                if (preg_match($re, $raw)) { $stillDangerous = true; break; }
            }
            if (!$stillDangerous && preg_match('/\(\s*function\s*\(\s*\)\s*\{/i', $raw)) {
                $stillDangerous = true;
            }
            if ($stillDangerous) {
                return '';
            }

            return $raw;
        };

        $walk = function (&$node, $key = '') use (&$walk, &$sanitizeLeaf, &$regexStripMalformed) {
            if (is_array($node)) {
                foreach ($node as $k => &$v) { $walk($v, is_string($k) ? $k : $key); }
                unset($v);
                return;
            }
            if (!is_string($node)) return;

            $inner = json_decode($node, true);
            if (is_array($inner)) {
                $walk($inner, $key);
                $node = json_encode($inner, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                return;
            }

            $trimmed = ltrim($node);
            if ($trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[')) {
                // Looks like it was meant to be a JSON container but the
                // attacker's own malformed escaping broke it. Regex-strip
                // instead of nuking the whole field.
                $node = $regexStripMalformed($node);
                return;
            }

            $node = $sanitizeLeaf($key, $node);
        };

        $walk($decoded);

        if (!$changed) return ['cleaned' => $paramsJson, 'changed' => false];
        return ['cleaned' => json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'changed' => true];
    }
}
<?php
/**
 * @package     com_muruguard
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

class MuruguardHelper
{
    /**
     * Ensures the request is from a logged-in backend user with manage rights.
     * Call from entry point, controllers, views, and destructive model methods.
     * This is the BASE gate every task requires; see requireDeleteAccess() /
     * requireEditAccess() / requireAdminAccess() below for the finer-grained
     * checks layered on top of it for specific destructive or configuration-
     * changing tasks -- a user group can have core.manage alone to view scan
     * results without being able to act on them.
     */
    public static function requireManageAccess(): void
    {
        $user = Factory::getApplication()->getIdentity();

        if ($user->guest || (int) $user->id <= 0) {
            throw new \Joomla\CMS\Exception\NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }

        if (!$user->authorise('core.manage', 'com_muruguard')) {
            throw new \Joomla\CMS\Exception\NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }
    }

    /** Required for destructive actions: deleting flagged files/folders, deleting rogue asset rows. */
    public static function requireDeleteAccess(): void
    {
        self::requirePermission('core.delete');
    }

    /** Required for in-place modification: Clean code, Clean menu XSS. */
    public static function requireEditAccess(): void
    {
        self::requirePermission('core.edit');
    }

    /** Required for changing component configuration: the Settings panel (scheduled scanning). */
    public static function requireAdminAccess(): void
    {
        self::requirePermission('core.admin');
    }

    private static function requirePermission(string $action): void
    {
        self::requireManageAccess();

        $user = Factory::getApplication()->getIdentity();
        if (!$user->authorise($action, 'com_muruguard')) {
            throw new \Joomla\CMS\Exception\NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
        }
    }

    /**
     * Non-throwing permission checks, for the view to decide whether to
     * show/enable an action button at all -- offering a button that will
     * just 403 on click is bad UX, so the template hides or disables it
     * up front based on these.
     */
    public static function canDelete(): bool
    {
        return self::can('core.delete');
    }

    public static function canEdit(): bool
    {
        return self::can('core.edit');
    }

    public static function canAdmin(): bool
    {
        return self::can('core.admin');
    }

    private static function can(string $action): bool
    {
        $user = Factory::getApplication()->getIdentity();
        return !$user->guest && (int) $user->id > 0 && (bool) $user->authorise($action, 'com_muruguard');
    }

    /** Central place for every pattern list used across the scan. */
    public static function getSignatures(): array
    {
        return [
            'EXEC_EXTS' => ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pht', 'shtml'],

            // Hidden dot-files with a well-known, ubiquitous benign
            // purpose -- shipped by countless legitimate composer/vendor
            // packages, not something an attacker planted. Exempted from
            // the "hidden dot-file with an executable extension" check.
            // Grow this list if another legitimate one turns up.
            'HIDDEN_DOTFILE_ALLOWLIST' => [
                '.phpstorm.meta.php',
            ],

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

            // Checked against a LIVE incoming request (GET/POST/URI/User-Agent)
            // by the companion plg_system_muruguardshield plugin, not by the
            // component's own file-content scan. 'block_eligible' marks the
            // ones confident enough to actively reject with a 403 when the
            // admin has opted into blocking (not just logging) -- every
            // other severity level is log-only regardless of that setting,
            // since a false positive here rejects a real visitor's request
            // rather than just flagging a file for human review.
            'REQUEST_SIGNATURES' => [
                'webshell_param_exec' => ['re' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|assert|create_function)\s*\(/i',
                    'severity' => 'high', 'block_eligible' => true,
                    'why' => 'A request parameter value itself contains a PHP code-execution function call -- the classic way an attacker interacts with an already-planted one-line eval/assert webshell, sending the actual command as the payload rather than in the file.'],
                'webshell_param_eval_b64' => ['re' => '/eval\s*\(\s*(?:@)?base64_decode\s*\(/i',
                    'severity' => 'high', 'block_eligible' => true,
                    'why' => 'A request parameter contains eval(base64_decode(...)) -- the exact payload shape used to run obfuscated PHP through a planted webshell.'],
                'sppb_upload_custom_icon' => ['re' => '/task\s*=\s*[\'"]?[^&\'"]*uploadcustomicon/i',
                    'severity' => 'high', 'block_eligible' => true,
                    'why' => 'Directly targets the SP Page Builder uploadCustomIcon task -- the exact unauthenticated RCE this whole tool exists to catch the aftermath of. A live probe against it is worth blocking outright, not just logging.'],
                'known_dropped_filename' => ['re' => '/^\/?.*(?:codex-sppb-[a-f0-9]+|codex_sppb\w*|queue_\d+)\.php(?:[?\/]|$)/i',
                    'severity' => 'high', 'block_eligible' => true,
                    'why' => 'The request path matches a known malware-drop filename pattern from this campaign -- either an attacker probing for a shell that was never dropped, or someone actively using one that was.'],
                'path_traversal_probe' => ['re' => '/(?:\.\.[\/\\\\]){2,}|\/etc\/passwd|wp-config\.php|configuration\.php~/i',
                    'severity' => 'medium', 'block_eligible' => false,
                    'why' => 'Directory-traversal sequences or a direct probe for a well-known sensitive file -- common reconnaissance, but broad enough (some legitimate frameworks use relative paths with ../ in query strings) that it is logged for review rather than blocked automatically.'],
                'known_scanner_user_agent' => ['re' => '/sqlmap|nikto|acunetix|nessus|masscan|zgrab|nuclei|dirbuster|wpscan/i',
                    'severity' => 'medium', 'block_eligible' => false,
                    'why' => 'The User-Agent string identifies a known vulnerability-scanning tool. Often a hostile scan, but also how a site owner\'s own authorised security testing shows up -- logged for review, not auto-blocked.'],
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

            // Matches the "template" column of a mass-injected batch of junk
            // #__template_styles rows seen in real SPPB-compromise cleanups:
            // dozens of rows named tmpl_<6 random lowercase letters>, title
            // "<name> - 默认" ("- Default" in Chinese, regardless of the
            // site's actual language), params usually just "{}". This alone
            // is a secondary signal (a real template happening to be named
            // this way is vanishingly unlikely but not impossible) --
            // scanDatabase() treats it as confirmatory alongside the
            // stronger, independent signal of the row's "template" column
            // not matching any template folder that actually exists on disk.
            'TEMPLATE_STYLE_JUNK_NAME_RE' => '/^tmpl_[a-z0-9]{4,12}$/i',

            // Joomla's own bundled fallback template -- present on both the
            // site and admin side in every stock install (offline.php,
            // error.php, fatal.php, ...), used for maintenance/error pages.
            // It's core Joomla, never installed via the extension
            // installer, so it legitimately has no templateDetails.xml --
            // exempt from the no-manifest junk-folder check below.
            'TEMPLATE_SYSTEM_FOLDER_NAMES' => ['system'],

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
                '/administrator/components/com_muruguard/',
                // com_sppbscan is this same extension's own pre-2.2.0 name
                // (see CHANGELOG.md "Rebrand SPPB Scan to MuRu Guard") -- a
                // leftover copy from before that rebrand is legitimate old
                // code, not a compromise. Without this, it self-flags: this
                // scanner's own CONTENT_SIGNATURES table necessarily
                // contains the literal marker text/regex source it's
                // matching against (e.g. "xss.report", "secure.local",
                // "FilesMan"), so a raw content scan of its own source
                // finds "matches" against itself. The current-named copy
                // only escapes this by coincidence, via the entry right
                // above skipping content scanning for its own live path.
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

            // Genuinely required core/template entry files -- even when
            // infected (a "prepended payload" ahead of the bootstrap/
            // access guard), the fix is to CLEAN the injected code, never
            // to delete the file outright, since the site (or the active
            // template) cannot function without it. Matched exactly for
            // the fixed entry points; matched by pattern for any
            // template's own root index.php since the template name
            // varies per site. Also covers the other files the bundled
            // core-checksum manifest verifies (see
            // getCoreChecksumManifest()) -- a checksum mismatch on any of
            // these needs manual review/restore, never a one-click delete.
            'PROTECTED_ENTRY_FILES' => [
                'index.php', 'administrator/index.php', 'api/index.php', 'includes/app.php',
                'includes/framework.php', 'robots.txt.dist', 'htaccess.txt', 'web.config.txt',
            ],
            'PROTECTED_ENTRY_FILE_PATTERNS' => [
                '#^(administrator/)?templates/[^/]+/index\.php$#i',
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
                // web.config is Joomla's IIS-hosting counterpart to
                // .htaccess and is shipped loose in several core
                // directories, not just the webroot -- allowed everywhere
                // this list applies.
                'libraries' => [
                    'bootstrap.php', 'loader.php', 'classmap.php', 'namespacemap.php',
                    'import.php', 'import.legacy.php', 'platform.php', 'fof30.autoload.php',
                    'cms.php', 'web.config',
                ],
                'cli' => [
                    'joomla.php', 'import.php', 'update_cron.php', 'deletefiles.php', 'garbagecron.php',
                    'web.config',
                ],
                'bin' => ['web.config'],
                // templates/system is Joomla's built-in system/error template.
                // Its top-level loose files are a small, fixed set; anything
                // else there (network.php, online.php, ...) is a disguise.
                'templates/system' => [
                    'index.php', 'error.php', 'error.full.php', 'fatal.php', 'offline.php', 'component.php', 'web.config',
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
    /**
     * Keyed by a stable, never-translated group id (used for icon lookups
     * and other by-key logic in the view) rather than the display label
     * itself, so the label can be translated without breaking anything
     * that depends on the key.
     */
    public static function getScanAreas(): array
    {
        return [
            'upload_media' => [
                'label' => Text::_('COM_MURUGUARD_GROUP_UPLOAD_MEDIA'),
                'areas' => [
                    'media'  => 'media/',
                    'images' => 'images/',
                    'tmp'    => 'tmp/',
                    'cache'  => 'cache/',
                    'files'  => 'files/',
                ],
            ],
            'extension_code' => [
                'label' => Text::_('COM_MURUGUARD_GROUP_EXTENSION_CODE'),
                'areas' => [
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
            ],
            'core_webroot' => [
                'label' => Text::_('COM_MURUGUARD_GROUP_CORE_WEBROOT'),
                'areas' => [
                    'core_entry' => Text::_('COM_MURUGUARD_AREA_CORE_ENTRY'),
                    'webroot'    => Text::_('COM_MURUGUARD_AREA_WEBROOT'),
                ],
            ],
            'database' => [
                'label' => Text::_('COM_MURUGUARD_GROUP_DATABASE'),
                'areas' => [
                    'database' => Text::_('COM_MURUGUARD_AREA_DATABASE'),
                ],
            ],
        ];
    }

    /**
     * Checks a LIVE incoming request against REQUEST_SIGNATURES. Called by
     * the companion plg_system_muruguardshield plugin on every page load
     * -- NOT by the component's own file-content scan, which never sees
     * request data at all. Everything (URI, every GET/POST value) is
     * flattened into one combined haystack and checked against every
     * signature except the User-Agent one, which checks that header
     * specifically. Returns the highest-severity match found, or null.
     */
    public static function scanRequestForAttack(array $get, array $post, string $uri, string $userAgent): ?array
    {
        $sig = self::getSignatures();

        $flatten = static function (array $arr) use (&$flatten): array {
            $out = [];
            foreach ($arr as $v) {
                $out = is_array($v) ? array_merge($out, $flatten($v)) : array_merge($out, [(string) $v]);
            }
            return $out;
        };
        $parts = array_filter(array_merge([$uri], $flatten($get), $flatten($post)), fn($p) => $p !== '');
        $combined = implode(' ', $parts);

        $best = null;
        foreach ($sig['REQUEST_SIGNATURES'] as $name => $def) {
            $haystack = $name === 'known_scanner_user_agent' ? $userAgent : $combined;
            if ($haystack === '' || !preg_match($def['re'], $haystack, $m)) continue;

            $candidate = [
                'rule'           => $name,
                'severity'       => $def['severity'],
                'block_eligible' => $def['block_eligible'],
                'why'            => $def['why'],
                'matched_text'   => mb_substr((string) $m[0], 0, 120),
            ];
            if ($best === null || ($candidate['severity'] === 'high' && $best['severity'] !== 'high')) {
                $best = $candidate;
            }
        }
        return $best;
    }

    /**
     * Deliberately the same JSON-file-under-this-component's-own-data-
     * folder pattern as scan-history.json (see MuruguardModelScanner::
     * scanHistoryFilePath() for the full reasoning) -- and here it also
     * doubles as the one thing both this component AND the separate
     * shield plugin can agree on without any cross-extension API: the
     * plugin just writes here directly using the same JPATH_ADMINISTRATOR
     * constant every Joomla extension has, no coupling beyond this path.
     * flock() is used on writes (unlike scan-history.json) because this
     * file can plausibly receive concurrent writes from simultaneous
     * requests during an actual attack burst, exactly when losing entries
     * matters most.
     */
    private static function attackLogFilePath(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/attack-log.json';
    }

    /** Newest first, capped at 500 entries so the file stays small and fast to read regardless of traffic volume. */
    public static function recordAttackLogEntry(array $entry): void
    {
        $path = self::attackLogFilePath();
        $fh = @fopen($path, 'c+');
        if ($fh === false) return;

        if (@flock($fh, LOCK_EX)) {
            $size = filesize($path) ?: 0;
            $contents = $size > 0 ? fread($fh, $size) : '';
            $log = json_decode((string) $contents, true);
            if (!is_array($log)) $log = [];

            array_unshift($log, $entry);
            $log = array_slice($log, 0, 500);

            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($log));
            fflush($fh);
            flock($fh, LOCK_UN);
        }
        fclose($fh);
    }

    public static function getAttackLog(): array
    {
        $path = self::attackLogFilePath();
        if (!is_file($path)) return [];
        $contents = @file_get_contents($path);
        if ($contents === false) return [];
        $decoded = json_decode($contents, true);
        return is_array($decoded) ? $decoded : [];
    }

    public static function clearAttackLog(): void
    {
        @file_put_contents(self::attackLogFilePath(), json_encode([]));
    }

    private static function loginAttemptsFilePath(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/login-attempts.json';
    }

    /**
     * Records one failed backend login attempt for brute-force tracking.
     * Entries older than 24h are pruned on every write so this file can
     * never grow unbounded even under a sustained attack -- a rolling
     * window is all isBruteForceThresholdExceeded() ever needs anyway.
     */
    public static function recordLoginFailure(string $ip, string $username): void
    {
        $path = self::loginAttemptsFilePath();
        $fh = @fopen($path, 'c+');
        if ($fh === false) return;

        if (@flock($fh, LOCK_EX)) {
            $size = filesize($path) ?: 0;
            $contents = $size > 0 ? fread($fh, $size) : '';
            $attempts = json_decode((string) $contents, true);
            if (!is_array($attempts)) $attempts = [];

            $cutoff = time() - 86400;
            $attempts = array_values(array_filter($attempts, fn($a) => ($a['time'] ?? 0) >= $cutoff));
            $attempts[] = ['ip' => $ip, 'username' => $username, 'time' => time()];

            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($attempts));
            fflush($fh);
            flock($fh, LOCK_UN);
        }
        fclose($fh);
    }

    public static function getLoginAttempts(): array
    {
        $path = self::loginAttemptsFilePath();
        if (!is_file($path)) return [];
        $contents = @file_get_contents($path);
        if ($contents === false) return [];
        $decoded = json_decode($contents, true);
        return is_array($decoded) ? $decoded : [];
    }

    /** True if $ip has failed $threshold or more times within the last $windowMinutes. */
    public static function isBruteForceThresholdExceeded(string $ip, int $threshold, int $windowMinutes): bool
    {
        if ($threshold <= 0) return false;
        $cutoff = time() - ($windowMinutes * 60);
        $count = 0;
        foreach (self::getLoginAttempts() as $a) {
            if (($a['ip'] ?? '') === $ip && ($a['time'] ?? 0) >= $cutoff) {
                $count++;
                if ($count >= $threshold) return true;
            }
        }
        return false;
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
    /**
     * Short, collapsed preview of a file's own content, used to append a
     * "Matched code:" snippet onto location-based reasons (masquerade
     * paths, stray index.php, ...) that don't otherwise quote any code --
     * without this, the code-analysis modal has nothing to show for these
     * checks even though the file's actual content is exactly what a
     * reviewer needs to see to judge the finding.
     */
    private static function filePreview(string $absPath, int $maxLen = 220): string
    {
        if ($absPath === '' || !is_file($absPath)) return '';
        $chunk = @file_get_contents($absPath, false, null, 0, 4096);
        if ($chunk === false || trim($chunk) === '') return '';
        $preview = trim(preg_replace('/\s+/', ' ', $chunk));
        return strlen($preview) > $maxLen ? substr($preview, 0, $maxLen) . '…' : $preview;
    }

    public static function checkCoreMasquerade(string $relPath, bool $isDir, array $sig, string $absPath = ''): ?string
    {
        $relPath = ltrim(str_replace('\\', '/', $relPath), '/');
        if ($relPath === '') return null;

        $base = basename($relPath);
        $ext  = strtolower(pathinfo($base, PATHINFO_EXTENSION));
        $preview = $isDir ? '' : self::filePreview($absPath);
        $suffix  = $preview !== '' ? " Matched code: {$preview}" : '';

        // 1. Exact known-masquerade relative paths.
        if (!$isDir && in_array($relPath, $sig['CORE_MASQUERADE_EXACT_PATHS'], true)) {
            return 'Path masquerades as a legitimate Joomla core file, but no such file exists in a clean Joomla install — a stealthy dropper disguise.' . $suffix;
        }

        // 2. Hidden dot-file carrying an executable extension, anywhere.
        //    Joomla never stores runnable code in a hidden file (e.g.
        //    administrator/.../toolbar/.module.php) -- except a small,
        //    known set of IDE/tooling metadata files that legitimate
        //    composer packages ship this way by convention (e.g.
        //    PhpStorm's .phpstorm.meta.php), which are exempted.
        if (!$isDir && $base !== '' && $base[0] === '.' && in_array($ext, $sig['EXEC_EXTS'], true)
            && !in_array(strtolower($base), array_map('strtolower', $sig['HIDDEN_DOTFILE_ALLOWLIST']), true)) {
            return "Hidden dot-file with an executable extension (\"{$base}\") — legitimate Joomla code is never stored in hidden executable files." . $suffix;
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
                        return "Executable file placed directly in the core \"{$dir}/\" directory, which never holds a file by this name in a clean Joomla install — a core-path disguise." . $suffix;
                    }
                    if ($ext !== '' && !in_array($ext, $stubExts, true) && $baseLower !== '.htaccess') {
                        return "Unexpected file (\"{$base}\") loose in the core \"{$dir}/\" directory — clean Joomla never ships this file, a common malware toolkit artifact." . $suffix;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Flags anything sitting inside a top-level templates/<name> or
     * administrator/templates/<name> folder whose <name> matches the same
     * auto-generated "tmpl_xxxxxx" junk-naming pattern checked against
     * #__template_styles rows in scanDatabase() (see
     * TEMPLATE_STYLE_JUNK_NAME_RE) -- a confirmed, real mass-injection
     * pattern: dozens of these folders dropped at once, each holding a
     * handful of PHP files given plausible-sounding-but-fake framework
     * names (handler.php, loader.php, registry.php, session.php, ...) to
     * blend in, paired with a matching junk row in the database. Unlike
     * scanFileContent()'s signature checks, this doesn't depend on
     * recognizing the payload's code at all -- it flags purely on the
     * folder naming, so it still catches the drop even if the file
     * contents don't match any known webshell signature. Applies to the
     * folder itself and everything inside it, at any depth, regardless of
     * scan mode.
     */
    /** Per-request cache for the templateDetails.xml check below, keyed by template folder absolute path -- avoids re-stat()ing the same folder once per file inside it. */
    private static array $templateManifestCache = [];

    public static function checkJunkTemplateFolder(string $relPath, array $sig, ?string $absPath = null): ?string
    {
        $relPath = ltrim(str_replace('\\', '/', $relPath), '/');
        $parts = explode('/', $relPath);

        if (($parts[0] ?? '') === 'templates') {
            $topFolder = $parts[1] ?? '';
            $depthAfterTop = count($parts) - 2;
        } elseif (($parts[0] ?? '') === 'administrator' && ($parts[1] ?? '') === 'templates') {
            $topFolder = $parts[2] ?? '';
            $depthAfterTop = count($parts) - 3;
        } else {
            return null;
        }

        if ($topFolder === '') {
            return null;
        }

        // "system" is Joomla's own bundled fallback template (offline.php,
        // error.php, fatal.php, ...), present in a stock install on both the
        // site and admin side. It's core Joomla, not an installed extension
        // -- it never goes through the extension installer and so
        // legitimately has no templateDetails.xml, unlike every other
        // folder under templates/. Exempt it from the no-manifest check
        // below so it isn't misclassified as a fake/junk template folder;
        // it can still be flagged separately by the actual content-
        // signature scan if a file inside it is genuinely infected.
        if (in_array(strtolower($topFolder), $sig['TEMPLATE_SYSTEM_FOLDER_NAMES'], true)) {
            return null;
        }

        $junkName = (bool) preg_match($sig['TEMPLATE_STYLE_JUNK_NAME_RE'], $topFolder);

        // Second, independent signal: does this folder have a
        // templateDetails.xml manifest at all? Joomla has no code path
        // that installs a template without one, so a folder that lacks
        // one was never actually installed as a real template -- a much
        // broader net than the tmpl_xxxxxx name check above, which only
        // catches one specific naming convention. Real-world mass
        // webshell-drop attacks have also been seen using an EXISTING
        // template's own name plus a random suffix (e.g. "beez3_degj",
        // "cassiopeia_hhnm") specifically to look more legitimate than an
        // obviously-fake tmpl_xxxxxx name at a glance.
        $noManifest = false;
        if ($absPath !== null && $depthAfterTop >= 0) {
            $templateRootAbs = $absPath;
            for ($i = 0; $i < $depthAfterTop; $i++) {
                $templateRootAbs = dirname($templateRootAbs);
            }
            if (!array_key_exists($templateRootAbs, self::$templateManifestCache)) {
                self::$templateManifestCache[$templateRootAbs] = is_file($templateRootAbs . '/templateDetails.xml');
            }
            $noManifest = !self::$templateManifestCache[$templateRootAbs];
        }

        if (!$junkName && !$noManifest) {
            return null;
        }

        if ($junkName) {
            return "Sits inside \"{$topFolder}\" — an auto-generated junk template folder name (tmpl_xxxxxx) seen paired with a matching fake #__template_styles database row in a real, confirmed mass-injection attack, not a legitimately installed template.";
        }

        return "Sits inside \"{$topFolder}\" — this folder has no templateDetails.xml manifest, so Joomla could never have installed it as a real template. A common mass webshell-drop pattern: an existing template's name plus a random suffix used purely to host a backdoor file behind a legitimate-looking path, not a real template.";
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
                $preview = self::filePreview($absPath);
                $suffix  = $preview !== '' ? " Matched code: {$preview}" : '';
                return 'Path masquerades as a template asset folder that does not exist in a clean install of any known Joomla template — flagged regardless of file content (even a blank stub here is a known real-world compromise artifact).' . $suffix;
            }
        }

        if (preg_match('#^(administrator/)?templates/[^/]+/index\.php$#i', $relPath)) return null;

        $contents = @file_get_contents($absPath, false, null, 0, 4096);
        if ($contents === false) return null;
        if (self::isStandardJoomlaStub($contents)) return null;

        $preview = trim(preg_replace('/\s+/', ' ', $contents));
        $preview = strlen($preview) > 220 ? substr($preview, 0, 220) . '…' : $preview;

        return "Non-standard index.php — Joomla only ever places a blank \"no direct access\" stub here (outside a template's own root layout file); this one contains extra code, a common disguise for a webshell. Matched code: {$preview}";
    }

    /**
     * True if any reason in a finding's reasons list corresponds to a
     * pattern this scanner can safely auto-repair (see
     * cleanPrependedPayload() / cleanHeadTagInjection()) -- used to build
     * the dedicated "Cleanable Files" tab in the UI, distinct from
     * findings that only support review/delete.
     */
    public static function isCleanablePattern(array $reasonsList): bool
    {
        foreach ($reasonsList as $r) {
            if (stripos($r, 'before the joomla bootstrap (_jexec)') !== false) return true;
            if (stripos($r, "before its own joomla bootstrap/access guard") !== false) return true;
            if (stripos($r, 'obfuscated script injected right after <head> tag') !== false) return true;
        }
        return false;
    }

    /**
     * True if $relPath is a genuinely required core/template entry file
     * that deleteTargets() refuses to delete (offering Clean instead).
     *
     * For a template's own root index.php (the only pattern in
     * PROTECTED_ENTRY_FILE_PATTERNS), "required" only holds if the
     * template is real -- i.e. Joomla could have actually installed it,
     * evidenced by a templateDetails.xml manifest sitting next to it. A
     * folder with a legitimate-looking name but no manifest was never a
     * real template (see checkJunkTemplateFolder()'s docblock); a
     * webshell dropped there should be deletable like any other
     * suspicious file, not steered toward "clean, never delete". Pass
     * $absPath when available (callers that only have a bare relative
     * path fall back to the old, safer-by-default "always required"
     * behaviour).
     */
    public static function isProtectedEntryPath(string $relPath, array $sig, ?string $absPath = null): bool
    {
        $relNorm = str_replace('\\', '/', $relPath);
        if (in_array($relNorm, $sig['PROTECTED_ENTRY_FILES'], true)) return true;
        foreach ($sig['PROTECTED_ENTRY_FILE_PATTERNS'] as $re) {
            if (preg_match($re, $relNorm)) {
                // Joomla's own bundled "system" fallback template (see
                // checkJunkTemplateFolder()) has no templateDetails.xml but
                // is still a genuinely required core file -- always
                // protected, regardless of the manifest check below.
                if (preg_match('#(?:^|/)templates/system/index\.php$#i', $relNorm)) {
                    return true;
                }
                if ($absPath !== null) {
                    return is_file(dirname($absPath) . '/templateDetails.xml');
                }
                return true;
            }
        }
        return false;
    }

    /** True if $relPath sits inside one of SCAN_CONFIG's 'code' directories (components, modules, plugins, libraries, templates, cli, bin, ...) -- an area where real, actively-used source files are expected to exist. */
    public static function isCodeAreaPath(string $relPath, array $sig): bool
    {
        $relNorm = ltrim(str_replace('\\', '/', $relPath), '/');
        foreach ($sig['SCAN_CONFIG'] as $dir => $mode) {
            if ($mode !== 'code') continue;
            if ($relNorm === $dir || strpos($relNorm, $dir . '/') === 0) return true;
        }
        return false;
    }

    /**
     * True when a finding inside a real code directory (see
     * isCodeAreaPath()) is flagged ONLY by content-signature matches --
     * i.e. every one of its reasons is a "Content signature: ..." hit,
     * with no structural/location red flag (core-masquerade, stray
     * index.php, unrecognized directory, suspicious filename, ...)
     * alongside it. That's the exact shape of a legitimate, actively-used
     * file that had a backdoor snippet injected into otherwise-normal
     * code, not a foreign file an attacker dropped -- the file's name and
     * location are completely unremarkable, only its content is
     * compromised. Deleting it outright would take down real site
     * functionality, so it must never be offered as a one-click-delete
     * candidate even when no auto-clean pattern recognizes this specific
     * infection -- landing in the Cleanable Files tab for manual review
     * is the safe outcome, not the destructive one.
     */
    public static function isContentOnlyCodeAreaFinding(string $relPath, array $reasonsList, array $sig): bool
    {
        if (empty($reasonsList) || !self::isCodeAreaPath($relPath, $sig)) return false;
        foreach ($reasonsList as $r) {
            if (stripos((string) $r, 'Content signature:') !== 0) return false;
        }
        return true;
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
    /** Patterns indicating executable/obfuscated code, used to judge whether text found before Joomla's bootstrap/guard marker is a real threat. */
    private static function suspiciousPrefixPatterns(): array
    {
        return [
            'stream-wrapper reference (zip://, phar://, etc.)' => '/(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//i',
            'numeric byte-array (chr() decode obfuscation)'    => '/array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)/i',
            'eval()'                                            => '/\beval\s*\(/i',
            'base64_decode()'                                   => '/base64_decode\s*\(/i',
            'assert()'                                           => '/\bassert\s*\(/i',
            'shell/process execution function'                  => '/\b(system|exec|shell_exec|passthru|proc_open)\s*\(/i',
        ];
    }

    /**
     * Locates the earliest point in a PHP file where Joomla's own
     * convention guarantees nothing should have executed yet -- either
     * the strict `define('_JEXEC', 1)` bootstrap constant (only the 4
     * true core entry points: index.php, administrator/index.php,
     * api/index.php, includes/app.php) or the universal
     * `defined('_JEXEC') or die(...)` guard that is the first statement
     * in virtually every OTHER Joomla PHP file (core libraries,
     * extensions, template root files, ...). Returns the matched
     * anchor's position plus everything between the opening <?php tag
     * and it, so callers can both FLAG suspicious content in that prefix
     * (checkCoreIndexIntegrity / checkGuardPrependedPayload) and, once
     * confirmed, safely CLEAN it (cleanPrependedPayload) by removing
     * exactly that prefix and nothing else -- the boundary is a hard
     * Joomla-convention marker, not a guess.
     */
    public static function checkPrependedPayload(string $contents): ?array
    {
        $openTagPos = stripos($contents, '<?php');
        if ($openTagPos === false) return null;

        $bootstrapPattern = '/(?:\\\\?\bdefine\s*\(\s*[\'"]_JEXEC[\'"]\s*,\s*1\s*\)|\bconst\s+_JEXEC\s*=\s*1)\s*;/i';
        $guardPattern      = '/defined\s*\(\s*[\'"]_JEXEC[\'"]\s*\)\s*or\s+die\s*(\([^)]*\))?\s*;/i';

        if (preg_match($bootstrapPattern, $contents, $m, PREG_OFFSET_CAPTURE)) {
            $anchorType = 'bootstrap';
        } elseif (preg_match($guardPattern, $contents, $m, PREG_OFFSET_CAPTURE)) {
            $anchorType = 'guard';
        } else {
            return null;
        }

        $prefixStart = $openTagPos + 5;
        $anchorPos   = $m[0][1];
        if ($anchorPos < $prefixStart) return null;
        $prefix = substr($contents, $prefixStart, $anchorPos - $prefixStart);

        foreach (self::suspiciousPrefixPatterns() as $label => $re) {
            if (preg_match($re, $prefix)) {
                return [
                    'anchor_type'  => $anchorType,
                    'label'        => $label,
                    'prefix'       => $prefix,
                    'open_tag_pos' => $openTagPos,
                    'anchor_pos'   => $anchorPos,
                ];
            }
        }
        return null;
    }

    /**
     * Loads the bundled per-Joomla-version SHA-256 checksum manifest for a
     * curated set of security-critical, site-independent core files (see
     * helpers/data/joomla_core_checksums.php for how it was generated and
     * exactly which files/versions it covers). Cached in a static so the
     * small data file is only read once per request no matter how many
     * files get checksum-checked.
     */
    public static function getCoreChecksumManifest(): array
    {
        static $manifest = null;
        if ($manifest === null) {
            $path = __DIR__ . '/data/joomla_core_checksums.php';
            $manifest = is_file($path) ? (include $path) : [];
        }
        return $manifest;
    }

    /**
     * Reads the exact installed Joomla core version from
     * administrator/manifests/files/joomla.xml -- the same file Joomla's
     * own update-checker relies on, present in every install. Plain
     * text/regex, no PHP execution, so this is safe to call against an
     * untrusted/potentially-infected codebase.
     */
    public static function getInstalledJoomlaVersion(string $root): ?string
    {
        $path = $root . '/administrator/manifests/files/joomla.xml';
        if (!is_file($path)) return null;
        $contents = @file_get_contents($path, false, null, 0, 4096);
        if ($contents === false) return null;
        if (preg_match('/<version>\s*([0-9]+\.[0-9]+\.[0-9]+)\s*<\/version>/i', $contents, $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * Compares a core file's actual SHA-256 against the bundled official
     * hash for the site's exact installed Joomla version. Returns null
     * (no finding) whenever the version or path isn't covered by the
     * manifest -- an unlisted version/file is a "we don't know" gap,
     * never treated as evidence of tampering, so this can only ever add
     * true findings on top of the existing heuristics, never introduce a
     * false positive from missing coverage. A mismatch is unambiguous,
     * byte-for-byte proof of tampering -- stronger than any heuristic
     * pattern match elsewhere in this scanner.
     */
    public static function checkCoreFileChecksum(string $relPath, string $absPath, ?string $version, array $manifest): ?string
    {
        if ($version === null || !isset($manifest[$version])) return null;
        $relNorm = ltrim(str_replace('\\', '/', $relPath), '/');
        if (!isset($manifest[$version][$relNorm])) return null;
        if (!is_file($absPath)) return null;
        $actual = @hash_file('sha256', $absPath);
        if ($actual === false) return null;
        $expected = $manifest[$version][$relNorm];
        if (hash_equals($expected, $actual)) return null;

        return "Core file checksum mismatch — this file's content does not match the official Joomla {$version} release byte-for-byte "
             . '(expected sha256 ' . substr($expected, 0, 12) . '…, found ' . substr($actual, 0, 12) . '…). '
             . 'This is direct, unambiguous evidence of tampering, not a heuristic guess.';
    }

    public static function checkCoreIndexIntegrity(string $contents): ?string
    {
        $info = self::checkPrependedPayload($contents);
        if ($info === null || $info['anchor_type'] !== 'bootstrap') return null;

        $preview = trim(preg_replace('/\s+/', ' ', $info['prefix']));
        $preview = strlen($preview) > 160 ? substr($preview, 0, 160) . '…' : $preview;
        return "Core entry-point file contains suspicious code before the Joomla bootstrap (_JEXEC) — {$info['label']} detected. Offending code: {$preview}";
    }

    /**
     * Same threat detection as checkCoreIndexIntegrity(), but for ANY
     * Joomla PHP file (core library, extension, template) using its own
     * universal `defined('_JEXEC') or die` access guard as the anchor
     * instead of the bootstrap constant only the 4 true entry points
     * define. Catches a legitimate core/extension file that has had
     * malicious code prepended ahead of its own guard -- the same
     * real-world "prepended payload" technique, just outside the 4 named
     * entry points, which previously went undetected by this check.
     */
    public static function checkGuardPrependedPayload(string $contents): ?string
    {
        $info = self::checkPrependedPayload($contents);
        if ($info === null || $info['anchor_type'] !== 'guard') return null;

        $preview = trim(preg_replace('/\s+/', ' ', $info['prefix']));
        $preview = strlen($preview) > 160 ? substr($preview, 0, 160) . '…' : $preview;
        return "File contains suspicious code before its own Joomla bootstrap/access guard (defined('_JEXEC') or die) — {$info['label']} detected; a legitimate Joomla file never executes anything before this line. Offending code: {$preview}";
    }

    /**
     * Repairs a "prepended payload" infection (see checkPrependedPayload())
     * by removing exactly the code sitting between the opening <?php tag
     * and Joomla's own bootstrap/guard statement, leaving everything from
     * that statement onward -- the entire legitimate file -- completely
     * untouched. Use this instead of deleting the file: index.php,
     * administrator/index.php, and a template's own root index.php are
     * all genuinely required files that should never simply be removed.
     */
    public static function cleanPrependedPayload(string $contents): array
    {
        $info = self::checkPrependedPayload($contents);
        if ($info === null) return ['cleaned' => $contents, 'changed' => false];

        $replacement = '<?php' . "\n";
        $before  = substr($contents, 0, $info['open_tag_pos']);
        $after   = substr($contents, $info['anchor_pos']);
        $cleaned = $before . $replacement . $after;

        $preview = trim(preg_replace('/\s+/', ' ', $info['prefix']));
        $preview = strlen($preview) > 160 ? substr($preview, 0, 160) . '…' : $preview;

        return [
            'cleaned' => $cleaned, 'changed' => true, 'removed_preview' => $preview,
            'removed_start' => $info['open_tag_pos'], 'removed_end' => $info['anchor_pos'],
            'replacement' => $replacement,
        ];
    }

    /**
     * Locates the first <script>...</script> block appearing after a
     * <head> tag, if its content matches known payload-loading markers
     * (base64/atob/eval/String.fromCharCode/document.write) or is simply
     * unusually large for an inline head script. Implemented with plain
     * string search (stripos/strpos/substr) rather than a single
     * monolithic regex spanning the whole file -- a nested-lazy-quantifier
     * regex applied to tens of KB of heavily-obfuscated real-world payload
     * is exactly the kind of input that can behave inconsistently under
     * PHP's PCRE backtrack limit, which would let detection and repair
     * silently disagree. This is the single source of truth for both
     * checkHeadTagInjection() (report) and cleanHeadTagInjection()
     * (repair), so they can never drift out of sync with each other.
     */
    private static function findInjectedHeadScript(string $contents): ?array
    {
        $headPos = stripos($contents, '<head');
        if ($headPos === false) return null;

        $scriptOpenPos = stripos($contents, '<script', $headPos);
        if ($scriptOpenPos === false) return null;

        $openTagCloseAt = strpos($contents, '>', $scriptOpenPos);
        if ($openTagCloseAt === false) return null;
        $bodyStart = $openTagCloseAt + 1;

        $scriptClosePos = stripos($contents, '</script', $bodyStart);
        if ($scriptClosePos === false) return null;
        $closeTagEndAt = strpos($contents, '>', $scriptClosePos);
        if ($closeTagEndAt === false) return null;
        $blockEnd = $closeTagEndAt + 1;

        $scriptBody = substr($contents, $bodyStart, $scriptClosePos - $bodyStart);
        $fullBlock  = substr($contents, $scriptOpenPos, $blockEnd - $scriptOpenPos);

        $hasMarker = (bool) preg_match('/base64|atob|eval|String\.fromCharCode|document\.write/i', $scriptBody);
        $isLarge   = strlen($scriptBody) > 200;
        if (!$hasMarker && !$isLarge) return null;

        return [
            'start' => $scriptOpenPos,
            'end'   => $blockEnd,
            'block' => $fullBlock,
            'label' => $hasMarker ? 'known payload-loading marker (base64/atob/eval/...)' : 'unusually large inline script',
        ];
    }

    public static function checkHeadTagInjection(string $contents): ?string
    {
        $info = self::findInjectedHeadScript($contents);
        if ($info === null) return null;

        $preview = trim(preg_replace('/\s+/', ' ', $info['block']));
        $preview = strlen($preview) > 200 ? substr($preview, 0, 200) . '…' : $preview;
        return "Suspicious obfuscated script injected right after <head> tag ({$info['label']}). Preview: {$preview}";
    }

    /**
     * Repairs a <head> script-injection infection (see
     * checkHeadTagInjection()) by removing exactly the injected
     * <script>...</script> block that check matched, leaving the <head>
     * tag and every other legitimate line in the template untouched.
     */
    public static function cleanHeadTagInjection(string $contents): array
    {
        $info = self::findInjectedHeadScript($contents);
        if ($info === null) return ['cleaned' => $contents, 'changed' => false];

        $cleaned = substr($contents, 0, $info['start']) . substr($contents, $info['end']);

        $preview = trim(preg_replace('/\s+/', ' ', $info['block']));
        $preview = strlen($preview) > 160 ? substr($preview, 0, 160) . '…' : $preview;

        return [
            'cleaned' => $cleaned, 'changed' => true, 'removed_preview' => $preview,
            'removed_start' => $info['start'], 'removed_end' => $info['end'], 'replacement' => '',
        ];
    }

    /**
     * Renders a ready-made, pre-escaped HTML block showing exactly what
     * the Clean action would remove (and add back, if anything) -- kept
     * server-side, like formatReasonForDisplay(), so the client never
     * parses or escapes free text, it just injects finished HTML. Takes
     * the exact removed/replacement strings a clean*() function reports
     * (see 'removed_start'/'removed_end'/'replacement' in
     * cleanPrependedPayload()/cleanHeadTagInjection()) rather than trying
     * to reverse-engineer the change from before/after content -- a
     * generic character-diff is ambiguous whenever the removed region's
     * boundary bytes repeat (e.g. a "<script...>" block sitting right
     * after "<head>" -- both start with "<"), which silently misaligns
     * the shown snippet by a few bytes. Using the exact positions the
     * clean function already computed avoids that class of bug entirely.
     */
    public static function formatCleanPreview(string $removed, string $replacement): string
    {
        $removedLen = strlen($removed);
        $removedTrim = trim($removed);
        $removedTrunc = strlen($removedTrim) > 400 ? substr($removedTrim, 0, 400) . '…' : $removedTrim;

        $addedTrim = trim($replacement);

        $html  = '<div class="muru-diff-block">';
        $html .= '<div class="muru-diff-label muru-diff-label-before">Before — Clean would remove ' . $removedLen . ' byte' . ($removedLen === 1 ? '' : 's') . '</div>';
        $html .= '<pre class="muru-diff-removed">' . htmlspecialchars($removedTrunc !== '' ? $removedTrunc : '(only whitespace)') . '</pre>';
        if ($addedTrim !== '') {
            $html .= '<div class="muru-diff-label muru-diff-label-after">After — replaced with</div>';
            $html .= '<pre class="muru-diff-added">' . htmlspecialchars($addedTrim) . '</pre>';
        } else {
            $html .= '<div class="muru-diff-label muru-diff-label-after">After — removed entirely, nothing put in its place</div>';
        }
        $html .= '</div>';
        return $html;
    }

    /**
     * Read-only dry run of cleanCodeFiles()'s exact repair logic (same
     * two functions, same order) against a file's CURRENT on-disk content
     * -- never writes anything. Returns a ready-to-display HTML diff
     * block when an auto-clean pattern is recognized, or null when it
     * isn't (unreadable file, or no pattern this scanner knows how to
     * auto-repair), so the UI can show an accurate "Preview Clean" only
     * where clicking Clean would actually change something.
     */
    public static function previewCleanDiff(string $absPath): ?string
    {
        if (!is_file($absPath)) return null;
        $contents = @file_get_contents($absPath);
        if ($contents === false) return null;

        $result = self::cleanPrependedPayload($contents);
        if (!$result['changed']) {
            $result = self::cleanHeadTagInjection($contents);
        }
        if (!$result['changed']) return null;

        $removed = substr($contents, $result['removed_start'], $result['removed_end'] - $result['removed_start']);
        return self::formatCleanPreview($removed, $result['replacement']);
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

        // Prepended-payload check on the file's OWN Joomla access guard --
        // catches a genuinely legitimate core/extension/template file that
        // has been infected by prepending malicious code ahead of its own
        // `defined('_JEXEC') or die` guard, the same real-world technique
        // as core entry-point tampering but applicable to any PHP file,
        // not just the 4 named entry points.
        if (in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht'], true)) {
            $guardIssue = self::checkGuardPrependedPayload($contents);
            if ($guardIssue !== null) { $flagged = true; $reasons[] = $guardIssue; }
        }

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
            'masquerade', 'disguise', 'polyglot', 'checksum mismatch',
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
            return '<div class="muru-reason-block"><p>' . htmlspecialchars($lead) . '</p>'
                 . '<div class="muru-reason-code-label">' . htmlspecialchars($label) . '</div>'
                 . '<pre class="muru-reason-code">' . htmlspecialchars($code) . '</pre></div>';
        }
        return '<div class="muru-reason-block"><p>' . htmlspecialchars($reason) . '</p></div>';
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
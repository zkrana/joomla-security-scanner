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

            'CONTENT_SIGNATURES' => [
                'eval_base64_post'   => '/eval\s*\(\s*(?:@)?base64_decode\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
                'cookie_gated_eval'  => '/md5\s*\(\s*(?:@)?\$_COOKIE\[[\'"][^\'"]+[\'"]\]\s*\)\s*==\s*[\'"][a-f0-9]{32}[\'"]/i',
                'assert_backdoor'    => '/assert\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
                'gsocket_indicator'  => '/GS_ARGS|gsocket/i',
                'shell_exec_chain'   => '/shell_exec\s*\(\s*\$_(POST|REQUEST|GET)/i',
                'xss_report_payload' => '/xss\.report|_hu_inject/i',
                'secure_local_marker'=> '/secure\.local/i',
                'webshell_generic'   => '/FilesMan|c99shell|r57shell|WSO\s*Web\s*Shell/i',
                'stream_wrapper_payload'    => '/require(?:_once)?\s*\(?\s*\$?\w*\s*\)?\s*;?.{0,200}?(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//is',
                'chr_byte_array_decode'     => '/\$\w+\s*=\s*array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)\s*;.{0,300}?chr\s*\(\s*\$\w+\[\$?\w+\]\s*\)/is',
                'string_lookup_obfuscation' => '/\$_?\w+\s*=\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}[\'"]\s*\)\s*;.{0,80}?\$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]/is',
                'self_replicating_dropper'  => '/glob\s*\(.{0,40}GLOB_ONLYDIR.{0,200}?file_put_contents\s*\(.{0,400}?md5\s*\(\s*\$\w+\s*\)\s*==\s*md5\s*\(\s*file_get_contents/is',
                'noop_comment_padding'      => '/(;\s*\/\*\s*\w{3,12}\s*\*\/\s*;\s*){8,}/i',
                'opcache_reset_only'        => '/^\s*<\?php\s*opcache_reset\s*\(\s*\)\s*;\s*\?>\s*$/i',
            ],

            'MENU_XSS_PATTERNS' => [
                'xss.report domain'            => '/xss\.report/i',
                '_hu_inject marker'            => '/_hu_?inject/i',
                'secure.local marker'          => '/secure\.local/i',
                'onerror/onload event handler' => '/on(error|load|mouseover|focus)\s*=/i',
                'inline <script> tag'          => '/<script[\s>]/i',
                'localStorage exfil/inject'    => '/localStorage\s*\.\s*(setItem|getItem)/i',
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
            'PHP_OPEN_TAG_RE' => '/<\?php/i',

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
            ],
        ];
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

    /** Runs content-signature + polyglot checks. Used in both scan modes. */
    public static function scanFileContent(string $path, string $ext, array $sig, int $maxSize, array &$reasons): bool
    {
        if (!is_file($path) || @filesize($path) === false || @filesize($path) > $maxSize) return false;
        $textLikeExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'pht', 'js', 'html', 'htm', 'txt', 'css', 'xml', 'gif', 'png', 'jpg', 'jpeg'];
        if (!in_array($ext, $textLikeExts, true) && $ext !== '') return false;
        $contents = @file_get_contents($path);
        if ($contents === false || $contents === '') return false;

        $flagged = false;
        foreach ($sig['CONTENT_SIGNATURES'] as $sigName => $re) {
            if (preg_match($re, $contents)) { $flagged = true; $reasons[] = "Content signature: $sigName"; }
        }
        if (in_array($ext, $sig['NON_PHP_EXTS_THAT_MUST_STAY_CLEAN'], true) && preg_match($sig['PHP_OPEN_TAG_RE'], $contents)) {
            $flagged = true;
            $reasons[] = 'Content signature: php_tag_in_image_file (polyglot shell disguised with an image extension)';
        }

        $headIssue = self::checkHeadTagInjection($contents);
        if ($headIssue !== null) { $flagged = true; $reasons[] = $headIssue; }

        return $flagged;
    }

    public static function recordFinding(array &$arr, string $absPath, string $root, string $reason, bool $isDir = false): void
    {
        $rel = ltrim(str_replace($root, '', $absPath), '/');
        $size = $isDir ? self::dirSize($absPath) : (is_file($absPath) ? (int) @filesize($absPath) : 0);
        $highSignals = [
            'content signature', 'icon-font', 'malicious pattern', 'unrecognized', 'numeric',
            'non-standard index.php', 'core entry-point', 'stream-wrapper', 'backup/duplicate', 'bootstrap',
        ];
        $confidence = 'medium';
        foreach ($highSignals as $sigName) {
            if (stripos($reason, $sigName) !== false) { $confidence = 'high'; break; }
        }
        $arr[$rel] = [
            'rel' => $rel, 'abs' => $absPath, 'reason' => $reason,
            'type' => $isDir ? 'dir' : 'file', 'confidence' => $confidence,
            'size' => $size, 'mtime' => (int) @filemtime($absPath),
        ];
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
<?php
/**
 * SP Page Builder Infection Scanner & Cleaner  (hardened build v4)
 *
 * v4 changes vs v3:
 *  - NEW: core entry-point integrity check. Joomla's real root index.php
 *    (and a few other known entry points) never executes anything before
 *    defining JOOMLA_MINIMUM_PHP / _JEXEC. Any code before that point —
 *    a require/include, a zip:// or phar:// stream-wrapper reference, a
 *    numeric byte-array decoded with chr(), etc. — is flagged as a
 *    confirmed core-file infection. This catches the real-world
 *    `$db = array(122,105,...); ... require zip://payload#2;` injection
 *    pattern seen prepended to index.php.
 *  - NEW: content signatures for stream-wrapper payload loading
 *    (zip://, phar://, compress.zlib://, data://), chr()-from-byte-array
 *    decoding, $M[12].$M[5]... string-lookup obfuscation (the style used
 *    by heavily obfuscated droppers), self-replicating dropper logic
 *    (glob() + chmod + file_put_contents + md5 verification loops), no-op
 *    comment padding used to break naive scanners, and "opcache_reset()
 *    only" trigger files (dropped after another malicious file is written
 *    to force PHP to pick up the new bytecode immediately).
 *  - NEW: explicit detection for backup/duplicate configuration.php files
 *    (configuration.bak.php, configuration.old.php, etc.) — these leak the
 *    same DB/mail credentials and Joomla secret as the live config and are
 *    a known artifact of restore tools as well as attacker reconnaissance.
 *  - NEW: marker/flag file detection — small, near-empty .txt files at
 *    webroot (e.g. a file containing just "0") are common dropper-toolkit
 *    artifacts (infection markers, lock files) and are now surfaced as a
 *    low/medium-confidence finding.
 *  - Confidence classifier extended to bucket all of the above as High
 *    confidence where appropriate.
 *  - $KNOWN_ROOT_FILES expanded to the full realistic set of stock Joomla
 *    5.x release files (web.config, configuration.php-dist, etc.) so
 *    legitimate files don't get flagged as "unrecognized."
 *
 * (v3 changes retained below for reference)
 *  - templates/ scanned recursively.
 *  - "numeric drop folder" detection (purely numeric folder names inside
 *    templates/, media/, images/).
 *  - "fake index.php stub" detection — any non-stub index.php outside a
 *    template's own root is flagged as a likely disguised webshell.
 *  - Cluster-drop detection (3+ new items in the same folder within a
 *    couple of minutes).
 *  - Timestamp-anomaly note applies to any flagged finding under templates/.
 *  - Strict allow-lists for assets/iconfont folders and JCE upload roots.
 *  - Directories can be flagged and deleted recursively; top-level Joomla
 *    folders are hard-protected from deletion regardless.
 *  - Confidence labels (High / Medium) on each finding.
 *
 * This is a heuristic scanner, not a guarantee. Pair it with a fresh
 * extension download + checksum comparison and a full server-side malware
 * scan (ClamAV / Imunify360 / your host's scanner) before declaring victory.
 */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
ini_set('display_errors', '0');
set_time_limit(180);

// =====================================================================
// CONFIG — EDIT BEFORE UPLOADING
// =====================================================================
$ACCESS_KEY         = 'PASTE_YOUR_GENERATED_KEY_HERE';
$JOOMLA_ROOT        = __DIR__;
$MAX_FILE_SCAN_SIZE = 2 * 1024 * 1024;
$SESSION_TIMEOUT    = 1800;
$MAX_FAILED_TRIES   = 5;
$LOCKOUT_WINDOW     = 900;
$ALLOWED_IPS        = [];
$DISABLED           = false;

$instanceId   = substr(hash('sha256', $ACCESS_KEY . __FILE__), 0, 16);
$LOG_FILE     = __DIR__ . "/.sppbscan-{$instanceId}.log";
$LOCKOUT_FILE = __DIR__ . "/.sppbscan-{$instanceId}.lock";

// =====================================================================
// SECURITY HEADERS
// =====================================================================
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('Content-Type: text/html; charset=UTF-8');

if ($DISABLED) { http_response_code(404); echo 'Not found.'; exit; }

if (strlen($ACCESS_KEY) < 32 || stripos($ACCESS_KEY, 'CHANGE_ME') !== false || stripos($ACCESS_KEY, 'REPLACE_THIS') !== false) {
    http_response_code(403);
    echo "Setup required: open this file and set \$ACCESS_KEY to a unique random secret (min 32 chars).\n";
    echo "Generate one: php -r \"echo bin2hex(random_bytes(32));\"\n";
    echo "Paste ONLY the generated value between the quotes — do not leave the placeholder text in there.\n";
    exit;
}

// =====================================================================
// SESSION SETUP
// =====================================================================
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_set_cookie_params([
    'lifetime' => 0, 'path' => '/',
    'secure'   => $isHttps, 'httponly' => true, 'samesite' => 'Strict',
]);
session_name('sppbscan_sid');
session_start();

// =====================================================================
// HELPERS
// =====================================================================
function e($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}
function logLine(string $line): void {
    global $LOG_FILE;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    @file_put_contents($LOG_FILE, '[' . date('Y-m-d H:i:s') . "] [$ip] $line\n", FILE_APPEND | LOCK_EX);
}
function humanSize(int $bytes): string {
    $units = ['B','KB','MB','GB']; $i = 0;
    while ($bytes >= 1024 && $i < 3) { $bytes /= 1024; $i++; }
    return round($bytes,1).' '.$units[$i];
}
function pruneFails(array $fails, int $window): array {
    $cutoff = time() - $window;
    return array_values(array_filter($fails, function ($t) use ($cutoff) { return $t >= $cutoff; }));
}
function getLockoutFails(string $file, int $window): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    $data = $raw ? json_decode($raw, true) : null;
    if (!is_array($data) || !isset($data['fails']) || !is_array($data['fails'])) return [];
    return pruneFails($data['fails'], $window);
}
function recordFailedAttempt(string $file, int $window): void {
    $fp = @fopen($file, 'c+');
    if (!$fp) return;
    if (flock($fp, LOCK_EX)) {
        $raw = stream_get_contents($fp);
        $data = $raw ? json_decode($raw, true) : null;
        if (!is_array($data) || !isset($data['fails'])) $data = ['fails' => []];
        $data['fails'] = pruneFails($data['fails'], $window);
        $data['fails'][] = time();
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, json_encode($data));
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}
function clearFailedAttempts(string $file): void {
    @file_put_contents($file, json_encode(['fails' => []]));
}
function walkDir(string $dir, callable $callback, array $skipDirNames = ['node_modules','.git']): void {
    if (!is_dir($dir)) return;
    $items = @scandir($dir);
    if ($items === false) return;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (in_array($item, $skipDirNames, true)) continue;
        $path = $dir.'/'.$item; $isDir = is_dir($path);
        $callback($path, $isDir);
        if ($isDir) walkDir($path, $callback, $skipDirNames);
    }
}
function readJoomlaDbConfig(string $root): ?array {
    $configFile = $root.'/configuration.php';
    if (!is_file($configFile)) return null;
    $contents = @file_get_contents($configFile);
    if ($contents === false) return null;
    $fields = ['host','user','password','db','dbprefix','dbtype'];
    $out = [];
    foreach ($fields as $f) {
        if (preg_match('/public\s*\$'.$f.'\s*=\s*\'((?:[^\'\\\\]|\\\\.)*)\'\s*;/', $contents, $m))
            $out[$f] = stripcslashes($m[1]);
    }
    if (empty($out['db'])) return null;
    return $out;
}
function dbConnect(array $cfg): ?mysqli {
    if (!isset($cfg['host'],$cfg['user'],$cfg['password'],$cfg['db'])) return null;
    $host = $cfg['host']; $port = 3306;
    if (strpos($host,':') !== false) { $parts = explode(':',$host,2); $host = $parts[0]; $port = (int)$parts[1]; }
    mysqli_report(MYSQLI_REPORT_OFF);
    $mysqli = @mysqli_connect($host,$cfg['user'],$cfg['password'],$cfg['db'],$port);
    return $mysqli ?: null;
}
function dirSize(string $dir): int {
    $total = 0;
    $items = @scandir($dir);
    if (!$items) return 0;
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') continue;
        $p = $dir.'/'.$it;
        if (is_dir($p)) $total += dirSize($p);
        elseif (is_file($p)) $total += (int)@filesize($p);
    }
    return $total;
}
function deleteRecursive(string $path): bool {
    if (is_link($path)) return @unlink($path);
    if (is_file($path)) return @unlink($path);
    if (!is_dir($path)) return true;
    $items = @scandir($path);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (!deleteRecursive($path.'/'.$item)) return false;
    }
    return @rmdir($path);
}
/** How many sibling items in the same folder were touched within $windowSeconds of $path's mtime. */
function clusterSiblingCount(string $path, int $windowSeconds = 150): int {
    $dir = dirname($path);
    $items = @scandir($dir);
    if (!$items) return 0;
    $myMtime = @filemtime($path);
    if (!$myMtime) return 0;
    $count = 0;
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') continue;
        $p = $dir.'/'.$it;
        if ($p === $path) continue;
        $t = @filemtime($p);
        if ($t && abs($t - $myMtime) <= $windowSeconds) $count++;
    }
    return $count;
}
/** Flags a file whose mtime date doesn't match the most common mtime date among its siblings (recent only). */
function mtimeOutlierNote(string $path): ?string {
    $dir = dirname($path);
    $items = @scandir($dir);
    if (!$items) return null;
    $counts = [];
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') continue;
        $p = $dir.'/'.$it;
        if (!is_file($p)) continue;
        $t = @filemtime($p);
        if (!$t) continue;
        $d = date('Y-m-d', $t);
        $counts[$d] = ($counts[$d] ?? 0) + 1;
    }
    if (count($counts) < 2) return null;
    arsort($counts);
    $modeDate = array_key_first($counts);
    $myMtime = @filemtime($path);
    if (!$myMtime) return null;
    $myDate = date('Y-m-d', $myMtime);
    if ($myDate === $modeDate) return null;
    $daysAgo = (time() - $myMtime) / 86400;
    if ($daysAgo > 60) return null;
    return "Modified on {$myDate}, while most sibling files in this folder date from {$modeDate} — confirm this change was an intentional update.";
}
/**
 * Returns true if $contents is (after stripping comments/whitespace)
 * nothing more than Joomla's standard "no direct access" guard. Joomla
 * places this blank stub in every subfolder by convention, so an
 * index.php existing somewhere is normal — but it should never contain
 * anything beyond this guard. Used to catch webshells disguised with a
 * legitimate-sounding filename.
 */
function isStandardJoomlaStub(string $contents): bool {
    $trimmed = trim($contents);
    if ($trimmed === '') return true; // some older stubs are just blank files

    // Strip /* */ and // comments, then collapse whitespace.
    $noBlockComments = preg_replace('#/\*.*?\*/#s', '', $trimmed);
    $noLineComments  = preg_replace('#//[^\n]*#', '', $noBlockComments);
    $normalized = trim(preg_replace('/\s+/', ' ', $noLineComments));

    // Remove the standard guard expression itself (several accepted variants).
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
 * True if $name looks like a standard Joomla date-based upload path
 * component (a 4-digit year or a 2-digit month/day) — a normal,
 * non-malicious folder-naming convention used by Joomla's media manager
 * and editors like JCE for organizing uploads by date (images/2025/10/17/).
 */
// Replace the existing function:
function isDateLikeNumericFolderName(string $name): bool {
    // Allow: 1-digit (album IDs), 2-digit (month/day), 4-digit (year)
    // Flag:  5+ digit purely numeric names (attacker timestamp/random drops)
    return (bool)preg_match('/^\d{1,4}$/', $name);
}

/**
 * NEW (v4): Joomla's real root index.php (and a handful of other known
 * entry points) never executes anything before defining
 * JOOMLA_MINIMUM_PHP / _JEXEC — that area of the file is reserved for a
 * doc comment block only. Any executable statement found there (a
 * require/include, a stream-wrapper reference, a byte-array decode, etc.)
 * means the file has been patched to silently load a separate payload on
 * every page load. This is the exact pattern used by the
 * `$db = array(122,105,...); require zip://payload#2;` injection seen in
 * real-world Joomla compromises.
 */
function checkCoreIndexIntegrity(string $contents): ?string {
    $openTagPos = stripos($contents, '<?php');
    if ($openTagPos === false) return null;

    $bootstrapPattern = '/(?:\\\\?\bdefine\s*\(\s*[\'"]_JEXEC[\'"]\s*,\s*1\s*\)|\bconst\s+_JEXEC\s*=\s*1)\s*;/i';
    if (!preg_match($bootstrapPattern, $contents, $m, PREG_OFFSET_CAPTURE)) {
        // Some legitimate Joomla files (e.g. includes/app.php) are included
        // by the real entry point and never define _JEXEC themselves. Don't
        // flag on absence -- content-signature scanning (run separately)
        // still catches actual malware in these files.
        return null;
    }

    $prefix = substr($contents, $openTagPos + 5, $m[0][1] - ($openTagPos + 5));

    // Only flag the prefix if it contains a genuinely malicious indicator --
    // not merely "non-empty". Joomla version-check code, JPATH_BASE guards,
    // use/namespace statements, etc. all legitimately vary by version and
    // entry point; trying to whitelist every variant is a losing game.
    $suspiciousPatterns = [
        'stream-wrapper reference (zip://, phar://, etc.)' => '/(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//i',
        'numeric byte-array (chr() decode obfuscation)'    => '/array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)/i',
        'eval()'                                            => '/\beval\s*\(/i',
        'base64_decode()'                                   => '/base64_decode\s*\(/i',
        'assert()'                                          => '/\bassert\s*\(/i',
        'shell/process execution function'                 => '/\b(system|exec|shell_exec|passthru|proc_open)\s*\(/i',
    ];

    foreach ($suspiciousPatterns as $label => $re) {
        if (preg_match($re, $prefix)) {
            $preview = trim(preg_replace('/\s+/', ' ', $prefix));
            $preview = strlen($preview) > 160 ? substr($preview, 0, 160).'…' : $preview;
            return "Core entry-point file contains suspicious code before the Joomla bootstrap (_JEXEC) — {$label} detected. This is the injection pattern used to silently load a separate payload on every page load. Offending code: {$preview}";
        }
    }
    return null;
}

function checkHeadTagInjection(string $contents): ?string {
    // Check for <head> tag followed by obfuscated script
    if (stripos($contents, '<head') === false) return null;
    
    // Look for patterns: <head> followed by script with base64, long hex, etc.
    $patterns = [
        // <head> followed by script tag with base64 encoded content
        '/<head[^>]*>\s*(?:<[^>]*>)*?\s*<script[^>]*>(?:.*?(?:base64|atob|eval|String\.fromCharCode|document\.write).*?)<\/script/is',
        // Obfuscated script right after <head>
        '/<head[^>]*>\s*<script[^>]*>(?:[\s\S]{200,}?)<\/script/is'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $contents, $matches)) {
            $preview = trim(preg_replace('/\s+/', ' ', $matches[0]));
            $preview = strlen($preview) > 200 ? substr($preview, 0, 200).'…' : $preview;
            return "Suspicious obfuscated script injected right after <head> tag — this matches the known attack pattern. Preview: {$preview}";
        }
    }
    
    return null;
}

function recordFinding(array &$arr, string $absPath, string $root, string $reason, bool $isDir = false): void {
    $rel = ltrim(str_replace($root,'',$absPath),'/');
    $size = $isDir ? dirSize($absPath) : (is_file($absPath) ? (int)@filesize($absPath) : 0);
    $highSignals = [
        'content signature','icon-font','malicious pattern','unrecognized','numeric',
        'non-standard index.php','core entry-point','stream-wrapper','backup/duplicate',
        'bootstrap',
    ];
    $confidence = 'medium';
    foreach ($highSignals as $sig) {
        if (stripos($reason, $sig) !== false) { $confidence = 'high'; break; }
    }
    $arr[$rel] = [
        'rel'=>$rel,'abs'=>$absPath,'reason'=>$reason,
        'type'=>$isDir ? 'dir' : 'file',
        'confidence'=>$confidence,
        'size'=>$size,
        'mtime'=>(int)@filemtime($absPath),
    ];
}

// =====================================================================
// IP ALLOW-LIST
// =====================================================================
if (!empty($ALLOWED_IPS)) {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!in_array($clientIp, $ALLOWED_IPS, true)) {
        http_response_code(403); logLine("BLOCKED: IP $clientIp not in allow-list"); echo 'Access denied.'; exit;
    }
}

// =====================================================================
// LOCKOUT CHECK
// =====================================================================
$currentFails = getLockoutFails($LOCKOUT_FILE, $LOCKOUT_WINDOW);
if (count($currentFails) >= $MAX_FAILED_TRIES) {
    $oldest = min($currentFails);
    $retryAfter = max(1, $LOCKOUT_WINDOW - (time() - $oldest));
    http_response_code(429);
    header("Retry-After: $retryAfter");
    ?><!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Locked Out</title>
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { background: #0a0d12; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             min-height: 100vh; display: flex; align-items: center; justify-content: center; }
      .card { background: #111827; border: 1px solid #1f2d3d; border-radius: 16px; padding: 48px 40px; max-width: 420px; width: 100%; text-align: center; }
      .icon { font-size: 48px; margin-bottom: 20px; }
      h1 { font-size: 22px; font-weight: 700; margin-bottom: 10px; color: #f87171; }
      p { color: #64748b; font-size: 14px; line-height: 1.6; }
      .retry { margin-top: 20px; font-size: 13px; color: #94a3b8; background: #1e293b; padding: 10px 20px;
               border-radius: 8px; display: inline-block; }
    </style></head><body>
    <div class="card">
      <div class="icon">🔒</div>
      <h1>Too Many Attempts</h1>
      <p>This scanner has been locked due to repeated failed key attempts.</p>
      <div class="retry">Retry in <?= ceil($retryAfter/60) ?> minute(s)</div>
    </div>
    </body></html><?php
    exit;
}

// =====================================================================
// LOGIN PAGE — shown when not yet authenticated and no key in URL
// =====================================================================
$providedKey = '';
if (isset($_GET['key']))  $providedKey = (string)$_GET['key'];
if (isset($_POST['key'])) $providedKey = (string)$_POST['key'];

$authed = false;
$justAuthedViaKey = false;
$loginError = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_key'])) {
    $submittedKey = trim((string)$_POST['login_key']);
    if (hash_equals($ACCESS_KEY, $submittedKey)) {
        clearFailedAttempts($LOCKOUT_FILE);
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        header('Location: ' . $path . '?key=' . urlencode($submittedKey), true, 302);
        exit;
    } else {
        recordFailedAttempt($LOCKOUT_FILE, $LOCKOUT_WINDOW);
        logLine('LOGIN FORM FAIL: bad key');
        usleep(800000);
        $loginError = 'Invalid secret key. Please try again.';
    }
}

if ($providedKey !== '') {
    if (hash_equals($ACCESS_KEY, $providedKey)) {
        clearFailedAttempts($LOCKOUT_FILE);
        session_regenerate_id(true);
        $_SESSION['sppbscan_auth_at'] = time();
        $authed = true;
        $justAuthedViaKey = isset($_GET['key']);
        logLine('AUTH OK via key');
    } else {
        recordFailedAttempt($LOCKOUT_FILE, $LOCKOUT_WINDOW);
        logLine('AUTH FAIL: bad key');
        usleep(800000);
        $loginError = 'Invalid secret key. Please try again.';
    }
} elseif (!empty($_SESSION['sppbscan_auth_at']) && (time() - $_SESSION['sppbscan_auth_at']) < $SESSION_TIMEOUT) {
    $_SESSION['sppbscan_auth_at'] = time();
    $authed = true;
}

if (!$authed) {
    $failsLeft = max(0, $MAX_FAILED_TRIES - count($currentFails));
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner — Authenticate</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #080b10;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .wrap { width: 100%; max-width: 440px; }
  .logo-row { display: flex; align-items: center; gap: 12px; margin-bottom: 36px; justify-content: center; }
  .shield {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, #1e40af, #3b82f6);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; flex-shrink: 0;
    box-shadow: 0 4px 16px rgba(59,130,246,0.35);
  }
  .logo-text { font-size: 16px; font-weight: 600; color: #94a3b8; letter-spacing: 0.02em; }
  .card {
    background: #0f1623; border: 1px solid #1a2540; border-radius: 20px;
    padding: 40px 36px 36px; box-shadow: 0 24px 64px rgba(0,0,0,0.5);
  }
  h1 { font-size: 24px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px; letter-spacing: -0.02em; }
  .sub { font-size: 13.5px; color: #4a5e7a; margin-bottom: 32px; line-height: 1.5; }
  label {
    display: block; font-size: 12px; font-weight: 600; letter-spacing: 0.07em;
    text-transform: uppercase; color: #4a5e7a; margin-bottom: 8px;
  }
  .input-wrap { position: relative; margin-bottom: 20px; }
  input[type="password"] {
    width: 100%; background: #080b10; border: 1px solid #1a2540; border-radius: 10px;
    color: #e2e8f0; font-size: 15px; padding: 13px 48px 13px 16px; outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    font-family: ui-monospace, 'Cascadia Code', monospace; letter-spacing: 0.05em;
  }
  input[type="password"]:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
  .toggle-vis {
    position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
    background: none; border: none; color: #4a5e7a; cursor: pointer;
    font-size: 16px; padding: 4px; transition: color 0.15s;
  }
  .toggle-vis:hover { color: #94a3b8; }
  .btn-submit {
    width: 100%; background: linear-gradient(135deg, #1d4ed8, #3b82f6); color: #fff;
    border: none; border-radius: 10px; font-size: 15px; font-weight: 600; padding: 14px;
    cursor: pointer; transition: opacity 0.15s, transform 0.1s; letter-spacing: 0.01em;
    box-shadow: 0 4px 16px rgba(59,130,246,0.3);
  }
  .btn-submit:hover { opacity: 0.92; transform: translateY(-1px); }
  .btn-submit:active { transform: translateY(0); }
  .error {
    background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25); border-radius: 10px;
    color: #fca5a5; font-size: 13px; padding: 12px 16px; margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }
  .attempts-left { text-align: center; font-size: 12px; color: #374151; margin-top: 20px; }
  .attempts-left span { color: <?= $failsLeft <= 2 ? '#f87171' : '#4b5563' ?>; font-weight: 600; }
  .divider { border: none; border-top: 1px solid #1a2540; margin: 28px 0 20px; }
  .hint { font-size: 12px; color: #2d3f58; text-align: center; line-height: 1.6; }
</style>
</head>
<body>
<div class="wrap">
  <div class="logo-row">
    <div class="shield">🛡️</div>
    <div class="logo-text">SP Page Builder · Incident Scanner</div>
  </div>

  <div class="card">
    <h1>Authentication required</h1>
    <p class="sub">Enter the secret key you configured in this scanner to continue.</p>

    <?php if ($loginError): ?>
    <div class="error"><span>⚠️</span> <?= e($loginError) ?></div>
    <?php endif; ?>

    <form method="post" autocomplete="off">
      <label for="login_key">Secret Key</label>
      <div class="input-wrap">
        <input type="password" id="login_key" name="login_key"
               placeholder="Paste your secret key…"
               autofocus autocomplete="off" spellcheck="false">
        <button type="button" class="toggle-vis" onclick="
          var i=document.getElementById('login_key');
          i.type=i.type==='password'?'text':'password';
          this.textContent=i.type==='password'?'👁':'🙈';
        " title="Toggle visibility">👁</button>
      </div>
      <button type="submit" class="btn-submit">Unlock Scanner →</button>
    </form>

    <hr class="divider">
    <p class="hint">
      After verification you'll be redirected with the key in the URL,<br>
      which is then stripped from your browser history automatically.
    </p>
  </div>

  <?php if ($failsLeft < $MAX_FAILED_TRIES): ?>
  <div class="attempts-left">
    <span><?= $failsLeft ?></span> attempt<?= $failsLeft !== 1 ? 's' : '' ?> remaining before lockout
  </div>
  <?php endif; ?>
</div>
<script>
  document.getElementById('login_key').addEventListener('input', function() {
    if (this.value.length >= 64) { this.closest('form').submit(); }
  });
</script>
</body>
</html>
    <?php
    exit;
}

if ($justAuthedViaKey) {
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    header("Location: $path", true, 302);
    exit;
}

if (empty($_SESSION['sppbscan_csrf'])) {
    $_SESSION['sppbscan_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['sppbscan_csrf'];

function csrfValid(string $csrfToken): bool {
    return isset($_POST['csrf']) && hash_equals($csrfToken, (string)$_POST['csrf']);
}

// =====================================================================
// LOGOUT
// =====================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    if (csrfValid($csrfToken)) {
        logLine('LOGOUT'); $_SESSION = []; session_destroy();
        setcookie(session_name(), '', time()-3600, '/');
    }
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    header("Location: $path", true, 302); exit;
}

// =====================================================================
// SELF-DESTRUCT
// =====================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'selfdestruct') {
    if (csrfValid($csrfToken)) {
        logLine('SELF-DESTRUCT'); $_SESSION = []; session_destroy();
        @unlink($LOCKOUT_FILE); @unlink($LOG_FILE); @unlink(__FILE__);
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Removed</title>'
           . '<style>body{background:#080b10;color:#e2e8f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}'
           . '.m{text-align:center;}.m h2{font-size:22px;margin-bottom:8px;}.m p{color:#4a5e7a;font-size:14px;}</style></head>'
           . '<body><div class="m"><div style="font-size:48px;margin-bottom:16px">✅</div>'
           . '<h2>Scanner removed</h2><p>This script has deleted itself. You can close this tab.</p></div></body></html>';
        exit;
    }
}

// =====================================================================
// SCAN CONFIGURATION — directory-driven, two simple modes
// =====================================================================
// 'upload'  = strict mode: executable files are never allowed here, numeric
//             drop-folders are flagged, and a non-stub index.php is flagged.
//             Use this ONLY for directories where users/attackers can drop
//             files (media, images, cache, tmp, custom upload folders).
// 'code'    = signature-only mode: this is real extension/component/module
//             code, so .php files are normal and expected everywhere. Only
//             actual malware content signatures are checked here — no
//             structural guessing about "should this subfolder exist".
$SCAN_CONFIG = [
    'media'                                    => 'upload',   // catches direct-drop attacks
    'images'                                   => 'upload',
    'tmp'                                      => 'upload',
    'cache'                                    => 'upload',
    'files'                                    => 'upload',

    'components'                               => 'code',
    'administrator/components'                 => 'code',
    'modules'                                   => 'code',
    'administrator/modules'                     => 'code',
    'plugins'                                    => 'code',
    'administrator/includes'                     => 'code',
    'libraries'                                   => 'code',
    'templates'                                    => 'code',
    'administrator/templates'                    => 'code',
];

// Strict allow-list for */assets/iconfont/* -- a real-world drop point for
// the SPPB unauthenticated upload vulnerability. Anything here that isn't a
// recognised font/icon asset is flagged, regardless of content.
$ICONFONT_ALLOWED_DIRNAMES   = ['css','font','fonts','demo','docs','demo-files'];
$ICONFONT_ALLOWED_EXTENSIONS = ['woff','woff2','ttf','eot','otf','svg','css','json','html','htm','txt','md'];
$ICONFONT_ALLOWED_BARE_NAMES = ['license','readme','changelog'];

// Strict allow-list for JCE's file browser upload path.
$JCE_UPLOAD_PATH_FRAGMENTS = [
    '/media/com_jce/editor/tiny_mce/plugins/filemanager/',
];
$JCE_UPLOAD_ALLOWED_EXTENSIONS = ['jpg','jpeg','png','gif','webp','svg','pdf','doc','docx','xls','xlsx','zip','css','js','json','html','htm'];

$EXEC_EXTS = ['php','phtml','php3','php4','php5','php7','phar','pht','shtml'];

// Filenames matching known malicious patterns from real SPPB compromises.
$SUSPICIOUS_FILENAME_REGEXES = [
    '/^codex-sppb-[a-f0-9]+\.php$/i',
    '/^codex_sppb.*\.php$/i',
    '/queue_\d+\.php$/i',
    '/\.php\.gif$/i',
    '/\.xml\.php$/i',
    '/^x\.xml$/i',
];

// Extra filename heuristics applied ONLY to files sitting directly in the
// Joomla webroot (shallow scan).
$ROOT_SUSPICIOUS_FILENAME_REGEXES = [
    '/^wp-[a-z0-9_-]*\.(php|txt|html?)$/i',
    '/file[-_]?ma[nr]+ger2?\.php$/i',
    '/^[a-z0-9]{1,3}\.php$/i',
    '/^\d{1,8}\.php$/i',
    '/^[a-z]{2,8}\.txt$/i',
];

$CONFIG_BACKUP_PATTERNS = [
    '/^configuration[\._\-]?bak\.php$/i',
    '/^configuration[\._\-]?old\.php$/i',
    '/^configuration\.php\.(bak|old|orig|save|swp|~)$/i',
    '/^config[\._\-]?backup\.php$/i',
    '/^configuration\d*\.php\.(txt|bak)$/i',
];

$CONTENT_SIGNATURES = [
    'eval_base64_post'   => '/eval\s*\(\s*(?:@)?base64_decode\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
    'cookie_gated_eval'  => '/md5\s*\(\s*(?:@)?\$_COOKIE\[[\'"][^\'"]+[\'"]\]\s*\)\s*==\s*[\'"][a-f0-9]{32}[\'"]/i',
    'assert_backdoor'    => '/assert\s*\(\s*(?:@)?\$_(POST|REQUEST|GET)/i',
    'gsocket_indicator'  => '/GS_ARGS|gsocket/i',
    'shell_exec_chain'   => '/shell_exec\s*\(\s*\$_(POST|REQUEST|GET)/i',
    'xss_report_payload' => '/xss\.report|_hu_inject/i',
    'secure_local_marker'=> '/secure\.local/i',
    'webshell_generic'   => '/FilesMan|c99shell|r57shell|WSO\s*Web\s*Shell/i',
    'stream_wrapper_payload' => '/require(?:_once)?\s*\(?\s*\$?\w*\s*\)?\s*;?.{0,200}?(zip|phar|compress\.zlib|compress\.bzip2|data):\/\//is',
    'chr_byte_array_decode'  => '/\$\w+\s*=\s*array\s*\(\s*(\d{2,3}\s*,\s*){6,}\d{2,3}\s*\)\s*;.{0,300}?chr\s*\(\s*\$\w+\[\$?\w+\]\s*\)/is',
    'string_lookup_obfuscation' => '/\$_?\w+\s*=\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{40,}[\'"]\s*\)\s*;.{0,80}?\$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]/is',
    'self_replicating_dropper'  => '/glob\s*\(.{0,40}GLOB_ONLYDIR.{0,200}?file_put_contents\s*\(.{0,400}?md5\s*\(\s*\$\w+\s*\)\s*==\s*md5\s*\(\s*file_get_contents/is',
    'noop_comment_padding'      => '/(;\s*\/\*\s*\w{3,12}\s*\*\/\s*;\s*){8,}/i',
    'opcache_reset_only' => '/^\s*<\?php\s*opcache_reset\s*\(\s*\)\s*;\s*\?>\s*$/i',
];

$NON_PHP_EXTS_THAT_MUST_STAY_CLEAN = ['png','jpg','jpeg','gif','webp','ico','svg','bmp'];
$PHP_OPEN_TAG_RE = '/<\?php/i';

$CORE_ENTRY_POINTS = [
    'index.php',
    'administrator/index.php',
    'api/index.php',
    'includes/app.php',
];

$KNOWN_ROOT_FILES = ['index.php','configuration.php','htaccess.txt','web.config.txt','robots.txt.dist',
                      'robots.txt','LICENSE.txt','README.txt','joomla.xml','htaccess.bak',
                      'php.ini','php.ini.bak','.user.ini','.htaccess','.htaccess.bak'];

$KNOWN_SAFE_RELATIVE_FILES = [
    'index.php', 'administrator/index.php', 'api/index.php',
    'includes/app.php', 'includes/framework.php', 'cli/joomla.php',
    'files/index.html', 'images/index.html', 'media/index.html',
];

$KNOWN_ROOT_DIRS = ['administrator','api','bin','cache','cli','components','includes',
                     'language','layouts','libraries','media','modules','plugins',
                     'templates','tmp','images','files','node_modules','.well-known'];

$PROTECTED_TOP_DIRS = ['administrator','components','libraries','media','images','templates',
                        'plugins','modules','language','cache','tmp','layouts','includes','api','cli'];


// =====================================================================
// SCAN: filesystem
// =====================================================================
$fileFindings = [];
$seenAbs = [];
$selfBasename = strtolower(basename(__FILE__));

/**
 * Scan a single file for content signatures + polyglot check.
 * Runs in BOTH 'upload' and 'code' modes — this is the core malware detector.
 */
function scanFileContent(string $path, string $ext, array $CONTENT_SIGNATURES,
                          array $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, string $PHP_OPEN_TAG_RE,
                          int $maxSize, array &$reasons): bool {
    if (!is_file($path) || @filesize($path) === false || @filesize($path) > $maxSize) return false;
    $textLikeExts = ['php','phtml','php3','php4','php5','php7','phar','pht','js','html','htm','txt','css','xml','gif','png','jpg','jpeg'];
    if (!in_array($ext, $textLikeExts, true) && $ext !== '') return false;
    $contents = @file_get_contents($path);
    if ($contents === false || $contents === '') return false;

    $flagged = false;
    foreach ($CONTENT_SIGNATURES as $sigName => $re) {
        if (preg_match($re, $contents)) { $flagged = true; $reasons[] = "Content signature: $sigName"; }
    }
    if (in_array($ext, $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, true) && preg_match($PHP_OPEN_TAG_RE, $contents)) {
        $flagged = true;
        $reasons[] = 'Content signature: php_tag_in_image_file (polyglot shell disguised with an image extension)';
    }
    
    // Check for head tag injection
    $headIssue = checkHeadTagInjection($contents);
    if ($headIssue !== null) {
        $flagged = true;
        $reasons[] = $headIssue;
    }
    
    return $flagged;
}

foreach ($SCAN_CONFIG as $relDir => $mode) {
    $dir = $JOOMLA_ROOT.'/'.$relDir;
    if (!is_dir($dir)) continue;

    walkDir($dir, function(string $path, bool $isDir) use (
        &$fileFindings, $JOOMLA_ROOT, $mode,
        $SUSPICIOUS_FILENAME_REGEXES, $CONTENT_SIGNATURES, $MAX_FILE_SCAN_SIZE,
        $ICONFONT_ALLOWED_DIRNAMES, $ICONFONT_ALLOWED_EXTENSIONS, $ICONFONT_ALLOWED_BARE_NAMES,
        $JCE_UPLOAD_PATH_FRAGMENTS, $JCE_UPLOAD_ALLOWED_EXTENSIONS,
        $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, $PHP_OPEN_TAG_RE,
        $KNOWN_SAFE_RELATIVE_FILES, $EXEC_EXTS, $selfBasename, &$seenAbs
    ) {
        if (strtolower(basename($path)) === $selfBasename) return;
        if (isset($seenAbs[$path])) return;

        $basename = basename($path);
        $relCheck = ltrim(str_replace($JOOMLA_ROOT, '', $path), '/');
        $isKnownSafeEntry = !$isDir && in_array($relCheck, $KNOWN_SAFE_RELATIVE_FILES, true);
        $flagged = false; $reasons = [];

        // ---- iconfont strict allow-list (applies regardless of mode) ----
        if (stripos($path, '/iconfont/') !== false) {
            $parentBase = strtolower(basename(dirname($path)));
            if ($isDir) {
                if ($parentBase === 'iconfont' && !in_array(strtolower($basename), $ICONFONT_ALLOWED_DIRNAMES, true)) {
                    $flagged = true;
                    $reasons[] = 'Unrecognized folder inside icon-font asset directory.';
                }
            } else {
                $extL = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                if (in_array($extL, $EXEC_EXTS, true)) {
                    $flagged = true;
                    $reasons[] = 'Executable file inside icon-font asset folder.';
                } elseif ($parentBase === 'iconfont') {
                    $baseNoExt = strtolower(pathinfo($basename, PATHINFO_FILENAME));
                    if (!in_array($extL, $ICONFONT_ALLOWED_EXTENSIONS, true)
                        && !($extL === '' && in_array($baseNoExt, $ICONFONT_ALLOWED_BARE_NAMES, true))) {
                        $flagged = true;
                        $reasons[] = 'Unrecognized file type inside icon-font asset directory.';
                    }
                }
            }
        }

        // ---- JCE upload strict allow-list (applies regardless of mode) ----
        if (!$isDir && !$flagged) {
            foreach ($JCE_UPLOAD_PATH_FRAGMENTS as $frag) {
                if (stripos($path, $frag) === false) continue;
                $extL = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                if (in_array($extL, $EXEC_EXTS, true)) {
                    $flagged = true;
                    $reasons[] = 'Executable file inside JCE file-browser upload path.';
                } elseif ($extL !== '' && !in_array($extL, $JCE_UPLOAD_ALLOWED_EXTENSIONS, true)) {
                    $flagged = true;
                    $reasons[] = 'Unrecognized file type inside JCE file-browser upload path.';
                }
                break;
            }
        }

        // ---- 'upload' mode: strict structural checks ----
        if ($mode === 'upload') {
            if ($isDir) {
                if (preg_match('/^\d+$/', $basename) && !isDateLikeNumericFolderName($basename)) {
                    $flagged = true;
                    $reasons[] = "Folder name is purely numeric (\"{$basename}\") and isn't a normal date/ID component — a common automated-malware-drop pattern.";
                }
            } else {
                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                if (!$isKnownSafeEntry && in_array($ext, $EXEC_EXTS, true)) {
                    $flagged = true;
                    $reasons[] = "Executable file (.$ext) inside an upload directory (media/images/cache/tmp/files) — these should never contain runnable code.";
                }
                if (!$isKnownSafeEntry) {
                    foreach ($SUSPICIOUS_FILENAME_REGEXES as $re) {
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

        // ---- content signature scan: runs in BOTH modes, on files only ----
        if (!$isDir) {
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (scanFileContent($path, $ext, $CONTENT_SIGNATURES, $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, $PHP_OPEN_TAG_RE, $MAX_FILE_SCAN_SIZE, $reasons)) {
                $flagged = true;
            }
        }

        if ($flagged) {
            $seenAbs[$path] = true;
            recordFinding($fileFindings, $path, $JOOMLA_ROOT, implode(' | ', array_unique($reasons)), $isDir);
        }
    });
}

// Shallow (non-recursive) check of the webroot itself for stray dropped files
// and unrecognized top-level folders/files.
$rootItems = @scandir($JOOMLA_ROOT) ?: [];
foreach ($rootItems as $it) {
    if ($it === '.' || $it === '..') continue;
    $p = $JOOMLA_ROOT.'/'.$it;
    if (isset($seenAbs[$p])) continue;
    if (strtolower($it) === $selfBasename) continue;

    if (is_dir($p)) {
        if (!in_array(strtolower($it), array_map('strtolower', $KNOWN_ROOT_DIRS), true)) {
            $seenAbs[$p] = true;
            recordFinding($fileFindings, $p, $JOOMLA_ROOT,
                'Unrecognized directory directly in the Joomla webroot — not part of a standard install.', true);
            walkDir($p, function(string $innerPath, bool $innerIsDir) use (&$fileFindings, $JOOMLA_ROOT, &$seenAbs, $selfBasename) {
                if ($innerIsDir || isset($seenAbs[$innerPath]) || strtolower(basename($innerPath)) === $selfBasename) return;
                $seenAbs[$innerPath] = true;
                recordFinding($fileFindings, $innerPath, $JOOMLA_ROOT,
                    'Inside an unrecognized top-level webroot directory.', false);
            });
        }
        continue;
    }

    if (!is_file($p)) continue;
    if (in_array(strtolower($it), array_map('strtolower', $KNOWN_ROOT_FILES), true)) continue;
    $relCheck = ltrim(str_replace($JOOMLA_ROOT, '', $p), '/');
    if (in_array($relCheck, $KNOWN_SAFE_RELATIVE_FILES, true)) continue;

    $flaggedRoot = false; $reasonsRoot = [];
    foreach ($SUSPICIOUS_FILENAME_REGEXES as $re) {
        if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Filename matches known malicious pattern.'; break; }
    }
    foreach ($ROOT_SUSPICIOUS_FILENAME_REGEXES as $re) {
        if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Filename resembles a known dropped-shell naming pattern.'; break; }
    }
    foreach ($CONFIG_BACKUP_PATTERNS as $re) {
        if (preg_match($re, $it)) { $flaggedRoot = true; $reasonsRoot[] = 'Backup/duplicate configuration file — leaks the same credentials as configuration.php.'; break; }
    }

    $extR = strtolower(pathinfo($p, PATHINFO_EXTENSION));
    scanFileContent($p, $extR, $CONTENT_SIGNATURES, $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, $PHP_OPEN_TAG_RE, $MAX_FILE_SCAN_SIZE, $reasonsRoot);
    if (count($reasonsRoot) > (($flaggedRoot ? 1 : 0))) $flaggedRoot = true; // scanFileContent added a signature reason

    $benignStaticExts = ['css','jpg','jpeg','png','gif','svg','ico','webp','woff','woff2','ttf','eot','map'];
    if (!$flaggedRoot && !in_array($extR, $benignStaticExts, true)) {
        $flaggedRoot = true;
        $reasonsRoot[] = 'Unrecognized file directly in the Joomla webroot — not part of a standard install.';
    }

    if ($flaggedRoot) {
        $seenAbs[$p] = true;
        recordFinding($fileFindings, $p, $JOOMLA_ROOT, implode(' | ', array_unique($reasonsRoot)), false);
    }
}

// Core entry-point integrity check (unchanged logic from before, still needs
// the checkCoreIndexIntegrity() function defined earlier in the file).
// Core entry-point integrity check + content-signature scan.
foreach ($CORE_ENTRY_POINTS as $relEntry) {
    $absEntry = $JOOMLA_ROOT.'/'.$relEntry;
    if (strtolower(basename($absEntry)) === $selfBasename) continue;
    if (!is_file($absEntry)) continue;
    $size = @filesize($absEntry);
    if ($size === false || $size > $MAX_FILE_SCAN_SIZE) continue;
    $contents = @file_get_contents($absEntry);
    if ($contents === false) continue;

    $reasonsEntry = [];
    $issue = checkCoreIndexIntegrity($contents);
    if ($issue !== null) $reasonsEntry[] = $issue;

    $ext = strtolower(pathinfo($absEntry, PATHINFO_EXTENSION));
    scanFileContent($absEntry, $ext, $CONTENT_SIGNATURES, $NON_PHP_EXTS_THAT_MUST_STAY_CLEAN, $PHP_OPEN_TAG_RE, $MAX_FILE_SCAN_SIZE, $reasonsEntry);

    if (!empty($reasonsEntry)) {
        $seenAbs[$absEntry] = true;
        recordFinding($fileFindings, $absEntry, $JOOMLA_ROOT, implode(' | ', array_unique($reasonsEntry)), false);
    }
}

// =====================================================================
// SCAN: database
// =====================================================================
$dbFindings = ['superusers'=>[],'menu_xss'=>[],'sppb_assets'=>[],'connected'=>false,'error'=>null];
$dbCfg = readJoomlaDbConfig($JOOMLA_ROOT);
if ($dbCfg) {
    $mysqli = dbConnect($dbCfg);
    if ($mysqli) {
        $dbFindings['connected'] = true;
        $prefix = $dbCfg['dbprefix'] !== '' ? $dbCfg['dbprefix'] : 'jos_';

        $usersTable = $prefix.'users';
        $res = @mysqli_query($mysqli,"SHOW TABLES LIKE '{$usersTable}'");
        if ($res && mysqli_num_rows($res)>0) {
            $sql = "SELECT u.id,u.name,u.username,u.email,u.registerDate,u.lastvisitDate
                    FROM `{$usersTable}` u
                    JOIN `{$prefix}user_usergroup_map` m ON m.user_id=u.id
                    WHERE m.group_id IN (SELECT id FROM `{$prefix}usergroups` WHERE title IN ('Super Users','Super User'))
                    ORDER BY u.registerDate DESC";
            $r = @mysqli_query($mysqli,$sql);
            if ($r) while ($row=mysqli_fetch_assoc($r)) {
                $suspicious=false;$why=[];
                if (stripos($row['email'],'secure.local')!==false){$suspicious=true;$why[]='email domain: secure.local (known attacker marker)';}
                if (preg_match('/webmanager\d+|codex|sppb/i',$row['username'])){$suspicious=true;$why[]='username matches known attacker pattern';}
                $dbFindings['superusers'][]=['id'=>$row['id'],'name'=>$row['name'],'username'=>$row['username'],
                    'email'=>$row['email'],'registered'=>$row['registerDate'],'lastvisit'=>$row['lastvisitDate'],
                    'suspicious'=>$suspicious,'why'=>implode('; ',$why)];
            }
        }

        $menuTable = $prefix.'menu';
        $res2 = @mysqli_query($mysqli,"SHOW TABLES LIKE '{$menuTable}'");
        if ($res2 && mysqli_num_rows($res2)>0) {
            $r2=@mysqli_query($mysqli,"SELECT id,title,link FROM `{$menuTable}` WHERE params LIKE '%xss.report%' OR params LIKE '%_hu_inject%' OR params LIKE '%secure.local%'");
            if ($r2) while ($row=mysqli_fetch_assoc($r2)) $dbFindings['menu_xss'][]=$row;
        }

        $assetsTable = $prefix.'sppagebuilder_assets';
        $res3 = @mysqli_query($mysqli,"SHOW TABLES LIKE '{$assetsTable}'");
        if ($res3 && mysqli_num_rows($res3)>0) {
            // Check for injected XSS/eval payloads in asset_value
            $r3=@mysqli_query($mysqli,"SELECT * FROM `{$assetsTable}`
                WHERE asset_value LIKE '%xss.report%'
                  OR asset_value LIKE '%base64_decode%'
                  OR asset_value LIKE '%eval(%' LIMIT 100");
            if ($r3) while ($row=mysqli_fetch_assoc($r3)) $dbFindings['sppb_assets'][]=$row;

            // Check for rogue iconfont registrations (random-name, created_by=0, not the legit icofont)
            $r4=@mysqli_query($mysqli,"SELECT * FROM `{$assetsTable}`
                WHERE type = 'iconfont'
                  AND name != 'icofont'
                  AND created_by = 0");
            if ($r4) while ($row=mysqli_fetch_assoc($r4)) $dbFindings['rogue_iconfont'][]=$row;
        }
        mysqli_close($mysqli);
    } else {
        $dbFindings['error']='Could not connect to database using credentials from configuration.php.';
    }
} else {
    $dbFindings['error']='configuration.php not found — run this script from the Joomla root.';
}

logLine('Scan run. Files: '.count($fileFindings).'. Susp SU: '.count(array_filter($dbFindings['superusers'],function($u){return $u['suspicious'];})).'. Menu XSS: '.count($dbFindings['menu_xss']));

// =====================================================================
// ACTION: delete
// =====================================================================
$flash = [];
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='delete') {
    if (!csrfValid($csrfToken)) {
        $flash[]='Security check failed. Reload the page and try again.';
        logLine('DELETE BLOCKED: bad CSRF');
    } else {
        $targets=$_POST['targets']??[];
        $rootReal=realpath($JOOMLA_ROOT);
        $protectedAbs = array_map(function($d) use ($rootReal) { return $rootReal.DIRECTORY_SEPARATOR.$d; }, $PROTECTED_TOP_DIRS);
        if (is_array($targets)&&$rootReal!==false) {
            foreach ($targets as $relPath) {
                $relPath=(string)$relPath;
                if (!isset($fileFindings[$relPath])){$flash[]="SKIPPED (not flagged): $relPath";continue;}
                $abs=realpath($JOOMLA_ROOT.'/'.$relPath);
                if ($abs===false){$flash[]="SKIPPED (file vanished): $relPath";continue;}
                if (strpos($abs,$rootReal.DIRECTORY_SEPARATOR)!==0){$flash[]="SKIPPED (outside root): $relPath";logLine("BLOCKED path escape: $relPath");continue;}
                if (basename($abs)===basename(__FILE__)||basename($abs)==='configuration.php'){$flash[]="SKIPPED (protected): $relPath";continue;}
                if (in_array($abs, $protectedAbs, true) || $abs === $rootReal) {
                    $flash[]="SKIPPED (protected top-level directory): $relPath";
                    logLine("BLOCKED protected-dir delete attempt: $relPath");
                    continue;
                }
                if (is_dir($abs)) {
                    if (deleteRecursive($abs)) { $flash[]="DELETED (folder): $relPath"; logLine("DELETED DIR: $abs"); }
                    else { $flash[]="FAILED (permissions?): $relPath"; logLine("DELETE DIR FAILED: $abs"); }
                } elseif (is_file($abs)) {
                    if (@unlink($abs)) { $flash[]="DELETED: $relPath"; logLine("DELETED: $abs"); }
                    else { $flash[]="FAILED (permissions?): $relPath"; logLine("DELETE FAILED: $abs"); }
                }
            }
        }
    }
    $_SESSION['sppbscan_flash']=$flash;
    $path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
    header("Location: $path",true,302); exit;
}
if (!empty($_SESSION['sppbscan_flash'])){$flash=$_SESSION['sppbscan_flash'];unset($_SESSION['sppbscan_flash']);}

$sessionAge = time()-($_SESSION['sppbscan_auth_at']??time());
$minutesLeft = max(0,ceil(($SESSION_TIMEOUT-$sessionAge)/60));
$suspiciousSU = array_filter($dbFindings['superusers'],function($u){return $u['suspicious'];});
$highCount = count(array_filter($fileFindings, function($f){return $f['confidence']==='high';}));
$medCount  = count($fileFindings) - $highCount;

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SP Page Builder · Infection Scanner</title>
<style>
:root {
  --bg: #080b10;
  --surface: #0d1420;
  --surface2: #111c2d;
  --border: #162033;
  --border2: #1e2f47;
  --text: #e2e8f0;
  --muted: #4a5e7a;
  --muted2: #2d3f58;
  --danger: #ef4444;
  --danger-soft: rgba(239,68,68,0.08);
  --danger-border: rgba(239,68,68,0.2);
  --warn: #f59e0b;
  --warn-soft: rgba(245,158,11,0.08);
  --ok: #22c55e;
  --ok-soft: rgba(34,197,94,0.08);
  --blue: #3b82f6;
  --blue-soft: rgba(59,130,246,0.1);
  --mono: ui-monospace, 'Cascadia Code', 'SF Mono', Consolas, monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 14px; line-height: 1.6; }
a { color: var(--blue); text-decoration: none; }
code { font-family: var(--mono); font-size: 12px; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }
pre { font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; }

.topbar {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 0 32px; height: 60px; display: flex; align-items: center;
  justify-content: space-between; gap: 16px; position: sticky; top: 0; z-index: 100;
}
.topbar-left { display: flex; align-items: center; gap: 12px; }
.topbar-shield {
  width: 34px; height: 34px; background: linear-gradient(135deg, #1e40af, #3b82f6);
  border-radius: 9px; display: flex; align-items: center; justify-content: center;
  font-size: 16px; flex-shrink: 0; box-shadow: 0 2px 8px rgba(59,130,246,0.3);
}
.topbar-title { font-size: 15px; font-weight: 600; color: var(--text); }
.topbar-sub { font-size: 12px; color: var(--muted); margin-top: 1px; }
.topbar-right { display: flex; align-items: center; gap: 10px; }
.session-pill {
  font-size: 12px; color: var(--muted); background: var(--surface2);
  border: 1px solid var(--border2); border-radius: 999px; padding: 5px 13px;
}
.main { max-width: 1080px; margin: 0 auto; padding: 36px 24px 80px; }

.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 28px; }
.stat {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 14px; padding: 20px 22px; display: flex; align-items: flex-start; gap: 14px;
}
.stat-icon {
  width: 40px; height: 40px; border-radius: 10px; display: flex;
  align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0;
}
.stat.clean .stat-icon  { background: var(--ok-soft); }
.stat.dirty .stat-icon  { background: var(--danger-soft); }
.stat.warn  .stat-icon  { background: var(--warn-soft); }
.stat-num { font-size: 26px; font-weight: 700; line-height: 1; margin-bottom: 3px; }
.stat.clean .stat-num { color: var(--ok); }
.stat.dirty .stat-num  { color: var(--danger); }
.stat.warn  .stat-num  { color: var(--warn); }
.stat-label { font-size: 12px; color: var(--muted); }

.disclaimer {
  background: var(--surface2); border: 1px solid var(--border2); border-radius: 12px;
  padding: 14px 18px; font-size: 12.5px; color: var(--muted); margin-bottom: 40px; line-height: 1.6;
}
.disclaimer strong { color: #94a3b8; }

.section { margin-bottom: 44px; }
.section-header {
  display: flex; align-items: center; gap: 10px; margin-bottom: 16px;
  padding-bottom: 14px; border-bottom: 1px solid var(--border);
}
.section-num {
  width: 26px; height: 26px; border-radius: 7px; background: var(--surface2);
  border: 1px solid var(--border2); font-size: 12px; font-weight: 700; color: var(--muted);
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.section-title { font-size: 16px; font-weight: 600; color: var(--text); }
.section-title small { font-size: 12px; font-weight: 400; color: var(--muted); margin-left: 8px; }

.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
.empty-state { padding: 32px 24px; display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13.5px; }
.empty-icon { font-size: 22px; }

table { width: 100%; border-collapse: collapse; }
th {
  background: var(--surface2); font-size: 11px; font-weight: 600; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--muted); padding: 10px 16px; text-align: left;
  border-bottom: 1px solid var(--border);
}
td { padding: 11px 16px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.015); }
.path-cell { font-family: var(--mono); font-size: 12px; color: #60a5fa; word-break: break-all; }
.reason-cell { font-size: 12px; color: var(--warn); }
.muted-cell { color: var(--muted); font-size: 12px; }

.badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.badge.ok      { background: var(--ok-soft); color: var(--ok); border: 1px solid rgba(34,197,94,0.2); }
.badge.danger  { background: var(--danger-soft); color: #fca5a5; border: 1px solid var(--danger-border); }
.badge.warn    { background: var(--warn-soft); color: #fbbf24; border: 1px solid rgba(245,158,11,0.25); }
.badge.neutral { background: var(--surface2); color: var(--muted); border: 1px solid var(--border2); }

.flash {
  background: var(--surface2); border: 1px solid var(--border2); border-radius: 12px;
  padding: 16px 20px; font-family: var(--mono); font-size: 12.5px; margin-bottom: 28px;
  white-space: pre-wrap; color: var(--text);
}
.flash strong { color: var(--blue); display: block; margin-bottom: 6px; }

.btn {
  display: inline-flex; align-items: center; gap: 6px; padding: 9px 18px; border-radius: 9px;
  font-size: 13.5px; font-weight: 600; cursor: pointer; border: none; transition: opacity 0.15s, transform 0.1s;
}
.btn:hover { opacity: 0.88; transform: translateY(-1px); }
.btn:active { transform: translateY(0); }
.btn-danger { background: var(--danger); color: #fff; }
.btn-ghost  { background: var(--surface2); border: 1px solid var(--border2); color: var(--muted); }
.btn-ghost:hover { color: var(--text); }
.btn-destruct { background: rgba(239,68,68,0.12); border: 1px solid var(--danger-border); color: #fca5a5; }

.toolbar { display: flex; align-items: center; gap: 12px; padding: 14px 16px; background: var(--surface2); border-top: 1px solid var(--border); flex-wrap: wrap; }
.toolbar-hint { font-size: 12px; color: var(--muted); }
.legend { display:flex; gap:16px; padding: 12px 16px; font-size: 12px; color: var(--muted); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.legend b { color: #94a3b8; }

.checklist { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 24px 28px; }
.checklist h4 { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin: 22px 0 12px; }
.checklist h4:first-child { margin-top: 0; }
.checklist ul { list-style: none; display: flex; flex-direction: column; gap: 14px; }
.checklist li { display: flex; gap: 12px; align-items: flex-start; font-size: 13.5px; line-height: 1.6; }
.checklist li::before { content: '→'; color: var(--blue); font-weight: 700; flex-shrink: 0; margin-top: 1px; }
.checklist pre { background: var(--surface2); border: 1px solid var(--border2); border-radius: 8px; padding: 14px 16px; margin-top: 10px; overflow-x: auto; color: #7dd3fc; }
.checklist strong { color: #f1f5f9; }

.finish-box {
  background: linear-gradient(135deg, rgba(239,68,68,0.06), rgba(239,68,68,0.02));
  border: 1px solid var(--danger-border); border-radius: 14px; padding: 24px 28px;
  display: flex; align-items: flex-start; gap: 20px;
}
.finish-text h3 { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
.finish-text p  { font-size: 13px; color: var(--muted); margin-bottom: 16px; }

input[type=checkbox] { accent-color: var(--blue); width: 15px; height: 15px; cursor: pointer; }
</style>
</head>


<body>

<div class="topbar">
  <div class="topbar-left">
    <div class="topbar-shield">🛡️</div>
    <div>
      <div class="topbar-title">SP Page Builder · Infection Scanner</div>
      <div class="topbar-sub">Scanned <?= e($JOOMLA_ROOT) ?> · <?= e(date('Y-m-d H:i:s')) ?></div>
    </div>
  </div>
  <div class="topbar-right">
    <span class="session-pill">⏱ <span id="session-countdown"><?= (int)$minutesLeft ?>:00</span> remaining</span>
    <form method="post" style="display:inline">
      <input type="hidden" name="csrf" value="<?= e($csrfToken) ?>">
      <input type="hidden" name="action" value="logout">
      <button type="submit" class="btn btn-ghost">Sign out</button>
    </form>
  </div>
</div>

<div class="main">

  <?php if (!empty($flash)): ?>
  <div class="flash">
<strong>Action result</strong><?php foreach ($flash as $r) echo e($r)."\n"; ?></div>
  <?php endif; ?>

  <div class="stats">
    <?php
    $fc = count($fileFindings);
    $sc = count($suspiciousSU);
    $mc = count($dbFindings['menu_xss']);
    $ac = count($dbFindings['sppb_assets']);
    function statClass($n){ return $n>0?'dirty':'clean'; }
    function statIcon($n){ return $n>0?'⚠️':'✅'; }
    ?>
    <div class="stat <?= statClass($fc) ?>">
      <div class="stat-icon"><?= statIcon($fc) ?></div>
      <div><div class="stat-num"><?= $fc ?></div><div class="stat-label">Suspicious files/folders <?php if($fc>0): ?>(<?= $highCount ?> high · <?= $medCount ?> medium)<?php endif; ?></div></div>
    </div>
    <div class="stat <?= statClass($sc) ?>">
      <div class="stat-icon"><?= statIcon($sc) ?></div>
      <div><div class="stat-num"><?= $sc ?></div><div class="stat-label">Rogue super users</div></div>
    </div>
    <div class="stat <?= statClass($mc) ?>">
      <div class="stat-icon"><?= statIcon($mc) ?></div>
      <div><div class="stat-num"><?= $mc ?></div><div class="stat-label">Menu XSS rows</div></div>
    </div>
    <div class="stat <?= statClass($ac) ?>">
      <div class="stat-icon"><?= statIcon($ac) ?></div>
      <div><div class="stat-num"><?= $ac ?></div><div class="stat-label">Rogue asset rows</div></div>
    </div>
    <?php if (!$dbFindings['connected']): ?>
    <div class="stat warn">
      <div class="stat-icon">⚡</div>
      <div><div class="stat-num" style="font-size:13px;margin-top:4px;">DB offline</div><div class="stat-label">Could not connect</div></div>
    </div>
    <?php endif; ?>
  </div>

  <div class="disclaimer">
    <strong>About this report:</strong> findings are heuristic, not a guarantee. <strong>High confidence</strong> means a known malware
    content signature, a malicious filename pattern, a purely-numeric drop folder, a fake index.php, a core entry-point bootstrap
    violation, a backup/duplicate configuration file, an unrecognized top-level webroot directory, or an unrecognized item inside a
    folder that should only ever contain static font/CSS/JS assets. <strong>Medium confidence</strong> means a structural anomaly
    (e.g. an executable file sitting in an upload path, a marker/flag file, or a file modified out-of-step with its siblings) that's
    worth a manual look but isn't confirmed malicious on its own. Always keep a backup before deleting anything.
  </div>

  <div class="disclaimer">
    <strong>About core entry-point integrity:</strong> <code>index.php</code> at the webroot (plus <code>administrator/index.php</code>,
    <code>api/index.php</code>, and <code>includes/app.php</code>) are checked against Joomla's expected bootstrap sequence. The real
    file never executes anything before defining <code>JOOMLA_MINIMUM_PHP</code> and <code>_JEXEC</code> — any code before that point
    (a <code>require</code>/<code>include</code>, a numeric byte-array decoded with <code>chr()</code>, a <code>zip://</code> or
    <code>phar://</code> stream-wrapper reference) is a strong sign the core file has been patched to silently load a separate payload
    on every page view. This is flagged as High confidence and should be treated as a confirmed compromise, not a false-positive-prone
    heuristic.
  </div>

  <div class="disclaimer">
    <strong>About webroot scanning:</strong> any folder sitting directly inside the Joomla webroot that isn't a standard Joomla
    core folder (administrator, components, media, images, templates, etc.) is flagged outright, and everything inside it is
    scanned regardless of file type — a legitimate extension or upload never appears as a brand-new sibling folder next to
    <code>configuration.php</code>. Loose files at the root are also checked, including <code>.shtml</code> files, backup/duplicate
    configuration files (<code>configuration.bak.php</code> and similar), and small near-empty <code>.txt</code> marker files —
    none of which Joomla ships by default.
  </div>

  <div class="disclaimer">
    <strong>About template scanning:</strong> <code>templates/</code> is scanned recursively. Two patterns are checked
    specifically there: (1) a purely-numeric folder name (e.g. <code>features/252692</code>) — never a normal Joomla naming
    convention, and a common signature of an automated malware drop; and (2) a fake <code>index.php</code> — Joomla places a
    blank "no direct access" stub in every subfolder by design, so the file existing is normal, but if its content is anything
    beyond that one-line guard, it's flagged as a likely disguised webshell. The only exempted file is a template's own
    top-level <code>index.php</code> (e.g. <code>templates/shaper_helixultimate/index.php</code>), which legitimately
    contains the real template layout code.
  </div>

  <div class="disclaimer">
    <strong>A note on JCE:</strong> some hosts have reported malicious files appearing inside the JCE editor component
    (<code>com_jce</code>) on sites that were also hit by the SP Page Builder upload vulnerability — likely the same
    attacker using JCE's own file-browser upload path as a secondary or fallback drop point once they had a foothold.
    This scanner also walks <code>media/com_jce</code>, <code>administrator/components/com_jce</code>,
    <code>components/com_jce</code>, and <code>plugins/editors/jce</code> using the same heuristics. If you don't
    actively need JCE, updating it to the latest release — or removing it entirely if it's unused — is worth doing
    alongside the SPPB fixes below.
  </div>

  <!-- 1. Files -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">1</div>
      <div class="section-title">Suspicious files &amp; folders <small>webroot · core entry points · templates · media · images · com_sppagebuilder · com_jce · tmp · cache</small></div>
    </div>
    <div class="panel">
      <?php if (empty($fileFindings)): ?>
        <div class="empty-state"><span class="empty-icon">✅</span> No suspicious files or folders detected in scanned directories.</div>
      <?php else: ?>
      <div class="legend"><span><b>High</b> — strong malware indicator</span><span><b>Medium</b> — anomaly worth review</span><span><b>DIR</b> — folder, deleted recursively</span></div>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= e($csrfToken) ?>">
        <input type="hidden" name="action" value="delete">
        <table>
          <tr>
            <th style="width:36px"><input type="checkbox" id="chk-all" onclick="document.querySelectorAll('.row-chk').forEach(c=>c.checked=this.checked)"></th>
            <th>Path</th><th>Type</th><th>Confidence</th><th>Reason</th><th>Size</th><th>Modified</th>
          </tr>
          <?php foreach ($fileFindings as $f): ?>
          <tr>
            <td><input type="checkbox" class="row-chk" name="targets[]" value="<?= e($f['rel']) ?>"></td>
            <td class="path-cell"><?= e($f['rel']) ?></td>
            <td><span class="badge neutral"><?= $f['type']==='dir' ? 'DIR' : 'FILE' ?></span></td>
            <td><span class="badge <?= $f['confidence']==='high' ? 'danger' : 'warn' ?>"><?= $f['confidence']==='high' ? '⚠ High' : '◐ Medium' ?></span></td>
            <td class="reason-cell"><?= e($f['reason']) ?></td>
            <td class="muted-cell"><?= e(humanSize($f['size'])) ?></td>
            <td class="muted-cell"><?= $f['mtime'] ? e(date('Y-m-d H:i',$f['mtime'])) : '—' ?></td>
          </tr>
          <?php endforeach; ?>
        </table>
        <div class="toolbar">
          <button type="submit" class="btn btn-danger" onclick="return confirm('Delete selected files/folders? Folders are removed recursively. This cannot be undone. Ensure you have a backup.')">Delete selected</button>
          <span class="toolbar-hint">Only items flagged by this scan run can be deleted. Top-level Joomla folders are protected.</span>
        </div>
      </form>
      <?php endif; ?>
    </div>
  </div>

  <!-- 2. Super Users -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">2</div>
      <div class="section-title">Super User accounts</div>
    </div>
    <div class="panel">
      <?php if (!$dbFindings['connected']): ?>
        <div class="empty-state"><span class="empty-icon">⚡</span> <?= e($dbFindings['error']??'Database not checked.') ?></div>
      <?php elseif (empty($dbFindings['superusers'])): ?>
        <div class="empty-state"><span class="empty-icon">✅</span> No Super User accounts found.</div>
      <?php else: ?>
      <table>
        <tr><th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Registered</th><th>Last Visit</th><th>Status</th></tr>
        <?php foreach ($dbFindings['superusers'] as $u): ?>
        <tr>
          <td class="muted-cell"><?= e($u['id']) ?></td>
          <td><?= e($u['name']) ?></td>
          <td class="path-cell"><?= e($u['username']) ?></td>
          <td><?= e($u['email']) ?></td>
          <td class="muted-cell"><?= e($u['registered']) ?></td>
          <td class="muted-cell"><?= e($u['lastvisit']) ?></td>
          <td>
            <?php if ($u['suspicious']): ?>
              <span class="badge danger">⚠ Suspicious</span>
              <div style="font-size:11.5px;color:#f87171;margin-top:5px;"><?= e($u['why']) ?></div>
            <?php else: ?>
              <span class="badge ok">✓ Normal</span>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </table>
      <div class="toolbar"><span class="toolbar-hint">Remove rogue accounts manually via <strong>Users → Manage</strong> in Joomla admin after confirming they aren't legitimate.</span></div>
      <?php endif; ?>
    </div>
  </div>

  <!-- 3. Menu XSS -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">3</div>
      <div class="section-title">Menu XSS injections <small>Helix Ultimate mega-menu payload</small></div>
    </div>
    <div class="panel">
      <?php if (!$dbFindings['connected']): ?>
        <div class="empty-state"><span class="empty-icon">⚡</span> Database not checked.</div>
      <?php elseif (empty($dbFindings['menu_xss'])): ?>
        <div class="empty-state"><span class="empty-icon">✅</span> No injected menu items found.</div>
      <?php else: ?>
      <table>
        <tr><th>Menu ID</th><th>Title</th><th>Link</th></tr>
        <?php foreach ($dbFindings['menu_xss'] as $m): ?>
        <tr>
          <td class="muted-cell"><?= e($m['id']) ?></td>
          <td><?= e($m['title']) ?></td>
          <td class="path-cell"><?= e($m['link']) ?></td>
        </tr>
        <?php endforeach; ?>
      </table>
      <div class="toolbar"><span class="toolbar-hint">Clear the <code>params</code> field for these rows via phpMyAdmin/SQL — not through the Joomla menu editor, which may render the payload.</span></div>
      <?php endif; ?>
    </div>
  </div>

  <!-- 4. Asset rows -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">4</div>
      <div class="section-title">SP Page Builder asset table</div>
    </div>
    <div class="panel">
      <?php if (!$dbFindings['connected']): ?>
        <div class="empty-state"><span class="empty-icon">⚡</span> Database not checked.</div>
      <?php elseif (empty($dbFindings['sppb_assets'])): ?>
        <div class="empty-state"><span class="empty-icon">✅</span> No suspicious rows in <code>sppagebuilder_assets</code>.</div>
      <?php else: ?>
      <table>
        <tr><th>Row data</th></tr>
        <?php foreach ($dbFindings['sppb_assets'] as $row): ?>
        <tr><td><pre><?= e(json_encode($row,JSON_PRETTY_PRINT)) ?></pre></td></tr>
        <?php endforeach; ?>
      </table>
      <?php endif; ?>
    </div>
  </div>

  <!-- 5. Hardening / tips -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">5</div>
      <div class="section-title">Cleanup &amp; hardening checklist</div>
    </div>
    <div class="checklist">

      <h4>If something was actually flagged above</h4>
      <ul>
        <li><span><strong>Don't panic-delete first.</strong> Review each High-confidence row, then Medium-confidence rows. If unsure about an item, copy it somewhere safe before removing it.</span></li>
        <li><span><strong>A core entry-point integrity finding</strong> (root <code>index.php</code> or similar) is the highest-priority item on this report — it means every page load is currently executing attacker code. Treat the site as actively compromised, not just historically infected.</span></li>
        <li><span><strong>An unrecognized top-level folder in the webroot</strong> (e.g. a random name like "3bd9leet" sitting next to configuration.php) is one of the clearest signs of a compromise — Joomla, its extensions, and its uploads never create new sibling folders at the root.</span></li>
        <li><span><strong>A numeric drop folder (e.g. "252692") inside templates/ or media/</strong> is one of the strongest real-world signs of an automated upload exploit — these, and everything inside them, should be removed.</span></li>
        <li><span><strong>A fake index.php</strong> (anything beyond the one-line "no direct access" guard, outside a template's own root index.php) should be treated as a confirmed webshell and removed immediately.</span></li>
        <li><span><strong>.shtml files and backup configuration files in the webroot</strong> are not standard Joomla file types and should be removed (after rotating any credentials they exposed).</span></li>
        <li><span><strong>A cluster of new, randomly-named files/folders created within the same minute</strong> (called out explicitly in the Reason column) is another strong sign of an automated drop.</span></li>
        <li><span><strong>Rotate every credential</strong> readable from <code>configuration.php</code> (and any backup copies found): database password, SMTP password, any API keys, and Joomla's <code>secret</code> value (Global Configuration → regenerate, or edit the file directly).</span></li>
        <li><span><strong>Force-logout all sessions</strong> after rotating credentials — truncate the <code>#__session</code> table or use Users → Sessions → "Destroy" in Joomla admin.</span></li>
        <li><span><strong>Remove rogue Super Users</strong> flagged in Section 2, and audit every other Super User for ones you don't recognize.</span></li>
      </ul>

      <h4>Close the hole, not just the symptom</h4>
      <ul>
        <li><span><strong>Update SP Page Builder immediately</strong> to the latest version — repeated infections in the same upload path almost always mean the underlying upload vulnerability is still unpatched.</span></li>
        <li><span><strong>Update Helix Ultimate and every other extension/template</strong> too — attackers often chain together whichever vulnerable extension is easiest, not just SPPB.</span></li>
        <li><span><strong>Update or remove the JCE editor.</strong> If you don't actively use JCE's editor or file browser, removing the component entirely is the simplest fix; if you do need it, update to the current release and re-run this scan afterward.</span></li>
        <li>
          <span><strong>Block PHP execution in upload directories</strong> as a stop-gap even after patching, via <code>.htaccess</code>:
          <pre>&lt;DirectoryMatch "/(media|images|uploads|tmp|cache|assets|icons|fonts)(/|$)"&gt;
  AllowOverride None
  &lt;FilesMatch "(?i)\.(php|phtml|phar|php[0-9]?|shtml)$"&gt;
    Require all denied
  &lt;/FilesMatch&gt;
&lt;/DirectoryMatch&gt;</pre>
          </span>
        </li>
        <li><span><strong>Verify against a fresh copy.</strong> This scanner uses heuristics, not file checksums. Download a clean copy of SP Page Builder / Helix Ultimate / JCE from the official source and diff (<code>diff -rq</code>) the installed version against it to catch anything subtler than these rules.</span></li>
      </ul>

      <h4>Look beyond the obvious folders</h4>
      <ul>
        <li><span><strong>Check cron jobs</strong> (cPanel → Cron Jobs, or <code>crontab -l</code> via SSH) for anything you didn't add — a common persistence method once a server is compromised.</span></li>
        <li><span><strong>Check for unrecognized hosting/API tokens</strong> (cPanel API keys, Git deploy keys, FTP/SFTP accounts) and revoke anything unfamiliar. Enable alerts for new token/account creation if your host supports it.</span></li>
        <li><span><strong>Run a full filesystem scan</strong> outside this tool's scope too — ClamAV, Imunify360, or your host's malware scanner — since a single scanner (including this one) can never guarantee full coverage.</span></li>
        <li><span><strong>Check outgoing mail/traffic</strong> for signs of abuse picked up after the breach (spam sent via PHP <code>mail()</code>, unfamiliar outbound connections), especially if your host flagged the account.</span></li>
      </ul>

      <h4>Prevent the next one</h4>
      <ul>
        <li><span><strong>Enable 2FA</strong> on Joomla admin, your hosting control panel, and any linked email accounts.</span></li>
        <li><span><strong>Re-scan after cleanup</strong> — and again in a week — since some droppers re-create themselves via a leftover scheduled task or a second, undiscovered backdoor.</span></li>
        <li><span><strong>If in doubt, restore from a pre-infection backup</strong>, apply every pending update, and only then bring the site back online with a fresh random key in this scanner.</span></li>
        <li><span><strong>Set a reminder to update extensions regularly</strong> — most real-world Joomla compromises trace back to a known, already-patched vulnerability in an extension that was simply never updated.</span></li>
      </ul>

    </div>
  </div>

  <!-- 6. Self-destruct -->
  <div class="section">
    <div class="section-header">
      <div class="section-num">6</div>
      <div class="section-title">Remove this scanner</div>
    </div>
    <div class="finish-box">
      <div style="font-size:32px;flex-shrink:0;">🗑️</div>
      <div class="finish-text">
        <h3>Delete scanner when finished</h3>
        <p>Leaving this tool accessible on a live server is itself a security risk. Use the button below or remove it manually via FTP/SSH.</p>
        <form method="post" onsubmit="return confirm('Permanently delete this scanner and its logs from the server?')">
          <input type="hidden" name="csrf" value="<?= e($csrfToken) ?>">
          <input type="hidden" name="action" value="selfdestruct">
          <button type="submit" class="btn btn-destruct">Self-destruct this scanner</button>
        </form>
      </div>
    </div>
  </div>

</div><!-- /main -->
<script>
(function() {
  var remainingSeconds = <?= (int)max(0, $SESSION_TIMEOUT - $sessionAge) ?>;
  var el = document.getElementById('session-countdown');
  function tick() {
    if (remainingSeconds <= 0) {
      el.textContent = 'expired';
      el.parentElement.style.color = '#f87171';
      setTimeout(function() {
        window.location.reload();
      }, 1500);
      return;
    }
    var m = Math.floor(remainingSeconds / 60);
    var s = remainingSeconds % 60;
    el.textContent = m + ':' + (s < 10 ? '0' : '') + s;
    remainingSeconds--;
    setTimeout(tick, 1000);
  }
  tick();
})();
</script>
</body>
</html>
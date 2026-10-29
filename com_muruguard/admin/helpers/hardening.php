<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * MuRu Shield Hardening — server-level (.htaccess) hardening, distinct
 * from Protection Mode (plg_muruguardshield), which operates at the PHP
 * layer instead. First capability: an HTTP Basic Auth gate in front of
 * /administrator (and, once that's verified working, optionally the
 * whole site via Emergency Mode) — blocking brute-force login attempts
 * before Joomla's own bootstrap even runs, not just after.
 *
 * Every write here follows the same discipline: back up whatever .htaccess
 * already existed, write the new managed block, then SELF-TEST it with a
 * real outbound request using the exact new credentials before treating
 * it as active. Any failure rolls back immediately. This is the single
 * most important property of this file -- getting Basic Auth wrong locks
 * the site owner out of their own admin panel, which is categorically
 * worse than any finding this scanner detects, so nothing here is ever
 * allowed to "probably work."
 */

defined('_JEXEC') or die;

class MuruguardHardeningHelper
{
    private const BACKEND_BEGIN = '# BEGIN MuRu Shield Hardening -- Backend Access';
    private const BACKEND_END   = '# END MuRu Shield Hardening -- Backend Access';
    private const EMERGENCY_BEGIN = '# BEGIN MuRu Shield Hardening -- Emergency Lockdown';
    private const EMERGENCY_END   = '# END MuRu Shield Hardening -- Emergency Lockdown';
    private const UPLOADLOCK_BEGIN = '# BEGIN MuRu Guard -- Upload Lockdown';
    private const UPLOADLOCK_END   = '# END MuRu Guard -- Upload Lockdown';

    /** Excludes visually-similar characters (0/O, 1/I/l) and the colon (.htpasswd's own field separator) -- same rationale as license key generation elsewhere in this codebase. */
    public static function generateSecurePassword(int $length = 20): string
    {
        $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%^&*-_=+';
        $max = strlen($alphabet) - 1;
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[random_int(0, $max)];
        }
        return $out;
    }

    private static function htaccessPath(string $dir): string
    {
        return rtrim($dir, '/') . '/.htaccess';
    }

    /** Copies the current .htaccess to a timestamped backup before any write -- '' (not null) means "there was nothing to back up," which is a valid, common starting state, not a failure. Returns null only on an actual copy failure. */
    private static function backupHtaccess(string $htaccessPath): ?string
    {
        if (!is_file($htaccessPath)) return '';
        $backupPath = $htaccessPath . '.muru-backup-' . date('Ymd-His');
        return @copy($htaccessPath, $backupPath) ? $backupPath : null;
    }

    private static function stripManagedBlock(string $contents, string $beginMarker, string $endMarker): string
    {
        $pattern = '/\R?' . preg_quote($beginMarker, '/') . '.*?' . preg_quote($endMarker, '/') . '\R?/s';
        $result = preg_replace($pattern, "\n", $contents);
        return $result ?? $contents;
    }

    private static function buildBackendAuthBlock(string $htpasswdAbsPath): string
    {
        $quoted = str_replace('"', '\\"', $htpasswdAbsPath);
        return self::BACKEND_BEGIN . "\n"
            . "<IfModule mod_auth_basic.c>\n"
            . "    AuthType Basic\n"
            . "    AuthName \"Restricted Area\"\n"
            . "    AuthUserFile \"{$quoted}\"\n"
            . "    Require valid-user\n"
            . "</IfModule>\n"
            . "<Files \".htpasswd\">\n"
            . "    Require all denied\n"
            . "</Files>\n"
            . self::BACKEND_END . "\n";
    }

    private static function buildEmergencyBlock(string $htpasswdAbsPath): string
    {
        $quoted = str_replace('"', '\\"', $htpasswdAbsPath);
        return self::EMERGENCY_BEGIN . "\n"
            . "<IfModule mod_auth_basic.c>\n"
            . "    AuthType Basic\n"
            . "    AuthName \"Site Temporarily Locked\"\n"
            . "    AuthUserFile \"{$quoted}\"\n"
            . "    Require valid-user\n"
            . "</IfModule>\n"
            . self::EMERGENCY_END . "\n";
    }

    public static function writeHtpasswd(string $path, string $username, string $password): bool
    {
        $hash = password_hash($password, PASSWORD_BCRYPT);
        if ($hash === false) return false;
        return @file_put_contents($path, $username . ':' . $hash . "\n") !== false;
    }

    /**
     * Confirms $password matches what's already active in $adminDir's
     * .htpasswd -- the plaintext password is deliberately never
     * persisted anywhere once backend auth is activated (see
     * MuruguardModelScanner::activateBackendAuth()'s docblock), so
     * Emergency Mode (which reuses those same credentials rather than
     * minting new ones) needs the admin to re-supply it, and this is
     * what confirms they typed the CURRENT one rather than writing an
     * Emergency Mode block pointed at a password nobody actually knows.
     */
    public static function verifyBackendPassword(string $adminDir, string $username, string $password): bool
    {
        $path = rtrim($adminDir, '/') . '/.htpasswd';
        if (!is_file($path)) return false;
        $line = trim((string) @file_get_contents($path));
        [$storedUser, $hash] = array_pad(explode(':', $line, 2), 2, '');
        if (!hash_equals($storedUser, $username)) return false;
        return $hash !== '' && password_verify($password, $hash);
    }

    /**
     * Merges the managed block into $dir/.htaccess (replacing a
     * previous run of this same block if present, leaving everything
     * else in the file untouched), backing up whatever was there first.
     * Returns the backup path ('' if there was nothing to back up), or
     * null on write failure.
     */
    private static function writeManagedBlock(string $dir, string $block, string $beginMarker, string $endMarker): ?string
    {
        $path = self::htaccessPath($dir);
        $existing = is_file($path) ? (string) @file_get_contents($path) : '';
        $backupPath = self::backupHtaccess($path);
        if ($backupPath === null) return null;

        $stripped = $existing !== '' ? self::stripManagedBlock($existing, $beginMarker, $endMarker) : '';
        $new = ltrim(rtrim($stripped) . "\n\n" . $block, "\n");
        if (@file_put_contents($path, $new) === false) return null;
        return $backupPath;
    }

    /** Restores $dir/.htaccess from a backup path previously returned by writeManagedBlock() -- '' means "delete the file, there wasn't one before." */
    private static function restoreFromBackup(string $dir, string $backupPath): void
    {
        $path = self::htaccessPath($dir);
        if ($backupPath === '') {
            @unlink($path);
            return;
        }
        if (is_file($backupPath)) {
            @copy($backupPath, $path);
        }
    }

    /**
     * The safety net this whole feature depends on: makes TWO real
     * outbound requests to $testUrl -- one with no credentials (MUST be
     * rejected with 401, otherwise the "protection" is a no-op) and one
     * with the exact new credentials (MUST NOT be rejected, otherwise
     * the admin would be locked out the moment they try to log in).
     * Fails CLOSED: if the probe request itself can't be completed at
     * all (no outbound HTTP capability, DNS/firewall issue, the site
     * can't reach itself), this reports failure rather than trusting an
     * unverified config -- "couldn't verify" and "verified broken" get
     * the same rollback treatment, on purpose.
     */
    public static function selfTestBasicAuth(string $testUrl, string $username, string $password): array
    {
        $unauth = self::probeHttpStatus($testUrl, null, null);
        if ($unauth === null) {
            return ['ok' => false, 'reason' => 'Could not reach the site from itself to verify (outbound HTTP may be disabled on this host). Refusing to activate rather than risk an unverified lock-out.'];
        }
        if ($unauth['status'] !== 401) {
            // Naming the actual web server (from its own response header,
            // when it sends one) turns "here are 3 possibilities, ask your
            // host" into a near-certain answer for the most common case --
            // Nginx/LiteSpeed-non-Apache-mode never reads .htaccess at
            // all, so seeing that in the Server header is close to
            // conclusive on its own.
            $serverNote = '';
            if ($unauth['server'] !== null) {
                $server = $unauth['server'];
                if (stripos($server, 'nginx') !== false) {
                    $serverNote = " Your server identifies itself as \"{$server}\" -- Nginx does not read .htaccess files at all, which is almost certainly why this didn't take effect. This feature requires Apache (or LiteSpeed running in Apache-compatible mode).";
                } elseif (stripos($server, 'litespeed') !== false) {
                    $serverNote = " Your server identifies itself as \"{$server}\" -- LiteSpeed only reads .htaccess when running in Apache-compatible mode; check with your host whether that's enabled.";
                } else {
                    $serverNote = " Your server identifies itself as \"{$server}\".";
                }
            }
            if ($unauth['status'] >= 300 && $unauth['status'] < 400) {
                $locationNote = $unauth['location'] !== null ? " (to {$unauth['location']})" : '';
                return ['ok' => false, 'reason' => "The unauthenticated verification request was redirected ({$unauth['status']}{$locationNote}) instead of being rejected with 401 -- something (a caching layer, a security plugin, or a forced host/protocol redirect) is intercepting the request before .htaccess's Basic Auth gets a chance to run.{$serverNote} Nothing was changed."];
            }
            return ['ok' => false, 'reason' => "An unauthenticated request should have been rejected with 401 but got {$unauth['status']} instead -- .htaccess isn't enforcing Basic Auth here.{$serverNote} This almost always means one of: (1) the site runs on Nginx or another server that doesn't read .htaccess at all -- this feature only works on Apache or LiteSpeed in Apache-compatible mode; (2) the host has \"AllowOverride None\" (or excludes AuthConfig) for administrator/, so .htaccess is being ignored entirely; (3) the mod_auth_basic Apache module isn't enabled. Check with your host which of these applies -- nothing was changed."];
        }

        $auth = self::probeHttpStatus($testUrl, $username, $password);
        if ($auth === null || $auth['status'] === 401) {
            return ['ok' => false, 'reason' => 'The correct new credentials were still rejected. Refusing to activate to avoid locking you out.'];
        }

        return ['ok' => true, 'reason' => ''];
    }

    /** @return array{status:int,server:?string,location:?string}|null */
    private static function probeHttpStatus(string $url, ?string $username, ?string $password): ?array
    {
        $headers = "Connection: close\r\n";
        if ($username !== null) {
            $headers .= 'Authorization: Basic ' . base64_encode($username . ':' . (string) $password) . "\r\n";
        }
        $context = stream_context_create([
            'http' => [
                'method'          => 'GET',
                'header'          => $headers,
                'timeout'         => 8,
                'ignore_errors'   => true,
                'follow_location' => 0,
            ],
            // This request only ever targets the site's OWN domain to
            // read back an HTTP status code for its own self-test -- not
            // a third party, and not carrying any sensitive payload --
            // so a staging/self-signed cert on that same site can't
            // block hardening from ever being verifiable.
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false || !isset($http_response_header)) return null;
        $status = null;
        $server = null;
        $location = null;
        foreach ($http_response_header as $line) {
            if ($status === null && preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
            } elseif (preg_match('#^Server:\s*(.+)$#i', $line, $m)) {
                $server = trim($m[1]);
            } elseif (preg_match('#^Location:\s*(.+)$#i', $line, $m)) {
                $location = trim($m[1]);
            }
        }
        if ($status === null) return null;
        return ['status' => $status, 'server' => $server, 'location' => $location];
    }

    /**
     * Full activate flow for backend (/administrator) Basic Auth.
     * Returns ['ok' => bool, 'reason' => string, 'password' => string|null].
     * $password is only ever returned on success, purely so the caller
     * can hand it back to the browser ONE time for the admin to save --
     * it is never persisted in plaintext anywhere (see writeHtpasswd()).
     */
    public static function activateBackendAuth(string $adminDir, string $testUrl, string $username, string $password): array
    {
        if (!is_writable($adminDir)) {
            return ['ok' => false, 'reason' => 'The administrator/ folder is not writable by PHP -- fix folder permissions and try again.'];
        }

        $htpasswdPath = rtrim($adminDir, '/') . '/.htpasswd';
        if (!self::writeHtpasswd($htpasswdPath, $username, $password)) {
            return ['ok' => false, 'reason' => 'Failed to write .htpasswd.'];
        }

        $block = self::buildBackendAuthBlock($htpasswdPath);
        $backupPath = self::writeManagedBlock($adminDir, $block, self::BACKEND_BEGIN, self::BACKEND_END);
        if ($backupPath === null) {
            @unlink($htpasswdPath);
            return ['ok' => false, 'reason' => 'Failed to write administrator/.htaccess.'];
        }

        $test = self::selfTestBasicAuth($testUrl, $username, $password);
        if (!$test['ok']) {
            self::restoreFromBackup($adminDir, $backupPath);
            @unlink($htpasswdPath);
            return ['ok' => false, 'reason' => $test['reason']];
        }

        return ['ok' => true, 'reason' => '', 'password' => $password, 'backupPath' => $backupPath];
    }

    public static function deactivateBackendAuth(string $adminDir): void
    {
        $path = self::htaccessPath($adminDir);
        if (is_file($path)) {
            $contents = (string) @file_get_contents($path);
            $stripped = self::stripManagedBlock($contents, self::BACKEND_BEGIN, self::BACKEND_END);
            if (trim($stripped) === '') {
                @unlink($path);
            } else {
                @file_put_contents($path, $stripped);
            }
        }
        @unlink(rtrim($adminDir, '/') . '/.htpasswd');
    }

    /**
     * Emergency Mode extends the SAME backend credentials to the site
     * root -- deliberately reuses the already-verified .htpasswd rather
     * than generating new credentials, so there is only ever one
     * password to remember, and self-tests against the homepage instead
     * of /administrator.
     */
    public static function activateEmergencyMode(string $siteRoot, string $adminDir, string $testUrl, string $username, string $password): array
    {
        if (!is_writable($siteRoot)) {
            return ['ok' => false, 'reason' => 'The site root is not writable by PHP -- fix folder permissions and try again.'];
        }

        $htpasswdPath = rtrim($adminDir, '/') . '/.htpasswd';
        if (!is_file($htpasswdPath)) {
            return ['ok' => false, 'reason' => 'Backend access protection must be active first -- Emergency Mode reuses those same credentials.'];
        }

        $block = self::buildEmergencyBlock($htpasswdPath);
        $backupPath = self::writeManagedBlock($siteRoot, $block, self::EMERGENCY_BEGIN, self::EMERGENCY_END);
        if ($backupPath === null) {
            return ['ok' => false, 'reason' => 'Failed to write the site root .htaccess.'];
        }

        $test = self::selfTestBasicAuth($testUrl, $username, $password);
        if (!$test['ok']) {
            self::restoreFromBackup($siteRoot, $backupPath);
            return ['ok' => false, 'reason' => $test['reason']];
        }

        return ['ok' => true, 'reason' => '', 'backupPath' => $backupPath];
    }

    public static function deactivateEmergencyMode(string $siteRoot): void
    {
        $path = self::htaccessPath($siteRoot);
        if (!is_file($path)) return;
        $contents = (string) @file_get_contents($path);
        $stripped = self::stripManagedBlock($contents, self::EMERGENCY_BEGIN, self::EMERGENCY_END);
        if (trim($stripped) === '') {
            @unlink($path);
        } else {
            @file_put_contents($path, $stripped);
        }
    }

    /**
     * Uninstall cleanup: removes every access-restricting block this
     * component wrote (Emergency Mode, Upload lockdown, Backend Access)
     * -- each only when its own marker is present, so a site owner's
     * unrelated .htaccess or .htpasswd is never touched. Returns the
     * labels of the blocks that were removed.
     */
    public static function removeAccessBlocksForUninstall(string $siteRoot, string $adminDir): array
    {
        $has = static function (string $dir, string $marker): bool {
            $path = self::htaccessPath($dir);
            return is_file($path) && strpos((string) @file_get_contents($path), $marker) !== false;
        };

        $removed = [];
        // Emergency Mode first: its root block points at the backend .htpasswd.
        if ($has($siteRoot, self::EMERGENCY_BEGIN)) { self::deactivateEmergencyMode($siteRoot); $removed[] = 'Emergency Mode'; }
        if ($has($siteRoot, self::UPLOADLOCK_BEGIN)) { self::deactivateUploadLock($siteRoot); $removed[] = 'Upload lockdown'; }
        if ($has($adminDir, self::BACKEND_BEGIN)) { self::deactivateBackendAuth($adminDir); $removed[] = 'Backend Access'; }
        return $removed;
    }

    // ------------------------------------------------------------------
    // Upload lockdown -- a temporary switch that refuses every request
    // carrying multipart/form-data (file uploads and many forms) at the
    // web server, before PHP or Joomla run. For the hours after a new
    // upload vulnerability is published, before the fixed version is
    // installed. The block goes at the TOP of .htaccess so it runs before
    // Joomla's own rewrite rules. Applying it is self-tested (homepage
    // still answers, a multipart POST is really refused) and rolled back
    // on any doubt, the same fail-closed discipline as the writers above.
    // ------------------------------------------------------------------

    /** Managed block text -- public so the UI can show exactly what is written. */
    public static function buildUploadLockBlock(bool $includeAdmin = false): string
    {
        $out = self::UPLOADLOCK_BEGIN . "\n"
            . "# Temporary: refuses every request that carries multipart/form-data\n"
            . "# (file uploads and many forms). Managed by MuRu Guard -- switch it off\n"
            . "# in MuRu Guard > Settings > Site Protection, not by hand.\n"
            . "<IfModule mod_rewrite.c>\n"
            . "RewriteEngine On\n";
        if (!$includeAdmin) {
            $out .= "RewriteCond %{REQUEST_URI} !(^|/)administrator/ [NC]\n";
        }
        $out .= "RewriteCond %{HTTP:Content-Type} multipart/form-data [NC]\n"
            . "RewriteRule ^ - [F,L]\n"
            . "</IfModule>\n"
            . self::UPLOADLOCK_END . "\n";

        return $out;
    }

    /** Nginx equivalent for hosts that never read .htaccess -- shown in the UI. $includeAdmin = the backend is blocked too. */
    public static function getNginxUploadLockSnippet(bool $includeAdmin = false): string
    {
        $out = "# MuRu Guard -- upload lockdown (nginx equivalent). Temporary.\n"
            . "# Add inside your site's `server { }` block, above the PHP location, and reload nginx.\n";
        $out .= $includeAdmin
            ? "# The backend is blocked too: saving backend forms stops working until you remove this.\n"
            : "# Joomla's backend forms are multipart too, so the backend is left out here as well.\n";
        $out .= 'set $muru_block_multipart "";' . "\n"
            . 'if ($content_type ~* "multipart/form-data") { set $muru_block_multipart "1"; }' . "\n";
        if (!$includeAdmin) {
            $out .= 'if ($request_uri ~* "(^|/)administrator/") { set $muru_block_multipart ""; }' . "\n";
        }
        return $out . 'if ($muru_block_multipart) { return 403; }' . "\n";
    }

    public static function isUploadLockActive(string $siteRoot): bool
    {
        $path = self::htaccessPath($siteRoot);
        if (!is_file($path)) return false;

        return strpos((string) @file_get_contents($path), self::UPLOADLOCK_BEGIN) !== false;
    }

    private static function uploadLockStateFilePath(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/uploadlock-state.php';
    }

    /** @return array{since:int,expiresAt:int,includeAdmin:bool}|null */
    public static function loadUploadLockState(): ?array
    {
        $path = self::uploadLockStateFilePath();
        if (!is_file($path)) return null;
        $d = json_decode(\MuruguardHelper::stripDataFileStub((string) @file_get_contents($path)), true);
        if (!is_array($d) || !isset($d['since'])) return null;

        return ['since' => (int) $d['since'], 'expiresAt' => (int) ($d['expiresAt'] ?? 0), 'includeAdmin' => !empty($d['includeAdmin'])];
    }

    private static function saveUploadLockState(?array $state): void
    {
        $path = self::uploadLockStateFilePath();
        if ($state === null) {
            @unlink($path);
            return;
        }
        \MuruguardHelper::writeDataFile($path, $state);
    }

    /** True when an expiry was set (not 0 = "until I turn it off") and it has passed. Pure. */
    public static function uploadLockIsDue(?array $state, int $now): bool
    {
        return $state !== null && (int) $state['expiresAt'] > 0 && $now >= (int) $state['expiresAt'];
    }

    /** Stub-protected copy of the current .htaccess in the component's data folder (never in the webroot). Returns the file name, or null on failure. */
    private static function backupHtaccessToDataDir(string $contents, string $tag): ?string
    {
        $backupDir = JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/htaccess-backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
        }
        @file_put_contents($backupDir . '/index.html', '<html><body></body></html>');
        $name = date('Ymd-His') . '-' . $tag . '-' . substr(md5($tag . microtime()), 0, 6) . '.php';
        $ok = @file_put_contents($backupDir . '/' . $name, \MuruguardHelper::dataFileStubPrefix() . $contents);
        return $ok !== false ? $name : null;
    }

    /** One real multipart POST to $url; returns the HTTP status, or null when the request could not be made. */
    private static function probeMultipartPost(string $url): ?int
    {
        $boundary = 'muruguard' . bin2hex(random_bytes(6));
        $body = "--{$boundary}\r\nContent-Disposition: form-data; name=\"muruguard_probe\"\r\n\r\n1\r\n--{$boundary}--\r\n";
        $context = stream_context_create([
            'http' => [
                'method'          => 'POST',
                'header'          => "Content-Type: multipart/form-data; boundary={$boundary}\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n",
                'content'         => $body,
                'timeout'         => 8,
                'ignore_errors'   => true,
                'follow_location' => 0,
            ],
            // Same reasoning as probeHttpStatus(): only the site's own domain.
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $response = @file_get_contents($url, false, $context);
        $headers = $http_response_header ?? [];
        if ($response === false && $headers === []) return null;
        if (isset($headers[0]) && preg_match('#HTTP/\S+\s+(\d{3})#', (string) $headers[0], $m)) return (int) $m[1];

        return null;
    }

    /**
     * Applies the lockdown. $hours 0 = until switched off. Returns ['ok' => bool, 'reason' => string].
     * Refuses on Nginx, without a writable .htaccess, or when the self-test fails (rolled back).
     */
    public static function activateUploadLock(string $siteRoot, string $baseUrl, int $hours, bool $includeAdmin): array
    {
        $path = self::htaccessPath($siteRoot);
        if (is_file($path) && !is_writable($path)) {
            return ['ok' => false, 'reason' => 'The webroot .htaccess is not writable by PHP -- fix file permissions and try again.'];
        }
        if (!is_file($path) && !is_writable($siteRoot)) {
            return ['ok' => false, 'reason' => 'The site root is not writable by PHP -- fix folder permissions and try again.'];
        }

        $base = rtrim($baseUrl, '/');
        // Baseline: a homepage that already answers an error (no home page set, maintenance) must not be blamed on the lock.
        $before = self::probeHttpStatus($base . '/', null, null);
        $beforeStatus = $before === null ? null : (int) $before['status'];
        $existing = is_file($path) ? (string) @file_get_contents($path) : '';
        if (self::backupHtaccessToDataDir($existing, 'uploadlock') === null) {
            return ['ok' => false, 'reason' => 'Could not back up the current .htaccess -- refusing to write without a backup.'];
        }
        $stripped = $existing !== '' ? ltrim(self::stripManagedBlock($existing, self::UPLOADLOCK_BEGIN, self::UPLOADLOCK_END), "\n") : '';
        $new = self::buildUploadLockBlock($includeAdmin) . ($stripped !== '' ? "\n" . $stripped : '');
        if (@file_put_contents($path, $new) === false) {
            return ['ok' => false, 'reason' => 'Failed to write the webroot .htaccess.'];
        }
        $rollback = function () use ($path, $existing): void {
            if ($existing === '') {
                @unlink($path);
            } else {
                @file_put_contents($path, $existing);
            }
        };

        $home = self::probeHttpStatus($base . '/', null, null);
        $brokeIt = $home === null || (int) $home['status'] >= 500
            || ($beforeStatus !== null && $beforeStatus < 400 && (int) $home['status'] >= 400);
        if ($brokeIt) {
            $rollback();
            $got = $home === null ? 'unreachable' : ('HTTP ' . $home['status']);
            return ['ok' => false, 'reason' => "Applied, but the homepage came back {$got} afterward -- rolled back automatically. Nothing was left broken."];
        }
        $server = (string) ($home['server'] ?? '');
        if (stripos($server, 'nginx') !== false) {
            $rollback();
            return ['ok' => false, 'reason' => "Your server identifies itself as \"{$server}\" -- Nginx does not read .htaccess files, so this lock could never take effect. Use the nginx snippet shown below instead. Nothing was changed."];
        }
        $status = self::probeMultipartPost($base . '/');
        if ($status !== 403) {
            $rollback();
            $got = $status === null ? 'no answer' : 'HTTP ' . $status;
            return ['ok' => false, 'reason' => "Applied, but a test upload was not refused ({$got}) -- the rule is not taking effect. This almost always means the host has \"AllowOverride None\" for the webroot or mod_rewrite is off -- check with your host. Nothing was changed."];
        }

        $now = time();
        self::saveUploadLockState(['since' => $now, 'expiresAt' => $hours > 0 ? $now + $hours * 3600 : 0, 'includeAdmin' => $includeAdmin]);

        return ['ok' => true, 'reason' => 'Upload lockdown is on and verified: a test upload was refused.'];
    }

    public static function deactivateUploadLock(string $siteRoot): void
    {
        $path = self::htaccessPath($siteRoot);
        if (is_file($path)) {
            $contents = (string) @file_get_contents($path);
            if (strpos($contents, self::UPLOADLOCK_BEGIN) !== false) {
                self::backupHtaccessToDataDir($contents, 'uploadlock-remove');
                $stripped = self::stripManagedBlock($contents, self::UPLOADLOCK_BEGIN, self::UPLOADLOCK_END);
                if (trim($stripped) === '') {
                    @unlink($path);
                } else {
                    @file_put_contents($path, ltrim($stripped, "\n"));
                }
            }
        }
        self::saveUploadLockState(null);
    }

    /**
     * Called by the scheduled check and when Settings opens: switches the lock off when its time is up, and
     * forgets a state file whose block is gone. Returns the current state (null = off).
     */
    public static function maintainUploadLock(string $siteRoot, ?int $now = null): ?array
    {
        $state = self::loadUploadLockState();
        $active = self::isUploadLockActive($siteRoot);
        if ($state !== null && !$active) {
            self::saveUploadLockState(null);
            return null;
        }
        if ($state === null && $active) {
            // Block present without a record (state file lost): keep it visible, with no expiry.
            return ['since' => 0, 'expiresAt' => 0, 'includeAdmin' => false];
        }
        if (self::uploadLockIsDue($state, $now ?? time())) {
            self::deactivateUploadLock($siteRoot);
            return null;
        }

        return $state;
    }
}

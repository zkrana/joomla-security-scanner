<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
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
}

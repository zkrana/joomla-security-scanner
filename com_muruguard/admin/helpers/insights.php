<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Dashboard insights -- read-only facts about the site that need no scan:
 * PHP and Joomla support status (with the PHP2Shell notice), a 0-100
 * security score with an A-F grade, Super User basics, the most important
 * Global Configuration settings, sensitive files left in the webroot, a
 * 24-hour / 7-day summary of what the Shield blocked, and the Joomla
 * Security Centre news feed.
 *
 * Everything here only reports. Nothing is changed on the site, and every
 * network fetch (php.net, joomla.org) is cached for hours and fails open:
 * an unreachable source just means that card stays empty.
 */

defined('_JEXEC') or die;

class MuruguardInsights
{
    // ------------------------------------------------------------------
    // PHP
    // ------------------------------------------------------------------

    /**
     * PHP2Shell (CVE-2026-109618, CVE-2026-109619, October 2026): remote
     * code execution in PHP's own request parsing, before Joomla runs, so
     * no extension can block it. Fixed in these releases; branches older
     * than 8.2 only get distribution backports.
     */
    public const PHP2SHELL_FIXED = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];

    /** End of security support per PHP branch (Dec 31 of that year). */
    public const PHP_SECURITY_EOL = [
        '7.4' => '2022-11-28', '8.0' => '2023-11-26',
        '8.1' => '2025-12-31', '8.2' => '2026-12-31', '8.3' => '2027-12-31', '8.4' => '2028-12-31',
    ];

    private const PHP_RELEASES_URL = 'https://www.php.net/releases/index.php?json&version=%s&max=40';
    private const PHP_RELEASES_MAX_AGE = 86400;
    private const FETCH_MAX_BYTES = 1048576;

    /** 'fixed', 'vulnerable' (a supported branch below its fix), 'eol' (8.1 or older: needs a vendor backport) or 'unknown'. */
    public static function php2shellStatus(string $phpVersion): string
    {
        if (!preg_match('/^(\d+)\.(\d+)\.(\d+)/', $phpVersion, $m)) return 'unknown';
        $branch = $m[1] . '.' . $m[2];
        $plain = $m[1] . '.' . $m[2] . '.' . $m[3];
        if (isset(self::PHP2SHELL_FIXED[$branch])) {
            return version_compare($plain, self::PHP2SHELL_FIXED[$branch], '>=') ? 'fixed' : 'vulnerable';
        }
        return version_compare($branch, '8.5', '>') ? 'fixed' : 'eol';
    }

    /** "8.3.12-1ubuntu" -> "8.3.12"; "" when there is no x.y.z to read. */
    public static function phpVersionTriple(string $phpVersion): string
    {
        return preg_match('/^(\d+\.\d+\.\d+)/', $phpVersion, $m) ? $m[1] : '';
    }

    /** 'eol', 'ok', 'current' (newer than the table) or 'unknown'. */
    public static function phpSupportStatus(string $phpVersion, int $now): string
    {
        if (!preg_match('/^(\d+)\.(\d+)/', $phpVersion, $m)) return 'unknown';
        $branch = $m[1] . '.' . $m[2];
        if (isset(self::PHP_SECURITY_EOL[$branch])) {
            return $now > strtotime(self::PHP_SECURITY_EOL[$branch] . ' 23:59:59 UTC') ? 'eol' : 'ok';
        }
        return version_compare($branch, '8.4', '>') ? 'current' : 'eol';
    }

    /** Reduces php.net's release JSON to [version => ['security' => bool, 'date' => string]]. */
    public static function shapePhpReleases(array $payload): array
    {
        $out = [];
        foreach ($payload as $version => $info) {
            if (!is_string($version) || !preg_match('/^\d+\.\d+\.\d+$/', $version) || !is_array($info)) continue;
            $tags = (isset($info['tags']) && is_array($info['tags'])) ? $info['tags'] : [];
            $out[$version] = ['security' => in_array('security', $tags, true), 'date' => (string) ($info['date'] ?? '')];
        }
        return $out;
    }

    /** Releases of one PHP branch ("8.3"), cached a day. Fails open: stale cache, then an empty list. */
    public static function fetchPhpReleases(string $minor): array
    {
        if (!preg_match('/^\d+\.\d+$/', $minor)) return [];
        $cache = self::readCache('phpreleases-cache.php');
        $entry = (isset($cache[$minor]) && is_array($cache[$minor])) ? $cache[$minor] : null;
        if ($entry !== null && (time() - (int) ($entry['fetchedAt'] ?? 0)) < self::PHP_RELEASES_MAX_AGE) {
            return (array) ($entry['releases'] ?? []);
        }

        $body = self::httpGet(sprintf(self::PHP_RELEASES_URL, rawurlencode($minor)));
        $data = $body === null ? null : json_decode($body, true);
        $shaped = is_array($data) ? self::shapePhpReleases($data) : [];
        if ($shaped === []) return $entry !== null ? (array) ($entry['releases'] ?? []) : [];

        $cache[$minor] = ['fetchedAt' => time(), 'releases' => $shaped];
        self::writeCache('phpreleases-cache.php', $cache);
        return $shaped;
    }

    /**
     * Banner state for the Dashboard, or null when there is nothing to say.
     * 'high': newer releases of this branch carry security fixes.
     * 'medium': the branch is past its security-support date.
     *
     * @return array{level:string,installed:string,latest:string,missed:int,eol:bool,php2shell:string}|null
     */
    public static function phpBannerState(string $phpVersion, string $supportStatus, array $releases): ?array
    {
        $installed = self::phpVersionTriple($phpVersion);
        if ($installed === '') return null;
        $missed = 0;
        $latest = $installed;
        foreach ($releases as $version => $info) {
            $version = (string) $version;
            if (version_compare($version, $latest, '>')) $latest = $version;
            if (!empty($info['security']) && version_compare($version, $installed, '>')) $missed++;
        }
        $php2shell = self::php2shellStatus($phpVersion);
        $eol = $supportStatus === 'eol';
        if ($missed === 0 && !$eol && $php2shell !== 'vulnerable') return null;

        return [
            'level'     => ($missed > 0 || $php2shell === 'vulnerable') ? 'high' : 'medium',
            'installed' => $installed,
            'latest'    => $latest,
            'missed'    => $missed,
            'eol'       => $eol,
            'php2shell' => $php2shell,
        ];
    }

    // ------------------------------------------------------------------
    // Joomla
    // ------------------------------------------------------------------

    /**
     * Joomla core support. $latest is the newest core version Joomla's own
     * updater has seen (null when it has not checked).
     *
     * @return array{status:string,installed:string,latest:?string}
     */
    public static function joomlaStatus(string $installed, ?string $latest): array
    {
        $out = ['status' => 'unknown', 'installed' => $installed, 'latest' => $latest];
        if (!preg_match('/^(\d+)\./', $installed, $m)) return $out;
        // Joomla 3 ended in August 2023 and Joomla 4 in October 2025: no more security fixes.
        if ((int) $m[1] <= 4) {
            $out['status'] = 'eol';
        } elseif ($latest !== null && version_compare($latest, $installed, '>')) {
            $out['status'] = 'update';
        } elseif ($latest !== null) {
            $out['status'] = 'current';
        }
        return $out;
    }

    // ------------------------------------------------------------------
    // Global Configuration (the five settings that matter most)
    // ------------------------------------------------------------------

    /**
     * @param array<string,mixed> $config Global Configuration values (debug, error_reporting, force_ssl, sef, ftp_enable).
     * @return list<array{id:string,label:string,ok:bool,value:string,advice:string}>
     */
    public static function configChecks(array $config, bool $isHttps): array
    {
        $rows = [];
        $debug = !empty($config['debug']);
        $rows[] = ['id' => 'debug', 'label' => 'Debug System', 'ok' => !$debug, 'value' => $debug ? 'On' : 'Off',
            'advice' => 'Shows database queries and file paths to visitors. Switch it off in System > Global Configuration > System.'];

        $er = strtolower((string) ($config['error_reporting'] ?? 'default'));
        $erBad = in_array($er, ['maximum', 'development'], true);
        $rows[] = ['id' => 'error_reporting', 'label' => 'Error Reporting', 'ok' => !$erBad, 'value' => $er === '' ? 'default' : $er,
            'advice' => 'Full error output reveals paths and code to anyone. Set it to "System Default" or "None" in Global Configuration > Server.'];

        $forceSsl = (int) ($config['force_ssl'] ?? 0);
        $rows[] = ['id' => 'force_ssl', 'label' => 'Force HTTPS', 'ok' => !$isHttps || $forceSsl === 2,
            'value' => $forceSsl === 2 ? 'Entire Site' : ($forceSsl === 1 ? 'Administrator Only' : 'None'),
            'advice' => 'The site answers over HTTPS but does not force it, so logins can still be sent in plain text. Set Force HTTPS to "Entire Site" in Global Configuration > Server.'];

        $sef = !empty($config['sef']);
        $rows[] = ['id' => 'sef', 'label' => 'Search Engine Friendly URLs', 'ok' => $sef, 'value' => $sef ? 'On' : 'Off',
            'advice' => 'Plain index.php?option=... URLs advertise which components are installed to automated scanners. Switch SEF URLs on in Global Configuration > Site.'];

        // FTP layer exists on Joomla 3 only.
        if (array_key_exists('ftp_enable', $config)) {
            $ftp = !empty($config['ftp_enable']);
            $rows[] = ['id' => 'ftp', 'label' => 'FTP Layer', 'ok' => !$ftp, 'value' => $ftp ? 'On' : 'Off',
                'advice' => 'Stores FTP credentials in configuration.php. Switch the FTP layer off unless your host truly needs it.'];
        }
        return $rows;
    }

    // ------------------------------------------------------------------
    // Super Users
    // ------------------------------------------------------------------

    /**
     * @param list<array{id:int,username:string,lastvisitDate:?string,block:int}> $superUsers
     * @return list<array{id:string,ok:bool,text:string}>
     */
    public static function adminChecks(array $superUsers): array
    {
        $active = array_values(array_filter($superUsers, fn($u) => empty($u['block'])));
        $rows = [];
        $count = count($active);
        $rows[] = ['id' => 'count', 'ok' => $count <= 3,
            'text' => $count <= 3
                ? "{$count} active Super User account" . ($count === 1 ? '' : 's') . '.'
                : "{$count} active Super User accounts. Each one is a full key to the site: keep only the people who need it."];

        $named = array_values(array_filter($active, fn($u) => in_array(strtolower((string) $u['username']), ['admin', 'administrator', 'root', 'superuser'], true)));
        $rows[] = ['id' => 'name', 'ok' => $named === [],
            'text' => $named === []
                ? 'No Super User uses a guessable name such as "admin".'
                : 'Super User "' . $named[0]['username'] . '" uses a name every password-guessing bot tries first. Rename it in Users > Manage.'];

        $never = array_values(array_filter($active, fn($u) => self::neverVisited($u['lastvisitDate'] ?? null)));
        $rows[] = ['id' => 'never', 'ok' => $never === [],
            'text' => $never === []
                ? 'Every Super User has logged in at least once.'
                : count($never) . ' Super User account' . (count($never) === 1 ? ' has' : 's have') . ' never logged in (' . implode(', ', array_map(fn($u) => $u['username'], array_slice($never, 0, 3))) . '). An unused admin account nobody watches is a common backdoor: check it is expected.'];
        return $rows;
    }

    private static function neverVisited(?string $date): bool
    {
        return $date === null || $date === '' || strpos($date, '0000-00-00') === 0;
    }

    // ------------------------------------------------------------------
    // Sensitive files left in the webroot (report only)
    // ------------------------------------------------------------------

    private const EXPOSED_ROOT_FILES = [
        'phpinfo.php' => 'Shows the full server configuration to anyone.',
        'info.php' => 'Usually a phpinfo() page that shows the full server configuration.',
        '.env' => 'Environment file that often holds passwords and API keys.',
        'configuration.php.bak' => 'Copy of configuration.php: database password readable as plain text.',
        'configuration.php.old' => 'Copy of configuration.php: database password readable as plain text.',
        'configuration.php.save' => 'Copy of configuration.php: database password readable as plain text.',
        'configuration.php.orig' => 'Copy of configuration.php: database password readable as plain text.',
        'configuration.php~' => 'Editor backup of configuration.php: database password readable as plain text.',
        'configuration.bak' => 'Copy of configuration.php: database password readable as plain text.',
        'configuration.txt' => 'Copy of configuration.php: database password readable as plain text.',
        'error_log' => 'PHP error log: shows file paths and sometimes queries.',
        'php_errors.log' => 'PHP error log: shows file paths and sometimes queries.',
    ];

    private const EXPOSED_ROOT_DIRS = [
        '.git' => 'Git repository: the whole source history, sometimes with passwords, can be downloaded.',
        '.svn' => 'Subversion folder: source history can be downloaded.',
    ];

    /** @return list<array{path:string,why:string}> */
    public static function findExposedFiles(string $root): array
    {
        $root = rtrim($root, '/');
        $found = [];
        foreach (self::EXPOSED_ROOT_FILES as $name => $why) {
            if (is_file($root . '/' . $name)) $found[] = ['path' => $name, 'why' => $why];
        }
        foreach (self::EXPOSED_ROOT_DIRS as $name => $why) {
            if (is_dir($root . '/' . $name)) $found[] = ['path' => $name . '/', 'why' => $why];
        }
        // Database dumps and site archives straight in the webroot.
        foreach ((array) @scandir($root) as $item) {
            if (!is_string($item) || $item === '' || $item[0] === '.' || !is_file($root . '/' . $item)) continue;
            if (preg_match('/\.(?:sql|sql\.gz|sql\.zip)$/i', $item)) {
                $found[] = ['path' => $item, 'why' => 'Database dump: every user, password hash and setting can be downloaded.'];
            } elseif (preg_match('/\.(?:zip|tar|tar\.gz|tgz|jpa|jps|rar|7z)$/i', $item)) {
                $found[] = ['path' => $item, 'why' => 'Archive in the webroot: if it is a site backup, it includes configuration.php.'];
            }
        }
        return array_slice($found, 0, 25);
    }

    // ------------------------------------------------------------------
    // Security score
    // ------------------------------------------------------------------

    /**
     * @param array<string,mixed> $signals
     * @return array{score:int,grade:string,label:string,issues:list<string>}
     */
    public static function computeSecurityScore(array $signals): array
    {
        $score = 100;
        $issues = [];

        if (empty($signals['https'])) { $score -= 15; $issues[] = 'The site is not served over HTTPS.'; }
        if (empty($signals['shield_enabled'])) { $score -= 15; $issues[] = 'Protection Mode (Shield) is off.'; }
        if (empty($signals['backend_auth_enabled'])) { $score -= 5; $issues[] = 'The Backend Access password wall is off.'; }

        $htTotal = max(0, (int) ($signals['htaccess_checks_total'] ?? 0));
        $htPresent = max(0, (int) ($signals['htaccess_checks_present'] ?? 0));
        if ($htTotal > 0 && $htPresent < $htTotal) {
            $missing = $htTotal - $htPresent;
            $score -= min(15, $missing * 3);
            $issues[] = "{$missing} of {$htTotal} recommended .htaccess hardening rule" . ($missing === 1 ? ' is' : 's are') . ' missing.';
        }

        $vuln = max(0, (int) ($signals['vulnerable_extensions'] ?? 0));
        if ($vuln > 0) {
            $score -= min(25, $vuln * 10);
            $issues[] = "{$vuln} installed extension" . ($vuln === 1 ? ' has' : 's have') . ' a known published vulnerability.';
        }

        $joomla = (string) ($signals['joomla_status'] ?? '');
        if ($joomla === 'eol') { $score -= 15; $issues[] = 'This Joomla version no longer receives security fixes.'; }
        elseif ($joomla === 'update') { $score -= 10; $issues[] = 'A newer Joomla release is available.'; }

        if (!empty($signals['php_banner'])) { $score -= 10; $issues[] = 'PHP is behind on security fixes or past its support date.'; }

        $config = max(0, (int) ($signals['config_issues'] ?? 0));
        if ($config > 0) {
            $score -= min(12, $config * 3);
            $issues[] = "{$config} Global Configuration setting" . ($config === 1 ? ' needs' : 's need') . ' attention.';
        }
        $admins = max(0, (int) ($signals['admin_issues'] ?? 0));
        if ($admins > 0) {
            $score -= min(9, $admins * 3);
            $issues[] = "{$admins} Super User check" . ($admins === 1 ? '' : 's') . ' failed.';
        }
        $exposed = max(0, (int) ($signals['exposed_files'] ?? 0));
        if ($exposed > 0) {
            $score -= min(15, $exposed * 5);
            $issues[] = "{$exposed} sensitive file" . ($exposed === 1 ? ' is' : 's are') . ' left in the webroot.';
        }

        $findings = max(0, (int) ($signals['open_findings'] ?? 0));
        if ($findings > 0) {
            $score -= min(30, $findings * 5);
            $issues[] = "{$findings} unresolved scan finding" . ($findings === 1 ? '' : 's') . '.';
        }

        $score = max(0, min(100, $score));
        return [
            'score'  => $score,
            'grade'  => self::gradeFor($score),
            'label'  => $score >= 85 ? 'Good' : ($score >= 60 ? 'Needs attention' : 'At risk'),
            'issues' => $issues,
        ];
    }

    /** A familiar A to F letter for the 0-100 score. 90, 80, 70 and 60 are the cut-offs. */
    public static function gradeFor(int $score): string
    {
        if ($score >= 90) return 'A';
        if ($score >= 80) return 'B';
        if ($score >= 70) return 'C';
        if ($score >= 60) return 'D';
        return 'F';
    }

    // ------------------------------------------------------------------
    // Threat Monitor basics -- what the Shield logged in the last 24 hours
    // and 7 days, from the attack log the plugin already writes.
    // ------------------------------------------------------------------

    /**
     * @param list<array<string,mixed>> $entries attack-log entries (any order)
     * @return array{total:int,blocked:int,byType:array<string,int>,topIps:array<string,int>,topRules:array<string,int>}
     */
    public static function summarizeThreats(array $entries, int $since): array
    {
        $out = ['total' => 0, 'blocked' => 0, 'byType' => [], 'topIps' => [], 'topRules' => []];
        foreach ($entries as $e) {
            if (!is_array($e) || (int) ($e['time'] ?? 0) < $since) continue;
            $out['total']++;
            if (!empty($e['blocked'])) $out['blocked']++;
            $type = (string) ($e['type'] ?? 'other');
            $out['byType'][$type] = ($out['byType'][$type] ?? 0) + 1;
            $ip = (string) ($e['ip'] ?? '');
            if ($ip !== '') $out['topIps'][$ip] = ($out['topIps'][$ip] ?? 0) + 1;
            $rule = (string) ($e['rule'] ?? '');
            if ($rule !== '') $out['topRules'][$rule] = ($out['topRules'][$rule] ?? 0) + 1;
        }
        arsort($out['byType']);
        arsort($out['topIps']);
        arsort($out['topRules']);
        $out['topIps'] = array_slice($out['topIps'], 0, 5, true);
        $out['topRules'] = array_slice($out['topRules'], 0, 5, true);
        return $out;
    }

    // ------------------------------------------------------------------
    // Joomla Security Centre news
    // ------------------------------------------------------------------

    private const NEWS_URL = 'https://developer.joomla.org/security-centre.feed?type=rss';
    private const NEWS_MAX_AGE = 43200;

    /** @return list<array{title:string,link:string,date:int}> newest first, at most $max. */
    public static function fetchSecurityNews(int $max = 5): array
    {
        $cache = self::readCache('security-news-cache.php');
        $fresh = (time() - (int) ($cache['fetchedAt'] ?? 0)) < self::NEWS_MAX_AGE;
        if ($fresh && isset($cache['items']) && is_array($cache['items'])) {
            return array_slice($cache['items'], 0, $max);
        }

        $body = self::httpGet(self::NEWS_URL);
        $items = $body === null ? [] : self::parseNewsFeed($body);
        if ($items === []) {
            // Keep the old list (and don't retry on every page view for the next hour).
            $old = isset($cache['items']) && is_array($cache['items']) ? $cache['items'] : [];
            self::writeCache('security-news-cache.php', ['fetchedAt' => time() - self::NEWS_MAX_AGE + 3600, 'items' => $old]);
            return array_slice($old, 0, $max);
        }
        self::writeCache('security-news-cache.php', ['fetchedAt' => time(), 'items' => $items]);
        return array_slice($items, 0, $max);
    }

    /** RSS 2.0 items -> [title, link, date]. Only https links on joomla.org are kept. */
    public static function parseNewsFeed(string $xml): array
    {
        if (!function_exists('simplexml_load_string')) return [];
        $prev = libxml_use_internal_errors(true);
        $doc = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if ($doc === false || !isset($doc->channel->item)) return [];

        $items = [];
        foreach ($doc->channel->item as $item) {
            $title = trim(html_entity_decode(strip_tags((string) $item->title), ENT_QUOTES, 'UTF-8'));
            $link = trim((string) $item->link);
            if ($title === '' || !preg_match('#^https://(?:[a-z0-9-]+\.)*joomla\.org/#i', $link)) continue;
            $date = strtotime((string) $item->pubDate);
            $items[] = ['title' => mb_substr($title, 0, 200), 'link' => $link, 'date' => $date === false ? 0 : $date];
            if (count($items) >= 10) break;
        }
        usort($items, fn($a, $b) => $b['date'] <=> $a['date']);
        return $items;
    }

    // ------------------------------------------------------------------
    // Shared plumbing
    // ------------------------------------------------------------------

    private static function dataPath(string $file): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/' . $file;
    }

    private static function readCache(string $file): array
    {
        $path = self::dataPath($file);
        if (!is_file($path)) return [];
        $decoded = json_decode(\MuruguardHelper::stripDataFileStub((string) @file_get_contents($path)), true);
        return is_array($decoded) ? $decoded : [];
    }

    private static function writeCache(string $file, array $data): void
    {
        \MuruguardHelper::writeDataFile(self::dataPath($file), $data);
    }

    /** HTTPS GET with a short timeout and a size cap. Null on any failure. */
    private static function httpGet(string $url): ?string
    {
        try {
            $context = stream_context_create([
                'http' => ['timeout' => 4, 'ignore_errors' => false, 'header' => "User-Agent: MuRu-Guard\r\n"],
                'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);
            $body = @file_get_contents($url, false, $context, 0, self::FETCH_MAX_BYTES + 1);
            if ($body === false || $body === '' || strlen($body) > self::FETCH_MAX_BYTES) return null;
            return $body;
        } catch (\Throwable $e) {
            return null;
        }
    }
}

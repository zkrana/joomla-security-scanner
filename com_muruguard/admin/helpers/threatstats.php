<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Threat Monitor data layer.
 *
 * The attack log is a ring buffer (500 live entries plus a capped archive),
 * which suits a "what just happened" list but not a chart. This class keeps
 * a small aggregate next to it: hourly buckets for two days and daily
 * buckets for two weeks (enough for the 24-hour and 7-day views and the
 * window before each), written from the one place every blocked or
 * detected event already passes through (MuruguardHelper::recordAttackLogEntry()).
 *
 * Everything that decides something is a pure function on arrays, so it is
 * testable without Joomla. Only the load/save/record wrappers touch the
 * disk, and they never throw: statistics must not slow down or break a
 * request that is already being refused. Time is bucketed in UTC; maps
 * inside a bucket are capped and old buckets are pruned on every write.
 */

defined('_JEXEC') or die;

class MuruguardThreatStats
{
    public const HOURS_KEPT = 48;
    public const DAYS_KEPT  = 14;
    public const SEVERITIES = ['low', 'medium', 'high', 'critical'];

    /** Entry types that are attacks or refusals. */
    public const ATTACK_TYPES = ['request', 'upload', 'bruteforce', 'country', 'ip_list', 'admin_lockdown', 'recon'];

    private const CAP_RULES = 30;
    private const CAP_TYPES = 14;

    /** Periods the Threat Monitor offers. */
    public const PERIODS = [
        '24h' => ['hours' => 24,  'unit' => 'hour'],
        '7d'  => ['hours' => 168, 'unit' => 'day'],
    ];

    /** Scans kept for the score trend. */
    public const SCANS_KEPT = 5;

    public static function emptyState(int $now = 0): array
    {
        return ['first' => $now, 'bf' => false, 'hours' => [], 'days' => []];
    }

    /** True for an entry that belongs in the statistics at all. */
    public static function isCountable(array $entry): bool
    {
        return in_array((string) ($entry['type'] ?? ''), self::ATTACK_TYPES, true) && (int) ($entry['time'] ?? 0) > 0;
    }

    /** Severity of an entry on the four-level scale; anything unknown counts as low. */
    public static function severityOf(array $entry): string
    {
        $s = strtolower((string) ($entry['severity'] ?? ''));
        return in_array($s, self::SEVERITIES, true) ? $s : 'low';
    }

    private static function emptyHour(): array
    {
        return ['t' => 0, 'b' => 0, 's' => array_fill_keys(self::SEVERITIES, 0)];
    }

    private static function emptyDay(): array
    {
        return self::emptyHour() + ['r' => [], 'y' => [], 'lf' => 0];
    }

    /** Increments $map[$key]; when the map outgrows $cap the smallest other entry is dropped. */
    private static function bump(array &$map, string $key, int $cap): void
    {
        if ($key === '') return;
        $map[$key] = ($map[$key] ?? 0) + 1;
        if (count($map) > $cap) {
            $min = null;
            $minKey = null;
            foreach ($map as $k => $v) {
                if ((string) $k === $key) continue;
                if ($min === null || $v < $min) { $min = $v; $minKey = $k; }
            }
            if ($minKey !== null) unset($map[$minKey]);
        }
    }

    /** Adds one attack-log entry to the aggregate. */
    public static function applyEntry(array $state, array $entry, int $now): array
    {
        if (!self::isCountable($entry)) return $state;

        $t = (int) $entry['time'];
        $sev = self::severityOf($entry);
        $hk = gmdate('YmdH', $t);
        $dk = gmdate('Ymd', $t);
        $blocked = !empty($entry['blocked']);

        $h = $state['hours'][$hk] ?? self::emptyHour();
        $h['t']++;
        if ($blocked) $h['b']++;
        $h['s'][$sev]++;
        $state['hours'][$hk] = $h;

        $d = $state['days'][$dk] ?? self::emptyDay();
        $d['t']++;
        if ($blocked) $d['b']++;
        $d['s'][$sev]++;
        self::bump($d['r'], (string) ($entry['rule'] ?? ''), self::CAP_RULES);
        self::bump($d['y'], (string) $entry['type'], self::CAP_TYPES);
        if (($entry['rule'] ?? '') === 'login_failure') $d['lf']++;
        $state['days'][$dk] = $d;

        return self::prune($state, $now);
    }

    /** Drops buckets older than the retention windows. */
    public static function prune(array $state, int $now): array
    {
        $hourCut = gmdate('YmdH', $now - self::HOURS_KEPT * 3600);
        $dayCut = gmdate('Ymd', $now - self::DAYS_KEPT * 86400);
        foreach (array_keys($state['hours'] ?? []) as $k) {
            if ((string) $k < $hourCut) unset($state['hours'][$k]);
        }
        foreach (array_keys($state['days'] ?? []) as $k) {
            if ((string) $k < $dayCut) unset($state['days'][$k]);
        }
        return $state;
    }

    /**
     * Builds the state from existing log entries (live log plus archive) so
     * a site that updates does not start with empty charts. Only entries
     * older than the first live-recorded one are added, so nothing is
     * counted twice.
     */
    public static function backfill(array $state, array $entries, int $now): array
    {
        $first = (int) ($state['first'] ?? 0);
        foreach ($entries as $e) {
            if (!is_array($e) || !self::isCountable($e)) continue;
            if ($first > 0 && (int) $e['time'] >= $first) continue;
            $state = self::applyEntry($state, $e, $now);
        }
        $state['bf'] = true;
        return $state;
    }

    /**
     * Threat level for a window, from its severity counts:
     *   critical: any critical event
     *   high:     10 or more high-severity events
     *   medium:   at least one high-severity event, or 25 or more medium ones
     *   low:      everything else, including a quiet site
     */
    public static function threatLevel(array $sev): string
    {
        if (($sev['critical'] ?? 0) > 0) return 'critical';
        if (($sev['high'] ?? 0) >= 10) return 'high';
        if (($sev['high'] ?? 0) >= 1 || ($sev['medium'] ?? 0) >= 25) return 'medium';
        return 'low';
    }

    private static function sumBuckets(array $buckets): array
    {
        $out = ['detected' => 0, 'blocked' => 0, 'sev' => array_fill_keys(self::SEVERITIES, 0)];
        foreach ($buckets as $b) {
            $out['detected'] += (int) ($b['t'] ?? 0);
            $out['blocked'] += (int) ($b['b'] ?? 0);
            foreach (self::SEVERITIES as $s) $out['sev'][$s] += (int) ($b['s'][$s] ?? 0);
        }
        return $out;
    }

    private static function mergeMaps(array $days, string $field): array
    {
        $out = [];
        foreach ($days as $d) {
            foreach ((array) ($d[$field] ?? []) as $k => $v) $out[(string) $k] = ($out[(string) $k] ?? 0) + (int) $v;
        }
        arsort($out);
        return $out;
    }

    /**
     * Everything the Threat Monitor draws for one period. The rule and type
     * lists only exist in daily buckets, so for 24 hours they cover today
     * and yesterday; 'listsNote' says so for the caption.
     */
    public static function buildView(array $state, string $period, int $now): array
    {
        if (!isset(self::PERIODS[$period])) $period = '7d';
        $unit = self::PERIODS[$period]['unit'];

        $keys = [];
        $prevKeys = [];
        if ($unit === 'hour') {
            for ($i = 23; $i >= 0; $i--) $keys[] = gmdate('YmdH', $now - $i * 3600);
            for ($i = 47; $i >= 24; $i--) $prevKeys[] = gmdate('YmdH', $now - $i * 3600);
        } else {
            for ($i = 6; $i >= 0; $i--) $keys[] = gmdate('Ymd', $now - $i * 86400);
            for ($i = 13; $i >= 7; $i--) $prevKeys[] = gmdate('Ymd', $now - $i * 86400);
        }
        $src = $unit === 'hour' ? ($state['hours'] ?? []) : ($state['days'] ?? []);

        $series = [];
        foreach ($keys as $k) {
            $b = $src[$k] ?? self::emptyHour();
            $series[] = [
                'label' => $unit === 'hour' ? substr($k, 8, 2) . ':00' : substr($k, 4, 2) . '-' . substr($k, 6, 2),
                't'     => (int) $b['t'],
                'b'     => (int) $b['b'],
                's'     => $b['s'] + array_fill_keys(self::SEVERITIES, 0),
            ];
        }

        $cur = self::sumBuckets(array_map(fn ($k) => $src[$k] ?? [], $keys));
        $prev = self::sumBuckets(array_map(fn ($k) => $src[$k] ?? [], $prevKeys));

        $dayKeys = $unit === 'hour' ? [gmdate('Ymd', $now - 86400), gmdate('Ymd', $now)] : $keys;
        $dayBuckets = array_values(array_filter(array_map(fn ($k) => $state['days'][$k] ?? null, $dayKeys)));
        $loginFailures = 0;
        foreach ($dayBuckets as $d) $loginFailures += (int) ($d['lf'] ?? 0);

        return [
            'period'        => $period,
            'series'        => $series,
            'totals'        => $cur,
            'prev'          => $prev,
            'level'         => self::threatLevel($cur['sev']),
            'rules'         => array_slice(self::mergeMaps($dayBuckets, 'r'), 0, 8, true),
            'types'         => self::mergeMaps($dayBuckets, 'y'),
            'loginFailures' => $loginFailures,
            'listsNote'     => $unit === 'hour' ? 'today and yesterday' : '',
        ];
    }

    /** Percentage change from $prev to $cur, or null when there is nothing to compare against. */
    public static function delta(?int $cur, ?int $prev): ?int
    {
        if ($cur === null || $prev === null || $prev <= 0) return null;
        return (int) round((($cur - $prev) / $prev) * 100);
    }

    /**
     * Adds one completed scan to the history, newest last. A scan already
     * recorded (same start time) is updated rather than added twice.
     */
    public static function appendScan(array $history, array $scan): array
    {
        $row = [
            'at'     => (int) ($scan['at'] ?? 0),
            'score'  => max(0, min(100, (int) ($scan['score'] ?? 0))),
            'high'   => max(0, (int) ($scan['high'] ?? 0)),
            'medium' => max(0, (int) ($scan['medium'] ?? 0)),
            'total'  => max(0, (int) ($scan['total'] ?? 0)),
        ];
        $history = array_values(array_filter($history, fn ($h) => (int) ($h['at'] ?? 0) !== $row['at']));
        $history[] = $row;
        usort($history, fn ($a, $b) => (int) $a['at'] <=> (int) $b['at']);
        return array_slice($history, -self::SCANS_KEPT);
    }

    // ------------------------------------------------------------------
    // Storage (never throws)
    // ------------------------------------------------------------------

    private static function dataDir(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/';
    }

    private static function statsPath(): string { return self::dataDir() . 'threat-stats.php'; }
    private static function scansPath(): string { return self::dataDir() . 'scan-trend.php'; }

    public static function loadState(): ?array
    {
        try {
            $path = self::statsPath();
            if (!is_file($path)) return null;
            $d = json_decode(MuruguardHelper::stripDataFileStub((string) @file_get_contents($path)), true);
            return is_array($d) && isset($d['hours'], $d['days']) ? $d : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Locked read-modify-write of the state through $mutate(state): state. */
    private static function mutate(callable $mutate): bool
    {
        try {
            $path = self::statsPath();
            $fh = @fopen($path, 'c+');
            if ($fh === false) return false;
            $ok = false;
            if (@flock($fh, LOCK_EX)) {
                $size = filesize($path) ?: 0;
                $raw = $size > 0 ? MuruguardHelper::stripDataFileStub((string) fread($fh, $size)) : '';
                $state = json_decode($raw, true);
                if (!is_array($state) || !isset($state['hours'], $state['days'])) $state = self::emptyState(time());
                $state = $mutate($state);
                MuruguardHelper::rewriteLockedDataFile($fh, $state);
                fflush($fh);
                flock($fh, LOCK_UN);
                $ok = true;
            }
            fclose($fh);
            return $ok;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Called for every attack-log entry; cheap, bounded, never throws. */
    public static function recordEntry(array $entry): void
    {
        if (!self::isCountable($entry)) return;
        self::mutate(fn (array $s) => self::applyEntry($s, $entry, time()));
    }

    /** First view after an update: fold the existing log and archive in once. */
    public static function ensureBackfilled(): ?array
    {
        $state = self::loadState();
        if (is_array($state) && !empty($state['bf'])) return $state;
        try {
            $entries = array_merge(MuruguardHelper::getAttackLog(), MuruguardHelper::getAttackLogArchive());
            self::mutate(fn (array $s) => self::backfill($s, $entries, time()));
        } catch (\Throwable $e) {
        }
        return self::loadState();
    }

    /** Clearing the Protection Log clears the charts drawn from it too. */
    public static function clearState(): void
    {
        @unlink(self::statsPath());
    }

    public static function loadScans(): array
    {
        try {
            $path = self::scansPath();
            if (!is_file($path)) return [];
            $d = json_decode(MuruguardHelper::stripDataFileStub((string) @file_get_contents($path)), true);
            return is_array($d) ? array_values(array_filter($d, 'is_array')) : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function recordScan(array $scan): void
    {
        try {
            $history = self::loadScans();
            foreach ($history as $h) {
                if ((int) ($h['at'] ?? 0) === (int) ($scan['at'] ?? -1) && (int) ($h['score'] ?? -1) === (int) ($scan['score'] ?? -2)
                    && (int) ($h['total'] ?? -1) === (int) ($scan['total'] ?? -2)) {
                    return; // already recorded, unchanged
                }
            }
            MuruguardHelper::writeDataFile(self::scansPath(), self::appendScan($history, $scan));
        } catch (\Throwable $e) {
        }
    }
}

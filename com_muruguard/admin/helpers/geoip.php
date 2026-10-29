<?php
/**
 * Local GeoIP country lookup for MuRu Guard.
 *
 * Replaces the old per-visitor call to ip-api.com (plain HTTP, no
 * commercial use, 45 requests a minute, and every visitor IP sent to a
 * third party). The site now keeps its own copy of the free DB-IP
 * "IP to Country Lite" database (CC BY 4.0, no account or key needed,
 * https://db-ip.com/db/download/ip-to-country-lite), refreshed monthly,
 * and answers every lookup from disk. No visitor IP ever leaves the
 * server.
 *
 * The database is a standard MaxMind DB (.mmdb) file. The small reader
 * below implements just what a country lookup needs from the published
 * format (https://maxmind.github.io/MaxMind-DB/): the metadata block,
 * the binary search tree, and the data-section decoder. It is pure PHP
 * with no extension or Composer dependency, so it runs on every host
 * that runs Joomla.
 *
 * Everything here fails open: a missing, corrupt or unreadable database
 * means "country unknown", which never blocks anyone.
 */

defined('_JEXEC') or die;

class MuruguardGeoIp
{
    /** Attribution required by the CC BY 4.0 licence; shown wherever country data is used. */
    public const ATTRIBUTION_TEXT = 'IP Geolocation by DB-IP';
    public const ATTRIBUTION_URL  = 'https://db-ip.com';

    /** DB-IP publishes one file per month at this address (YYYY-MM). */
    private const DOWNLOAD_URL = 'https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz';

    /** Refresh once the copy is older than this. DB-IP updates monthly. */
    public const MAX_AGE_DAYS = 35;

    /** The compressed file is about 4 MB and the database about 8 MB today; anything far larger is refused. */
    private const MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024;
    private const MAX_DB_BYTES       = 96 * 1024 * 1024;

    private const METADATA_MARKER = "\xAB\xCD\xEFMaxMind.com";

    /** @var array<string,mixed>|null Reader state for this request (null = not opened yet, false = unavailable). */
    private static $reader = null;

    // ------------------------------------------------------------------
    // Paths and status
    // ------------------------------------------------------------------

    public static function dbPath(): string
    {
        return JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/data/geoip/dbip-country-lite.mmdb';
    }

    /** @return array{installed:bool,builtAt:?int,downloadedAt:?int,sizeBytes:int,stale:bool} */
    public static function status(): array
    {
        $path = self::dbPath();
        if (!is_file($path)) {
            return ['installed' => false, 'builtAt' => null, 'downloadedAt' => null, 'sizeBytes' => 0, 'stale' => true];
        }
        $downloadedAt = (int) @filemtime($path);
        $builtAt = null;
        $meta = self::openReader();
        if (is_array($meta) && isset($meta['build_epoch'])) {
            $builtAt = (int) $meta['build_epoch'];
        }
        return [
            'installed'    => true,
            'builtAt'      => $builtAt,
            'downloadedAt' => $downloadedAt ?: null,
            'sizeBytes'    => (int) @filesize($path),
            'stale'        => $downloadedAt > 0 && (time() - $downloadedAt) > self::MAX_AGE_DAYS * 86400,
        ];
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /** Two-letter ISO country code for $ip, or null when unknown (no database, private address, not listed, any error). */
    public static function countryForIp(string $ip): ?string
    {
        try {
            $record = self::lookup($ip);
            if (!is_array($record)) return null;
            $code = (string) ($record['country']['iso_code'] ?? '');
            return preg_match('/^[A-Z]{2}$/', $code) ? $code : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Decoded record for $ip, or null. Public for tests. */
    public static function lookup(string $ip)
    {
        $packed = @inet_pton($ip);
        if ($packed === false) return null;
        $r = self::openReader();
        if (!is_array($r)) return null;

        $bitCount = strlen($packed) * 8;
        if ($r['ip_version'] === 4 && $bitCount === 128) return null; // IPv6 in an IPv4-only database
        $node = ($bitCount === 32 && $r['ip_version'] === 6) ? $r['ipv4_start'] : 0;

        for ($i = 0; $i < $bitCount && $node < $r['node_count']; $i++) {
            $bit = (ord($packed[$i >> 3]) >> (7 - ($i & 7))) & 1;
            $node = self::readRecord($r, $node, $bit);
        }
        if ($node === $r['node_count']) return null; // not in the database
        if ($node < $r['node_count']) return null;    // malformed tree

        $offset = $node - $r['node_count'] - 16; // relative to the data section
        if ($offset < 0) return null;
        [$value] = self::decode($r, $offset);
        return $value;
    }

    // ------------------------------------------------------------------
    // Database download / refresh
    // ------------------------------------------------------------------

    /** True when the database is missing or older than MAX_AGE_DAYS. */
    public static function needsRefresh(): bool
    {
        $path = self::dbPath();
        if (!is_file($path)) return true;
        return (time() - (int) @filemtime($path)) > self::MAX_AGE_DAYS * 86400;
    }

    /**
     * Downloads this month's database (or last month's, early in a month
     * before the new file is out), checks that it opens and answers a
     * known lookup, and only then swaps it in. The existing copy is kept
     * on any failure.
     *
     * @return array{ok:bool,error?:string,builtAt?:int,sizeBytes?:int}
     */
    public static function downloadDatabase(): array
    {
        if (!function_exists('gzopen')) return ['ok' => false, 'error' => 'PHP zlib extension is not available'];
        $dir = dirname(self::dbPath());
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return ['ok' => false, 'error' => 'Could not create the GeoIP folder'];
        }
        if (!is_file($dir . '/index.html')) @file_put_contents($dir . '/index.html', '<html><body></body></html>');

        $lastError = 'Download failed';
        foreach ([date('Y-m'), date('Y-m', strtotime('first day of last month'))] as $month) {
            $gzTmp = $dir . '/download-' . bin2hex(random_bytes(6)) . '.gz';
            $dbTmp = $dir . '/download-' . bin2hex(random_bytes(6)) . '.mmdb';
            try {
                $fetched = self::fetchToFile(sprintf(self::DOWNLOAD_URL, $month), $gzTmp);
                if ($fetched !== true) {
                    $lastError = $fetched;
                    continue;
                }
                $unzipped = self::gunzipToFile($gzTmp, $dbTmp);
                if ($unzipped !== true) {
                    $lastError = $unzipped;
                    continue;
                }
                $check = self::verifyDatabaseFile($dbTmp);
                if ($check !== true) {
                    $lastError = $check;
                    continue;
                }
                if (!@rename($dbTmp, self::dbPath())) {
                    $lastError = 'Could not save the database';
                    continue;
                }
                self::$reader = null; // reopen the new file on next lookup
                $meta = self::openReader();
                return [
                    'ok'        => true,
                    'builtAt'   => is_array($meta) ? (int) ($meta['build_epoch'] ?? 0) : 0,
                    'sizeBytes' => (int) @filesize(self::dbPath()),
                ];
            } finally {
                @unlink($gzTmp);
                @unlink($dbTmp);
            }
        }
        return ['ok' => false, 'error' => $lastError];
    }

    /** Refreshes the database when it is missing or stale. For the scheduled scan; never throws. */
    public static function refreshIfStale(): ?array
    {
        try {
            return self::needsRefresh() ? self::downloadDatabase() : null;
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'Unexpected error'];
        }
    }

    /** @return true|string */
    private static function fetchToFile(string $url, string $dest)
    {
        $ctx = stream_context_create([
            'http' => ['method' => 'GET', 'timeout' => 30, 'follow_location' => 0, 'ignore_errors' => true,
                       'header' => "User-Agent: MuRu-Guard-GeoIP\r\n"],
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $in = @fopen($url, 'rb', false, $ctx);
        if ($in === false) return 'Could not reach download.db-ip.com';
        $status = 0;
        foreach ((array) ($http_response_header ?? []) as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) $status = (int) $m[1];
        }
        if ($status !== 200) {
            fclose($in);
            return 'download.db-ip.com answered HTTP ' . $status;
        }
        $out = @fopen($dest, 'wb');
        if ($out === false) {
            fclose($in);
            return 'Could not write the download';
        }
        $total = 0;
        while (!feof($in)) {
            $chunk = fread($in, 65536);
            if ($chunk === false) break;
            $total += strlen($chunk);
            if ($total > self::MAX_DOWNLOAD_BYTES) {
                fclose($in);
                fclose($out);
                return 'Download is larger than expected';
            }
            fwrite($out, $chunk);
        }
        fclose($in);
        fclose($out);
        return $total > 0 ? true : 'Empty download';
    }

    /** @return true|string */
    private static function gunzipToFile(string $gz, string $dest)
    {
        $in = @gzopen($gz, 'rb');
        if ($in === false) return 'The download is not a valid gzip file';
        $out = @fopen($dest, 'wb');
        if ($out === false) {
            gzclose($in);
            return 'Could not write the database';
        }
        $total = 0;
        while (!gzeof($in)) {
            $chunk = gzread($in, 65536);
            if ($chunk === false) break;
            $total += strlen($chunk);
            if ($total > self::MAX_DB_BYTES) {
                gzclose($in);
                fclose($out);
                return 'Database is larger than expected';
            }
            fwrite($out, $chunk);
        }
        gzclose($in);
        fclose($out);
        return $total > 0 ? true : 'The download was empty after unpacking';
    }

    /** Opens $path as a country database and checks a known address. @return true|string */
    public static function verifyDatabaseFile(string $path)
    {
        $saved = self::$reader;
        $r = false;
        try {
            $r = self::openReaderAt($path);
            if (!is_array($r)) return 'The file is not a valid MaxMind DB';
            if (stripos((string) ($r['database_type'] ?? ''), 'country') === false) return 'The file is not a country database';
            self::$reader = $r;
            // 8.8.8.8 (Google DNS) has been listed as US in every edition.
            if (self::countryForIp('8.8.8.8') !== 'US') return 'The database did not answer a test lookup';
            return true;
        } catch (\Throwable $e) {
            return 'The database could not be read';
        } finally {
            if (is_array($r)) fclose($r['handle']);
            self::$reader = $saved;
        }
    }

    // ------------------------------------------------------------------
    // MaxMind DB reader
    // ------------------------------------------------------------------

    /** @return array<string,mixed>|false */
    private static function openReader()
    {
        if (self::$reader === null) {
            self::$reader = self::openReaderAt(self::dbPath());
        }
        return self::$reader;
    }

    /** @return array<string,mixed>|false */
    private static function openReaderAt(string $path)
    {
        if (!is_file($path) || !is_readable($path)) return false;
        $size = (int) filesize($path);
        if ($size < 1024) return false;
        $fh = @fopen($path, 'rb');
        if ($fh === false) return false;

        // The metadata sits at the very end, within the last 128 KiB.
        $tailLen = min($size, 131072);
        fseek($fh, $size - $tailLen);
        $tail = (string) fread($fh, $tailLen);
        $pos = strrpos($tail, self::METADATA_MARKER);
        if ($pos === false) {
            fclose($fh);
            return false;
        }
        $metaStart = $size - $tailLen + $pos + strlen(self::METADATA_MARKER);

        $r = ['handle' => $fh, 'size' => $size, 'data_start' => $metaStart];
        [$meta] = self::decode($r, 0);
        if (!is_array($meta)) {
            fclose($fh);
            return false;
        }

        $nodeCount  = (int) ($meta['node_count'] ?? 0);
        $recordSize = (int) ($meta['record_size'] ?? 0);
        $ipVersion  = (int) ($meta['ip_version'] ?? 0);
        if ($nodeCount <= 0 || !in_array($recordSize, [24, 28, 32], true) || !in_array($ipVersion, [4, 6], true)) {
            fclose($fh);
            return false;
        }
        $nodeBytes = $recordSize / 4; // two records per node
        $treeSize = $nodeCount * $nodeBytes;
        if ($treeSize + 16 > $size) {
            fclose($fh);
            return false;
        }

        $r = [
            'handle'        => $fh,
            'size'          => $size,
            'node_count'    => $nodeCount,
            'record_size'   => $recordSize,
            'node_bytes'    => $nodeBytes,
            'ip_version'    => $ipVersion,
            'data_start'    => $treeSize + 16,
            'database_type' => (string) ($meta['database_type'] ?? ''),
            'build_epoch'   => (int) ($meta['build_epoch'] ?? 0),
            'ipv4_start'    => 0,
        ];
        if ($ipVersion === 6) {
            // IPv4 addresses live under ::/96; find that node once.
            $node = 0;
            for ($i = 0; $i < 96 && $node < $nodeCount; $i++) {
                $node = self::readRecord($r, $node, 0);
            }
            $r['ipv4_start'] = $node;
        }
        return $r;
    }

    private static function readRecord(array $r, int $node, int $bit): int
    {
        fseek($r['handle'], $node * $r['node_bytes']);
        $b = (string) fread($r['handle'], $r['node_bytes']);
        if (strlen($b) !== $r['node_bytes']) return $r['node_count'];
        switch ($r['record_size']) {
            case 24:
                $s = $bit === 0 ? substr($b, 0, 3) : substr($b, 3, 3);
                return unpack('N', "\0" . $s)[1];
            case 28:
                $mid = ord($b[3]);
                if ($bit === 0) {
                    return (($mid & 0xF0) << 20) | unpack('N', "\0" . substr($b, 0, 3))[1];
                }
                return (($mid & 0x0F) << 24) | unpack('N', "\0" . substr($b, 4, 3))[1];
            default: // 32
                return unpack('N', $bit === 0 ? substr($b, 0, 4) : substr($b, 4, 4))[1];
        }
    }

    private static function readBytes(array $r, int $absOffset, int $len): string
    {
        if ($len <= 0) return '';
        if ($absOffset < 0 || $absOffset + $len > $r['size']) throw new \RuntimeException('MMDB read out of range');
        fseek($r['handle'], $absOffset);
        $s = (string) fread($r['handle'], $len);
        if (strlen($s) !== $len) throw new \RuntimeException('MMDB short read');
        return $s;
    }

    /**
     * Decodes one value at $offset (relative to the data section).
     * @return array{0:mixed,1:int} the value and the offset just after it
     */
    private static function decode(array $r, int $offset, int $depth = 0): array
    {
        if ($depth > 32) throw new \RuntimeException('MMDB nesting too deep');
        $base = $r['data_start'];
        $ctrl = ord(self::readBytes($r, $base + $offset, 1));
        $offset++;
        $type = $ctrl >> 5;

        if ($type === 1) { // pointer
            $ss = ($ctrl >> 3) & 0x3;
            $vvv = $ctrl & 0x7;
            $len = $ss + 1;
            $buf = self::readBytes($r, $base + $offset, $len);
            $offset += $len;
            if ($ss === 0) $ptr = ($vvv << 8) | ord($buf[0]);
            elseif ($ss === 1) $ptr = (($vvv << 16) | unpack('n', $buf)[1]) + 2048;
            elseif ($ss === 2) $ptr = (($vvv << 24) | unpack('N', "\0" . $buf)[1]) + 526336;
            else $ptr = unpack('N', $buf)[1];
            [$value] = self::decode($r, $ptr, $depth + 1);
            return [$value, $offset];
        }

        if ($type === 0) { // extended type
            $type = 7 + ord(self::readBytes($r, $base + $offset, 1));
            $offset++;
        }

        $size = $ctrl & 0x1F;
        if ($size >= 29) {
            $extra = $size - 28;
            $buf = self::readBytes($r, $base + $offset, $extra);
            $offset += $extra;
            if ($size === 29) $size = 29 + ord($buf[0]);
            elseif ($size === 30) $size = 285 + unpack('n', $buf)[1];
            else $size = 65821 + unpack('N', "\0" . $buf)[1];
        }

        switch ($type) {
            case 2: // UTF-8 string
            case 4: // bytes
                return [self::readBytes($r, $base + $offset, $size), $offset + $size];
            case 3: // double
                return [unpack('E', self::readBytes($r, $base + $offset, 8))[1], $offset + 8];
            case 15: // float
                return [unpack('G', self::readBytes($r, $base + $offset, 4))[1], $offset + 4];
            case 5: // uint16
            case 6: // uint32
            case 8: // int32
            case 9: // uint64
            case 10: // uint128
                $buf = self::readBytes($r, $base + $offset, $size);
                $n = 0;
                for ($i = 0; $i < $size; $i++) $n = ($n * 256) + ord($buf[$i]);
                if ($type === 8 && $size === 4 && $n >= 0x80000000) $n -= 0x100000000;
                return [$n, $offset + $size];
            case 7: // map
                $map = [];
                for ($i = 0; $i < $size; $i++) {
                    [$key, $offset] = self::decode($r, $offset, $depth + 1);
                    [$val, $offset] = self::decode($r, $offset, $depth + 1);
                    $map[(string) $key] = $val;
                }
                return [$map, $offset];
            case 11: // array
                $arr = [];
                for ($i = 0; $i < $size; $i++) {
                    [$arr[], $offset] = self::decode($r, $offset, $depth + 1);
                }
                return [$arr, $offset];
            case 14: // boolean
                return [$size !== 0, $offset];
            default: // 12 container, 13 end marker: not used in country databases
                throw new \RuntimeException('Unsupported MMDB type ' . $type);
        }
    }
}

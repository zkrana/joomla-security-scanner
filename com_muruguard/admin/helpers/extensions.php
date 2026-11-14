<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Extension health for the Dashboard: installed third-party extensions worth a second look. Advice only, nothing is
 * changed on the site. Runs on Joomla 3.10 and Joomla 4 to 6 (plain PHP, no database access here: the model passes
 * the rows in).
 *
 * Abandoned: the installed release is 2 or more years old and Joomla's update data offers nothing newer, so the
 * next security hole may never be fixed. Two dates must both be old: the manifest's creationDate (the only release
 * date Joomla keeps, though many developers never change it) and the time the manifest file was last written on this
 * site (every install or update rewrites it). An extension whose dates cannot be read is skipped, never guessed.
 *
 * Unused: disabled extensions, modules with no published instance, and site templates no page uses. Their files stay
 * on the server and can still be reached, so a forgotten extension is a common way in.
 */

defined('_JEXEC') or die;

class MuruguardExtensionHealth
{
    public const AGE_YEARS = 2;
    public const MAX_LISTED = 30;

    /** MuRu Guard's own extensions are never listed. */
    private const OWN = ['com_muruguard', 'muruguardshield', 'muruguardquickicon', 'mod_muruguardstatus', 'pkg_muruguard'];

    /** A creationDate as a timestamp, or null when it cannot be read reliably ("2023-05-01", "May 2023", "05/2023", "2023"). */
    public static function parseDate(string $d): ?int
    {
        $d = trim($d);
        if ($d === '') return null;
        if (preg_match('/^(\d{4})$/', $d, $m)) return gmmktime(0, 0, 0, 12, 31, (int) $m[1]); // a bare year: its end
        if (preg_match('/^(\d{1,2})[\/.-](\d{4})$/', $d, $m)) return gmmktime(0, 0, 0, (int) $m[1], 28, (int) $m[2]);
        if (preg_match('/^(\d{4})[\/.-](\d{1,2})$/', $d, $m)) return gmmktime(0, 0, 0, (int) $m[2], 28, (int) $m[1]);
        $t = strtotime($d . ' UTC');
        if ($t === false || $t < gmmktime(0, 0, 0, 1, 1, 2000) || $t > time() + 86400 * 366) return null;
        return $t;
    }

    private static function isOwn(array $r): bool
    {
        return in_array((string) ($r['element'] ?? ''), self::OWN, true);
    }

    /**
     * Old third-party extensions with no newer version offered.
     *
     * @param array $rows each: id, name, type, element, created (creationDate), installed (manifest file time or
     *                    null), version, hasUpdateSite (bool), updateAvailable (bool)
     */
    public static function abandoned(array $rows, int $now): array
    {
        $out = [];
        foreach ($rows as $r) {
            if (self::isOwn($r) || !empty($r['updateAvailable'])) continue;
            $t = self::parseDate((string) ($r['created'] ?? ''));
            $installed = (int) ($r['installed'] ?? 0);
            if ($t === null || $installed <= 0) continue;
            // The newer of the two: a stale creationDate on a freshly installed update does not count as old.
            $t = max($t, $installed);
            $years = ($now - $t) / (365.25 * 86400);
            if ($years < self::AGE_YEARS) continue;
            $out[] = [
                'id' => (int) $r['id'], 'name' => (string) $r['name'], 'type' => (string) $r['type'],
                'version' => (string) ($r['version'] ?? ''), 'released' => $t, 'years' => round($years, 1),
                'hasUpdateSite' => !empty($r['hasUpdateSite']),
            ];
        }
        usort($out, function ($a, $b) {
            return $a['released'] <=> $b['released'];
        });
        return array_slice($out, 0, self::MAX_LISTED);
    }

    /**
     * Extensions that are installed but do nothing on the site.
     *
     * @param array $rows   each: id, name, type, element, folder, enabled (bool), clientId, publishedModules (int,
     *                       modules only), templateInUse (bool, site templates only)
     * @param array $owners base names of installed third-party components and templates ("easystore",
     *                       "sppagebuilder", "helixultimate"): their own modules and plugins are often switched off on
     *                       purpose, so they are not listed
     * @return array<int,array{id:int,name:string,type:string,reason:string}>
     */
    public static function unused(array $rows, array $owners = []): array
    {
        $out = [];
        foreach ($rows as $r) {
            if (self::isOwn($r) || self::belongsTo($r, $owners)) continue;
            $type = (string) ($r['type'] ?? '');
            $reason = null;
            if (empty($r['enabled'])) {
                $reason = 'disabled';
            } elseif ($type === 'module' && array_key_exists('publishedModules', $r) && (int) $r['publishedModules'] === 0) {
                $reason = 'no_published_module';
            } elseif ($type === 'template' && (int) ($r['clientId'] ?? 0) === 0 && array_key_exists('templateInUse', $r) && !$r['templateInUse']) {
                $reason = 'template_not_used';
            }
            if ($reason === null) continue;
            $out[] = ['id' => (int) $r['id'], 'name' => (string) $r['name'], 'type' => $type, 'reason' => $reason];
        }
        usort($out, function ($a, $b) {
            return [$a['type'], strtolower($a['name'])] <=> [$b['type'], strtolower($b['name'])];
        });
        return array_slice($out, 0, self::MAX_LISTED);
    }

    /** True when a module or plugin is part of an installed component or template (same base name). */
    public static function belongsTo(array $r, array $owners): bool
    {
        $type = (string) ($r['type'] ?? '');
        if ($type !== 'module' && $type !== 'plugin') return false;
        $names = [strtolower((string) ($r['element'] ?? ''))];
        if ($type === 'module') $names = [preg_replace('/^mod_/', '', $names[0])];
        if ($type === 'plugin') $names[] = strtolower((string) ($r['folder'] ?? ''));
        foreach ($owners as $owner) {
            $owner = strtolower((string) $owner);
            if ($owner === '') continue;
            foreach ($names as $n) {
                if ($n === $owner || strpos($n, $owner . '_') === 0) return true;
            }
        }
        return false;
    }

    /** Where the manifest of an installed extension lives (its file time is the last install or update on this site). */
    public static function manifestCandidates(string $type, string $element, string $folder, int $clientId): array
    {
        $base = $clientId === 1 ? JPATH_ADMINISTRATOR : JPATH_SITE;
        $short = preg_replace('/^(com|mod|tpl|pkg|lib|files)_/', '', $element);
        $short = is_string($short) ? $short : $element;
        switch ($type) {
            case 'component':
                return [JPATH_ADMINISTRATOR . '/components/' . $element . '/' . $short . '.xml', JPATH_ADMINISTRATOR . '/components/' . $element . '/' . $element . '.xml'];
            case 'module':
                return [$base . '/modules/' . $element . '/' . $element . '.xml'];
            case 'plugin':
                return [JPATH_PLUGINS . '/' . $folder . '/' . $element . '/' . $element . '.xml'];
            case 'template':
                return [$base . '/templates/' . $element . '/templateDetails.xml'];
            case 'package':
                return [JPATH_MANIFESTS . '/packages/' . $element . '.xml'];
            case 'library':
                return [JPATH_MANIFESTS . '/libraries/' . $element . '.xml'];
            case 'file':
                return [JPATH_MANIFESTS . '/files/' . $element . '.xml'];
        }
        return [];
    }
}

<?php
/**
 * @package     MuRu Guard
 * @copyright   Copyright (C) Lyzerslab. All rights reserved.
 * @license     GNU General Public License version 2 or later
 */

defined('_JEXEC') or die;

/**
 * Security presets: four protection levels, each a fixed set of values for settings MuRu Guard already has. Pure
 * logic (no Joomla calls), so the plan shown to the admin and the values written are the same and can be tested.
 *
 * Only the settings listed in MAP are ever written. Settings that can lock someone out, need site-specific input or
 * are incident tools (Emergency Mode, country lists, trusted proxies, Admin Lockdown, upload lockdown, scan settings)
 * are never part of a preset.
 */
final class MuruguardPresets
{
    public const LEVELS = ['basic', 'standard', 'advanced', 'maximum'];
    public const RECOMMENDED = 'standard';

    /** Params key holding the level applied last ('' = never). */
    public const STORED = 'security_preset';
    /** Params key holding the values a preset replaced, for Undo. */
    public const UNDO = 'security_preset_undo';

    /**
     * Each setting: [label language key, values for basic, standard, advanced, maximum].
     * Values are what the Settings screens store (1/0 switches, integers).
     */
    private const MAP = [
        'shield_enabled'              => ['COM_MURUGUARD_PRESET_K_SHIELD', 1, 1, 1, 1],
        'shield_block_patterns'       => ['COM_MURUGUARD_PRESET_K_PATTERNS', 1, 1, 1, 1],
        'shield_block_bruteforce'     => ['COM_MURUGUARD_PRESET_K_BRUTEFORCE', 1, 1, 1, 1],
        'shield_bruteforce_threshold' => ['COM_MURUGUARD_PRESET_K_BRUTEFORCE_ATTEMPTS', 8, 5, 5, 3],
        'shield_bruteforce_window'    => ['COM_MURUGUARD_PRESET_K_BRUTEFORCE_MINUTES', 15, 15, 30, 60],
        'sppb_guard_endpoints'        => ['COM_MURUGUARD_PRESET_K_SPPB_ENDPOINTS', 1, 1, 1, 1],
        'shield_block_useragents'     => ['COM_MURUGUARD_PRESET_K_USERAGENTS', 0, 1, 1, 1],
        'protected_users_enabled'     => ['COM_MURUGUARD_PRESET_K_PROTECTED_USERS', 0, 1, 1, 1],
    ];

    /** Defaults the settings have when they were never saved (as in config.xml and the Settings screens). */
    private const DEFAULTS = [
        'shield_bruteforce_threshold' => 5, 'shield_bruteforce_window' => 15,
        'sppb_guard_endpoints' => 1,
    ];

    public static function isLevel(string $level): bool
    {
        return in_array($level, self::LEVELS, true);
    }

    /** Every key a preset may write (for Undo and for "do not touch anything else" checks). */
    public static function keys(): array
    {
        return array_keys(self::MAP);
    }

    public static function label(string $key): string
    {
        return (string) (self::MAP[$key][0] ?? $key);
    }

    /**
     * The values a level sets.
     *
     * @return array<string,int>
     */
    public static function targets(string $level): array
    {
        if (!self::isLevel($level)) return [];
        $col = 1 + array_search($level, self::LEVELS, true);
        $out = [];
        foreach (self::MAP as $key => $row) {
            $out[$key] = (int) $row[$col];
        }
        return $out;
    }

    /** A stored value as the Settings screens read it (missing = the setting's default, else 0). */
    public static function current(array $params, string $key): int
    {
        if (array_key_exists($key, $params) && $params[$key] !== '' && $params[$key] !== null) return (int) $params[$key];
        return (int) (self::DEFAULTS[$key] ?? 0);
    }

    /**
     * What applying a level would change: [key => [from, to]] for the settings whose value differs.
     *
     * @return array<string,array{0:int,1:int}>
     */
    public static function plan(array $params, string $level): array
    {
        $changes = [];
        foreach (self::targets($level) as $key => $to) {
            $from = self::current($params, $key);
            if ($from !== $to) $changes[$key] = [$from, $to];
        }
        return $changes;
    }

    /** The level whose values all match the stored settings ('' when none does). Strictest match wins. */
    public static function matching(array $params): string
    {
        foreach (array_reverse(self::LEVELS) as $level) {
            if (self::plan($params, $level) === []) return $level;
        }
        return '';
    }

    /**
     * What the Settings screen shows as active: a level, 'custom' (a preset was applied, then changed by hand) or ''
     * (never applied and no exact match).
     */
    public static function active(array $params): string
    {
        $match = self::matching($params);
        if ($match !== '') return $match;
        $stored = (string) ($params[self::STORED] ?? '');
        return self::isLevel($stored) ? 'custom' : '';
    }

    /**
     * The values to save for Undo: every key the level is about to write, with its current stored form (absent keys
     * are recorded as null, so Undo removes them again and the default applies), plus the previous preset name.
     */
    public static function undoSnapshot(array $params, string $level): array
    {
        $prev = [];
        foreach (array_keys(self::plan($params, $level)) as $key) {
            $prev[$key] = array_key_exists($key, $params) ? $params[$key] : null;
        }
        return ['level' => (string) ($params[self::STORED] ?? ''), 'values' => $prev, 'time' => time()];
    }
}

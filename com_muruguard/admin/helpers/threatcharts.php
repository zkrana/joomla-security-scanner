<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Threat Monitor drawing code.
 *
 * Plain functions that turn the arrays from MuruguardThreatStats into inline
 * SVG and small HTML blocks. No chart library and no remote asset. Every
 * chart has a text alternative ("View as table") and an aria-label, and every
 * colour is paired with a word in the legend, so nothing relies on colour
 * alone. Everything returns a string and escapes its own input.
 */

defined('_JEXEC') or die;

class MuruguardThreatCharts
{
    /** Severity colours. Critical is black: it is the "stop and look" level. */
    public const COLORS = ['low' => '#94a3b8', 'medium' => '#f59e0b', 'high' => '#ef4444', 'critical' => '#111827'];
    private const LEVEL_KEYS = ['low' => 'COM_MURUGUARD_THREATMON_LEVEL_LOW', 'medium' => 'COM_MURUGUARD_THREATMON_LEVEL_MEDIUM', 'high' => 'COM_MURUGUARD_THREATMON_LEVEL_HIGH', 'critical' => 'COM_MURUGUARD_THREATMON_LEVEL_CRITICAL'];
    private const LEVEL_FALLBACK = ['low' => 'Low', 'medium' => 'Medium', 'high' => 'High', 'critical' => 'Critical'];
    private const TYPE_COLORS = ['#4338ca', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#14b8a6', '#64748b'];

    private static function e($v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
    }

    /** Translated text when a language key exists, otherwise the English fallback given here. */
    private static function t(string $key, string $fallback): string
    {
        if (class_exists('\Joomla\CMS\Language\Text')) {
            $v = \Joomla\CMS\Language\Text::_($key);
            if ($v !== $key) return $v;
        }
        return $fallback;
    }

    private static function levelLabel(string $level): string
    {
        return self::t(self::LEVEL_KEYS[$level] ?? '', self::LEVEL_FALLBACK[$level] ?? $level);
    }

    /** Friendly names for the raw rule and type ids shown in lists. */
    public static function ruleLabel(string $rule): string
    {
        return ucfirst(str_replace(['_', '-'], ' ', $rule));
    }

    public static function niceMax(int $v): int
    {
        if ($v <= 4) return 4;
        $pow = 10 ** (int) floor(log10($v));
        foreach ([1, 2, 5, 10] as $m) {
            if ($v <= $m * $pow) return (int) ($m * $pow);
        }
        return (int) (10 * $pow);
    }

    /** Collapsed "View as table" fallback for a chart. */
    public static function dataTable(array $headers, array $rows): string
    {
        $o = '<details class="muru-tm-table"><summary>' . self::e(self::t('COM_MURUGUARD_THREATMON_VIEW_TABLE', 'View as table')) . '</summary><table><thead><tr>';
        foreach ($headers as $h) $o .= '<th scope="col">' . self::e($h) . '</th>';
        $o .= '</tr></thead><tbody>';
        foreach ($rows as $r) {
            $o .= '<tr>';
            foreach ($r as $c) $o .= '<td>' . self::e($c) . '</td>';
            $o .= '</tr>';
        }
        return $o . '</tbody></table></details>';
    }

    public static function legend(array $keys = ['low', 'medium', 'high', 'critical']): string
    {
        $o = '<div class="muru-tm-legend">';
        foreach ($keys as $k) {
            $o .= '<span><i style="background:' . self::COLORS[$k] . '"></i>' . self::e(self::levelLabel($k)) . '</span>';
        }
        return $o . '</div>';
    }

    /** Stacked bars, one per series entry, split by severity. */
    public static function stackedBars(array $series, int $w = 720, int $h = 200): string
    {
        $n = count($series);
        $max = 0;
        foreach ($series as $p) $max = max($max, (int) $p['t']);
        $top = self::niceMax($max);
        $padL = 34; $padB = 22; $padT = 8; $padR = 6;
        $plotW = $w - $padL - $padR; $plotH = $h - $padB - $padT;
        $slot = $n > 0 ? $plotW / $n : $plotW;
        $bw = max(2, min(34, $slot * 0.7));

        $svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" class="muru-tm-svg" role="img" aria-label="' . self::e(self::t('COM_MURUGUARD_THREATMON_CHART_ATTACKS_ARIA', 'Attacks over time, stacked by severity')) . '" preserveAspectRatio="xMidYMid meet">';
        for ($g = 0; $g <= 2; $g++) {
            $y = $padT + $plotH - ($plotH * $g / 2);
            $svg .= '<line x1="' . $padL . '" y1="' . round($y, 1) . '" x2="' . ($w - $padR) . '" y2="' . round($y, 1) . '" stroke="#e5e7eb" stroke-width="1"/>';
            $svg .= '<text x="' . ($padL - 6) . '" y="' . round($y + 3, 1) . '" text-anchor="end" font-size="10" fill="#6b7280">' . (int) round($top * $g / 2) . '</text>';
        }
        $every = max(1, (int) ceil($n / 12));
        foreach ($series as $i => $p) {
            $x = $padL + $slot * $i + ($slot - $bw) / 2;
            $yy = $padT + $plotH;
            $svg .= '<g><title>' . self::e($p['label'] . ': ' . (int) $p['t']) . '</title>';
            foreach (['low', 'medium', 'high', 'critical'] as $sev) {
                $c = (int) ($p['s'][$sev] ?? 0);
                if ($c <= 0) continue;
                $bh = max(1, $plotH * $c / $top);
                $yy -= $bh;
                $svg .= '<rect x="' . round($x, 1) . '" y="' . round($yy, 1) . '" width="' . round($bw, 1) . '" height="' . round($bh, 1) . '" fill="' . self::COLORS[$sev] . '" rx="1"/>';
            }
            $svg .= '</g>';
            if ($i % $every === 0) {
                $svg .= '<text x="' . round($x + $bw / 2, 1) . '" y="' . ($h - 6) . '" text-anchor="middle" font-size="10" fill="#6b7280">' . self::e($p['label']) . '</text>';
            }
        }
        return $svg . '</svg>';
    }

    /** Horizontal bar list in plain HTML/CSS. */
    public static function hbars(array $map, string $color = '#4338ca', ?callable $labelFn = null): string
    {
        if ($map === []) return '<p class="muru-tm-empty">' . self::e(self::t('COM_MURUGUARD_THREATMON_NO_DATA', 'Nothing recorded in this period.')) . '</p>';
        $max = max($map);
        $o = '<ul class="muru-tm-hbars">';
        foreach ($map as $k => $v) {
            $label = $labelFn ? $labelFn((string) $k) : (string) $k;
            $pct = $max > 0 ? max(2, (int) round($v / $max * 100)) : 0;
            $o .= '<li><span class="muru-tm-hl" title="' . self::e($label) . '">' . self::e($label) . '</span>'
                . '<span class="muru-tm-hb"><b style="width:' . $pct . '%;background:' . $color . '"></b></span>'
                . '<span class="muru-tm-hn">' . (int) $v . '</span></li>';
        }
        return $o . '</ul>';
    }

    /** Donut for a small category map; the centre shows the total. */
    public static function donut(array $map, int $size = 160): string
    {
        $total = array_sum($map);
        if ($total <= 0) return '<p class="muru-tm-empty">' . self::e(self::t('COM_MURUGUARD_THREATMON_NO_DATA', 'Nothing recorded in this period.')) . '</p>';
        $r = 52; $c = 2 * M_PI * $r; $off = 0;
        $svg = '<svg viewBox="0 0 160 160" width="' . $size . '" height="' . $size . '" class="muru-tm-donut" role="img" aria-label="' . self::e(self::t('COM_MURUGUARD_THREATMON_CHART_TYPES_ARIA', 'Attack types')) . '">';
        $i = 0; $legend = '<ul class="muru-tm-dlegend">';
        foreach ($map as $k => $v) {
            $len = $c * $v / $total;
            $col = self::TYPE_COLORS[$i % count(self::TYPE_COLORS)];
            $svg .= '<circle cx="80" cy="80" r="' . $r . '" fill="none" stroke="' . $col . '" stroke-width="22" stroke-dasharray="' . round($len, 2) . ' ' . round($c - $len, 2) . '" stroke-dashoffset="' . round(-$off, 2) . '" transform="rotate(-90 80 80)"><title>' . self::e(self::ruleLabel((string) $k)) . ': ' . (int) $v . '</title></circle>';
            $off += $len;
            $legend .= '<li><i style="background:' . $col . '"></i>' . self::e(self::ruleLabel((string) $k)) . ' <b>' . (int) $v . '</b></li>';
            $i++;
        }
        $svg .= '<text x="80" y="86" text-anchor="middle" font-size="22" font-weight="700" fill="#111827">' . (int) $total . '</text></svg>';
        return '<div class="muru-tm-donutwrap">' . $svg . $legend . '</ul></div>';
    }

    /** Line chart with points, for the score trend (0..100). */
    public static function lineChart(array $scans, int $w = 720, int $h = 170): string
    {
        $n = count($scans);
        if ($n < 2) {
            return '<p class="muru-tm-empty">' . self::e(self::t('COM_MURUGUARD_THREATMON_NEED_SCANS', 'Run at least two scans to see a trend.')) . '</p>';
        }
        $padL = 30; $padB = 22; $padT = 8; $padR = 22;
        $plotW = $w - $padL - $padR; $plotH = $h - $padB - $padT;
        $svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" class="muru-tm-svg" role="img" aria-label="' . self::e(self::t('COM_MURUGUARD_THREATMON_CHART_SCORE_ARIA', 'Security score over recent scans')) . '" preserveAspectRatio="xMidYMid meet">';
        foreach ([0, 50, 100] as $g) {
            $y = $padT + $plotH - $plotH * $g / 100;
            $svg .= '<line x1="' . $padL . '" y1="' . round($y, 1) . '" x2="' . ($w - $padR) . '" y2="' . round($y, 1) . '" stroke="#e5e7eb"/><text x="' . ($padL - 5) . '" y="' . round($y + 3, 1) . '" text-anchor="end" font-size="10" fill="#6b7280">' . $g . '</text>';
        }
        $pts = [];
        foreach ($scans as $i => $s) {
            $x = $padL + $plotW * $i / ($n - 1);
            $y = $padT + $plotH - $plotH * (int) $s['score'] / 100;
            $pts[] = [round($x, 1), round($y, 1)];
        }
        $svg .= '<polyline points="' . implode(' ', array_map(fn ($p) => $p[0] . ',' . $p[1], $pts)) . '" fill="none" stroke="#4338ca" stroke-width="2"/>';
        foreach ($scans as $i => $s) {
            $svg .= '<circle cx="' . $pts[$i][0] . '" cy="' . $pts[$i][1] . '" r="3.5" fill="#4338ca"><title>' . self::e(gmdate('Y-m-d H:i', (int) $s['at']) . ' UTC: ' . (int) $s['score']) . '</title></circle>';
            $svg .= '<text x="' . $pts[$i][0] . '" y="' . ($h - 6) . '" text-anchor="' . ($i === $n - 1 ? 'end' : ($i === 0 ? 'start' : 'middle')) . '" font-size="10" fill="#6b7280">' . self::e(gmdate('m-d H:i', (int) $s['at'])) . '</text>';
        }
        return $svg . '</svg>';
    }

    public static function deltaBadge(?int $pct, bool $upIsBad = true): string
    {
        if ($pct === null) return '';
        if ($pct === 0) return '<span class="muru-tm-delta flat">0%</span>';
        $bad = $upIsBad ? $pct > 0 : $pct < 0;
        return '<span class="muru-tm-delta ' . ($bad ? 'bad' : 'good') . '" title="' . self::e(self::t('COM_MURUGUARD_THREATMON_VS_PREV', 'Compared with the previous period')) . '">' . ($pct > 0 ? '+' : '') . $pct . '%</span>';
    }

    /** Top row: threat level meter plus the headline numbers with changes against the previous period. */
    public static function statsRow(array $view, ?int $score): string
    {
        $level = (string) $view['level'];
        $t = $view['totals'];
        $p = $view['prev'];
        $meter = '<div class="muru-tm-meter" role="img" aria-label="' . self::e(self::t('COM_MURUGUARD_THREATMON_LEVEL', 'Threat level') . ': ' . self::levelLabel($level)) . '">';
        foreach (['low', 'medium', 'high', 'critical'] as $l) {
            $meter .= '<span class="' . ($l === $level ? 'on' : '') . '" style="' . ($l === $level ? 'background:' . self::COLORS[$l] . ';color:#fff' : '') . '">' . self::e(self::levelLabel($l)) . '</span>';
        }
        $meter .= '</div>';

        $hi = (int) $t['sev']['high'] + (int) $t['sev']['critical'];
        $hiPrev = (int) $p['sev']['high'] + (int) $p['sev']['critical'];
        $cards = [
            [self::t('COM_MURUGUARD_THREATMON_DETECTED', 'Attacks detected'), (int) $t['detected'], self::deltaBadge(MuruguardThreatStats::delta((int) $t['detected'], (int) $p['detected']))],
            [self::t('COM_MURUGUARD_THREATMON_BLOCKED', 'Blocked'), (int) $t['blocked'], self::deltaBadge(MuruguardThreatStats::delta((int) $t['blocked'], (int) $p['blocked']), false)],
            [self::t('COM_MURUGUARD_THREATMON_HIGH', 'High and critical'), $hi, self::deltaBadge(MuruguardThreatStats::delta($hi, $hiPrev))],
            [self::t('COM_MURUGUARD_THREATMON_LOGIN_FAILS', 'Failed logins'), (int) $view['loginFailures'], ''],
            [self::t('COM_MURUGUARD_THREATMON_SCORE', 'Security score'), $score === null ? '-' : $score, ''],
        ];
        $o = '<div class="muru-tm-top"><div class="muru-tm-levelcard"><div class="muru-tm-k">' . self::e(self::t('COM_MURUGUARD_THREATMON_LEVEL', 'Threat level')) . '</div>' . $meter
            . '<p>' . self::e(self::t('COM_MURUGUARD_THREATMON_LEVEL_RULE', 'High: 10 or more high-severity events. Medium: at least one high-severity event, or 25 or more medium ones. Otherwise Low.')) . '</p></div><div class="muru-tm-cards">';
        foreach ($cards as [$k, $v, $d]) {
            $o .= '<div class="muru-tm-card"><div class="muru-tm-k">' . self::e($k) . '</div><div class="muru-tm-v">' . self::e($v) . $d . '</div></div>';
        }
        return $o . '</div></div>';
    }

    private static function box(string $title, string $inner, string $note = ''): string
    {
        return '<section class="muru-tm-box"><h4>' . self::e($title) . '</h4>' . ($note !== '' ? '<p class="muru-tm-note">' . self::e($note) . '</p>' : '') . $inner . '</section>';
    }

    /** One period's charts. */
    public static function renderPeriod(array $view, ?int $score): string
    {
        $o = self::statsRow($view, $score);
        $note = $view['listsNote'] !== '' ? self::t('COM_MURUGUARD_THREATMON_LISTS_NOTE_24H', 'This list covers today and yesterday (UTC).') : '';
        $rows = array_map(fn ($p) => [$p['label'], $p['t'], $p['b'], $p['s']['low'], $p['s']['medium'], $p['s']['high'], $p['s']['critical']], $view['series']);
        $o .= '<div class="muru-tm-grid"><div class="muru-tm-wide">' . self::box(self::t('COM_MURUGUARD_THREATMON_C1', 'Attacks over time'),
            self::legend() . self::stackedBars($view['series'])
            . self::dataTable([self::t('COM_MURUGUARD_THREATMON_COL_PERIOD', 'Period'), self::t('COM_MURUGUARD_THREATMON_COL_TOTAL', 'Total'), self::t('COM_MURUGUARD_THREATMON_BLOCKED', 'Blocked'), self::levelLabel('low'), self::levelLabel('medium'), self::levelLabel('high'), self::levelLabel('critical')], $rows)) . '</div>';
        $o .= self::box(self::t('COM_MURUGUARD_THREATMON_C2', 'Top attack rules'), self::hbars($view['rules'], '#4338ca', [self::class, 'ruleLabel']), $note);
        $o .= self::box(self::t('COM_MURUGUARD_THREATMON_C3', 'Attack types'), self::donut($view['types']), $note);
        return $o . '</div>';
    }

    /** The score trend over the last scans. */
    public static function renderScans(array $scans): string
    {
        $rows = array_map(fn ($s) => [gmdate('Y-m-d H:i', (int) $s['at']) . ' UTC', (int) $s['score'], (int) $s['high'], (int) $s['medium'], (int) $s['total']], $scans);
        return self::box(self::t('COM_MURUGUARD_THREATMON_C7', 'Security score trend'),
            self::lineChart($scans)
            . ($rows !== [] ? self::dataTable([self::t('COM_MURUGUARD_THREATMON_COL_SCAN', 'Scan'), self::t('COM_MURUGUARD_THREATMON_SCORE', 'Security score'), self::levelLabel('high'), self::levelLabel('medium'), self::t('COM_MURUGUARD_THREATMON_COL_TOTAL', 'Total')], $rows) : ''),
            self::t('COM_MURUGUARD_THREATMON_SCANS_NOTE', 'The last 5 scans, with the score the Dashboard showed for each.'));
    }

    public static function css(): string
    {
        return <<<'CSS'
.muru-tm{font-size:14px;line-height:1.5;color:#1f2937}
.muru-tm *{box-sizing:border-box}
.muru-tm h4{margin:0 0 8px;font-size:13px;font-weight:800;color:#111827}
.muru-tm-top{display:grid;grid-template-columns:minmax(240px,1fr) 3fr;gap:12px;margin-bottom:12px}
@media(max-width:900px){.muru-tm-top{grid-template-columns:1fr}}
.muru-tm-levelcard,.muru-tm-card,.muru-tm-box{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:12px 14px}
.muru-tm-levelcard p{font-size:11px;color:#6b7280;margin:8px 0 0}
.muru-tm-k{font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.03em}
.muru-tm-meter{display:flex;border-radius:8px;overflow:hidden;border:1px solid #e5e7eb;margin-top:6px}
.muru-tm-meter span{flex:1;text-align:center;padding:6px 2px;font-size:12px;font-weight:800;background:#f9fafb;color:#9ca3af}
.muru-tm-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
@media(max-width:560px){.muru-tm-cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
.muru-tm-v{font-size:24px;font-weight:800;color:#111827;display:flex;align-items:baseline;gap:6px}
.muru-tm-delta{font-size:11px;font-weight:700;border-radius:999px;padding:1px 6px}
.muru-tm-delta.bad{background:#fee2e2;color:#b91c1c}.muru-tm-delta.good{background:#dcfce7;color:#15803d}.muru-tm-delta.flat{background:#f3f4f6;color:#6b7280}
.muru-tm-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:12px}
@media(max-width:900px){.muru-tm-grid{grid-template-columns:1fr}}
.muru-tm-wide{grid-column:1/-1}
.muru-tm-svg{width:100%;height:auto;display:block}
.muru-tm-legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:#4b5563;margin-bottom:6px}
.muru-tm-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.muru-tm-hbars{list-style:none;margin:0;padding:0;display:grid;gap:6px}
.muru-tm-hbars li{display:grid;grid-template-columns:minmax(80px,38%) 1fr auto;gap:8px;align-items:center;font-size:12px}
.muru-tm-hl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.muru-tm-hb{background:#f3f4f6;border-radius:4px;height:10px;overflow:hidden}.muru-tm-hb b{display:block;height:100%;border-radius:4px}
.muru-tm-hn{font-weight:700;min-width:24px;text-align:right}
.muru-tm-donutwrap{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.muru-tm-dlegend{list-style:none;margin:0;padding:0;font-size:12px;display:grid;gap:3px}
.muru-tm-dlegend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.muru-tm-note{margin:0 0 8px;font-size:11px;color:#6b7280}
.muru-tm-empty{margin:0;color:#6b7280;font-size:12px}
.muru-tm-table{margin-top:8px;font-size:12px}.muru-tm-table summary{cursor:pointer;color:#4338ca;font-weight:700}
.muru-tm-table table{width:100%;border-collapse:collapse;margin-top:6px}.muru-tm-table th,.muru-tm-table td{border:1px solid #e5e7eb;padding:3px 6px;text-align:left}
CSS;
    }
}

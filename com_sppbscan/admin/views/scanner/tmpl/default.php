<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Toolbar\ToolbarInterface;

/** @var SppbscanViewScanner $this */
$fileFindings = $this->fileFindings ?? [];
$dbFindings   = $this->dbFindings   ?? [];
$suspiciousSU = !empty($dbFindings['superusers'])
    ? array_filter($dbFindings['superusers'], fn($u) => $u['suspicious'])
    : [];

$scanUrl    = 'index.php?option=com_sppbscan&task=scanner.scan';
$rescanUrl  = 'index.php?option=com_sppbscan&task=scanner.scan&rescan=1';
?>

<script src="https://cdn.tailwindcss.com"></script>
<style>
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fadeSlideUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
  @keyframes pulse-ring { 0%,100%{opacity:.4;transform:scale(1)} 50%{opacity:.8;transform:scale(1.08)} }
  .spinner { animation: spin 0.8s linear infinite; }
  .anim-in { animation: fadeSlideUp 0.4s ease both; }
  .shield-pulse { animation: pulse-ring 2.5s ease-in-out infinite; }
  /* keep Joomla admin from resetting our colours */
  #sppbscan-root * { box-sizing: border-box; }
  #sppbscan-root table { border-collapse: collapse; width: 100%; }
  #sppbscan-root pre  { white-space: pre-wrap; word-break: break-all; }
  #sppbscan-root code { font-family: ui-monospace, monospace; }
  /* scrollable table wrapper */
  .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
</style>

<div id="sppbscan-root" class="font-sans text-gray-800">

<?php
/* ── SPPB version warning banner ───────────────────────────────── */
$w = $this->sppbWarning ?? null;
if ($w !== null && $w['safe'] !== true):
    $version = htmlspecialchars($w['version']);
    $major   = (int)($w['major'] ?? 0);
    if ($w['safe'] === false && $major === 5):
        $borderColor = '#dc2626'; $bgColor = '#fef2f2'; $textColor = '#991b1b';
        $icon = '🚨'; $badgeClass = 'bg-red-600';
        $headline = "SP Page Builder {$version} is installed — this major version is vulnerable and has no patch.";
        $detail   = 'SPPB 5.x has its own separate known vulnerabilities. <strong>Update to SPPB 6.6.2+ immediately</strong>, or remove the component if you no longer use it.';
        $btnClass = 'bg-red-600 hover:bg-red-700';
    elseif ($w['safe'] === false):
        $borderColor = '#dc2626'; $bgColor = '#fef2f2'; $textColor = '#991b1b';
        $icon = '🚨'; $badgeClass = 'bg-red-600';
        $headline = "SP Page Builder {$version} is installed — vulnerable to the uploadCustomIcon RCE.";
        $detail   = 'Unauthenticated attackers can upload PHP webshells via Custom Icons in SPPB 6.x &lt; 6.6.2. <strong>Update to 6.6.2 immediately</strong> before doing anything else.';
        $btnClass = 'bg-red-600 hover:bg-red-700';
    else:
        $borderColor = '#d97706'; $bgColor = '#fffbeb'; $textColor = '#78350f';
        $icon = '⚠️'; $badgeClass = 'bg-amber-500';
        $headline = "SP Page Builder is installed but its version could not be determined.";
        $detail   = 'Check manually under <strong>Extensions → Manage → Manage</strong> and confirm it is 6.6.2 or newer.';
        $btnClass = 'bg-amber-500 hover:bg-amber-600';
    endif;
?>
<div class="anim-in flex gap-4 items-start rounded-xl border-l-4 p-4 mb-5 shadow-sm"
     style="background:<?= $bgColor ?>; border-color:<?= $borderColor ?>; color:<?= $textColor ?>">
    <div class="text-3xl flex-shrink-0 mt-0.5"><?= $icon ?></div>
    <div class="flex-1 min-w-0">
        <p class="font-bold text-sm leading-snug mb-1"><?= $headline ?></p>
        <p class="text-xs leading-relaxed opacity-90"><?= $detail ?></p>
        <a href="index.php?option=com_installer&view=update"
           class="inline-flex items-center gap-1.5 mt-3 px-4 py-1.5 rounded-lg text-white text-xs font-semibold shadow <?= $btnClass ?> transition-colors">
            🔧 Go to Extension Manager → Update
        </a>
    </div>
</div>
<?php endif; ?>

<!-- ── Loading overlay ────────────────────────────────────────── -->
<div id="sppbscan-overlay"
     class="hidden fixed inset-0 z-50 flex-col items-center justify-center gap-0
            bg-slate-900/80 backdrop-blur-sm">
    <div class="flex flex-col items-center text-center max-w-xs px-4">

        <!-- icon -->
        <div class="relative w-16 h-16 mb-5 flex items-center justify-center text-3xl">
            <div class="absolute inset-0 rounded-full border-4 border-white/10 border-t-blue-500 animate-spin"></div>
            <span class="animate-pulse">🛡️</span>
        </div>

        <h3 class="text-white font-bold text-base mb-2">Scanning your Joomla installation</h3>
        <p id="sppbscan-loading-status"
           class="text-slate-400 text-sm mb-5 min-h-[18px] transition-opacity duration-300">
            Starting scan…
        </p>

        <!-- indeterminate progress bar -->
        <div class="w-56 h-1.5 rounded-full bg-white/10 overflow-hidden mb-4">
            <div class="h-full rounded-full bg-gradient-to-r from-blue-500 to-blue-400 sppbscan-bar"></div>
        </div>

        <p class="text-slate-500 text-[11px] leading-relaxed">
            This usually takes 10–30 seconds depending on site size — please don't close this tab.
        </p>
    </div>
</div>

<style>
/* Tailwind has no built-in indeterminate-bar keyframe, so this one stays custom. */
.sppbscan-bar { width: 30%; animation: sppbscan-bar-slide 1.8s ease-in-out infinite; }
@keyframes sppbscan-bar-slide {
    0%   { width: 15%; margin-left: 0; }
    50%  { width: 55%; margin-left: 20%; }
    100% { width: 15%; margin-left: 100%; }
}
</style>


<!-- ── Support widget ─────────────────────────────────────────── -->
<details class="fixed top-16 right-5 z-40 group" id="support-widget">
    <summary class="list-none cursor-pointer select-none flex items-center gap-2
                    bg-white border border-gray-200 rounded-xl px-4 py-2 text-sm font-semibold
                    shadow-md hover:shadow-lg transition-all text-gray-700">
        💬 Support
        <span class="text-gray-400 group-open:rotate-180 transition-transform text-xs">▾</span>
    </summary>
    <div class="absolute right-0 mt-2 w-56 bg-white border border-gray-100 rounded-xl shadow-xl overflow-hidden">
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener"
           class="flex items-center gap-2 px-4 py-3 text-sm text-gray-700 hover:bg-gray-50 border-b border-gray-50 transition-colors">
            ☕ Buy me a coffee
        </a>
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener"
           class="flex items-center gap-2 px-4 py-3 text-sm text-gray-700 hover:bg-gray-50 border-b border-gray-50 transition-colors">
            ✉️ Email support
        </a>
        <a href="https://www.linkedin.com/in/zkranadevs/" target="_blank" rel="noopener"
           class="flex items-center gap-2 px-4 py-3 text-sm text-gray-700 hover:bg-gray-50 transition-colors">
            💼 LinkedIn
        </a>
    </div>
</details>

<?php if (!$this->scanned): ?>
<!-- ══════════════════════════════════════════════════════════════
     SCAN GATE
     ══════════════════════════════════════════════════════════════ -->
<div class="anim-in flex flex-col items-center justify-center min-h-80 gap-8 py-16">
    <!-- Animated shield -->
    <div class="relative flex items-center justify-center">
        <div class="absolute w-32 h-32 rounded-full bg-indigo-100 shield-pulse"></div>
        <div class="relative text-7xl">🛡️</div>
    </div>

    <div class="text-center max-w-lg">
        <h2 class="text-2xl font-extrabold text-gray-900 mb-3">SP Page Builder Infection Scanner</h2>
        <p class="text-gray-500 text-sm leading-relaxed">
            Click <strong class="text-gray-700">Run Scan</strong> to walk the filesystem and check the database
            for malware, rogue admin accounts, XSS injections, and defacement markers
            left behind by the SPPB <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs">uploadCustomIcon</code> RCE (pre-6.6.2).
        </p>
    </div>

    <form action="<?= Route::_($scanUrl) ?>" method="post" id="sppbscan-form">
        <?= HTMLHelper::_('form.token') ?>
        <button type="submit"
                class="inline-flex items-center gap-2 px-8 py-3.5 bg-indigo-600 hover:bg-indigo-700
                       text-white font-bold rounded-xl shadow-lg hover:shadow-xl
                       transition-all duration-200 hover:-translate-y-0.5 text-base">
            🔍 Run Scan
        </button>
    </form>

    <div class="flex items-center gap-2 text-xs text-gray-400 bg-gray-50 border border-gray-100 rounded-lg px-4 py-2">
        <span>⏱</span>
        <span>Typically takes 10–30 seconds &nbsp;·&nbsp; Results cached for 5 minutes</span>
    </div>
</div>

<?php else: ?>
<!-- ══════════════════════════════════════════════════════════════
     RESULTS
     ══════════════════════════════════════════════════════════════ -->

<!-- Re-scan bar -->
<div class="anim-in flex flex-wrap items-center justify-between gap-3
            bg-white border border-gray-200 rounded-xl px-5 py-3 mb-6 shadow-sm">
    <div class="flex items-center gap-2 text-sm text-gray-600">
        <span class="text-lg">🕐</span>
        Last scanned:
        <span class="font-bold text-gray-900"><?= date('Y-m-d H:i:s', $this->scanStartedAt) ?></span>
        <span class="text-gray-300">·</span>
        <span class="text-gray-400">Cached for 5 min</span>
    </div>
    <form action="<?= Route::_($rescanUrl) ?>" method="post" id="sppbscan-rescan-form" style="margin:0">
        <?= HTMLHelper::_('form.token') ?>
        <button type="submit"
                class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-gray-300
                       rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50
                       transition-colors shadow-sm">
            🔄 Re-scan now
        </button>
    </form>
</div>

<!-- Stats grid -->
<?php
$fc = count($fileFindings);
$suCount = count($suspiciousSU);
$menuCount = count($dbFindings['menu_xss'] ?? []);
$assetCount = count($dbFindings['sppb_assets'] ?? []) + count($dbFindings['rogue_iconfont'] ?? []);
$deface = count($dbFindings['template_defacement'] ?? []);
$stats = [
    ['icon'=>'📁', 'num'=>$fc,         'label'=>'Suspicious Files',
     'sub'=>$fc>0 ? "{$this->highCount} high · {$this->medCount} medium" : 'filesystem clean',
     'danger'=>$fc>0],
    ['icon'=>'👤', 'num'=>$suCount,    'label'=>'Rogue Super Users',
     'sub'=>$suCount>0 ? 'needs immediate review' : 'all accounts normal',
     'danger'=>$suCount>0],
    ['icon'=>'🔗', 'num'=>$menuCount,  'label'=>'Menu XSS Rows',
     'sub'=>$menuCount>0 ? 'injected payloads found' : 'menu table clean',
     'danger'=>$menuCount>0],
    ['icon'=>'🗄',  'num'=>$assetCount,'label'=>'Rogue Asset Rows',
     'sub'=>$assetCount>0 ? 'asset table tainted' : 'asset table clean',
     'danger'=>$assetCount>0],
    ['icon'=>'🖼',  'num'=>$deface,    'label'=>'Template Defacement',
     'sub'=>$deface>0 ? 'template styles modified' : 'templates intact',
     'danger'=>$deface>0],
];
?>
<div class="anim-in grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
    <?php foreach ($stats as $i => $s): ?>
    <div class="bg-white rounded-xl border <?= $s['danger'] ? 'border-red-200 shadow-red-50' : 'border-green-100' ?> shadow-sm p-4"
         style="animation-delay:<?= $i * 60 ?>ms">
        <div class="flex items-start justify-between mb-2">
            <span class="text-2xl"><?= $s['icon'] ?></span>
            <span class="<?= $s['danger'] ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600' ?> text-xs font-bold px-2 py-0.5 rounded-full">
                <?= $s['danger'] ? '⚠ ALERT' : '✓ OK' ?>
            </span>
        </div>
        <div class="text-3xl font-extrabold <?= $s['danger'] ? 'text-red-600' : 'text-green-600' ?> leading-none mb-1">
            <?= (int)$s['num'] ?>
        </div>
        <div class="text-xs font-semibold text-gray-700 mb-0.5"><?= $s['label'] ?></div>
        <div class="text-[11px] text-gray-400"><?= $s['sub'] ?></div>
    </div>
    <?php endforeach; ?>
</div>

<!-- Heuristic notice -->
<div class="flex items-center gap-3 bg-blue-50 border border-blue-200 rounded-xl px-5 py-3 mb-6 text-sm text-blue-800">
    <span class="text-xl flex-shrink-0">ℹ️</span>
    <span>This is a heuristic scanner. Pair it with a full server-side malware scan <strong>(ClamAV / Imunify360)</strong> before declaring the site clean.</span>
</div>

<?php
/* ── Helper: section card wrapper ── */
function sppb_section_open(string $id, string $emoji, string $title, int $count): void {
    $dot = $count > 0
        ? '<span class="inline-flex items-center justify-center w-5 h-5 bg-red-500 text-white text-[10px] font-bold rounded-full ml-2">' . $count . '</span>'
        : '<span class="inline-flex items-center justify-center w-5 h-5 bg-green-500 text-white text-[10px] font-bold rounded-full ml-2">✓</span>';
    echo '<details id="' . $id . '" ' . ($count > 0 ? 'open' : '') . ' class="group bg-white border border-gray-200 rounded-xl shadow-sm mb-4 overflow-hidden anim-in">';
    echo '<summary class="list-none cursor-pointer select-none flex items-center justify-between p-2 hover:bg-gray-50 transition-colors">';
    echo '<span class="flex items-center gap-2 font-bold text-gray-800">' . $emoji . ' <span>' . $title . '</span>' . $dot . '</span>';
    echo '<span class="text-gray-400 group-open:rotate-180 transition-transform duration-200 text-sm">▾</span>';
    echo '</summary>';
    echo '<div class="border-t border-gray-100 p-2">';
}
function sppb_section_close(): void {
    echo '</div></details>';
}
?>

<!-- ── 1. Files ──────────────────────────────────────────────── -->
<?php sppb_section_open('sec-files', '📁', 'Suspicious Files &amp; Folders', $fc); ?>
<?php if (empty($fileFindings)): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span>
        <span class="font-medium">No suspicious files detected.</span>
    </div>
<?php else: ?>
    <form action="index.php?option=com_sppbscan&task=scanner.delete" method="post"
          onsubmit="return confirm('Delete selected files/folders? This cannot be undone.');">
        <div class="flex items-center justify-between mb-3">
            <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                       onclick="document.querySelectorAll('.sppb-file-chk').forEach(c=>c.checked=this.checked)">
                Select all
            </label>
            <div class="flex items-center gap-2 text-xs text-gray-500">
                <span class="inline-flex items-center gap-1 px-2 py-0.5 bg-red-100 text-red-700 rounded-full font-semibold">🔴 <?= $this->highCount ?> high</span>
                <span class="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full font-semibold">🟡 <?= $this->medCount ?> medium</span>
            </div>
        </div>
        <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-gray-50 border-b border-gray-100">
                        <th class="w-10 px-4 py-3"></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Path</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Type</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Severity</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Reason</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Size</th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Modified</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-50">
                <?php foreach ($fileFindings as $f): ?>
                    <tr class="hover:bg-gray-50/60 transition-colors <?= $f['confidence']==='high' ? 'bg-red-50/30' : '' ?>">
                        <td class="px-4 py-3">
                            <input type="checkbox" class="sppb-file-chk w-4 h-4 rounded border-gray-300"
                                   name="targets[]" value="<?= htmlspecialchars($f['rel']) ?>">
                        </td>
                        <td class="px-4 py-3">
                            <code class="text-xs text-gray-600 break-all"><?= htmlspecialchars($f['rel']) ?></code>
                        </td>
                        <td class="px-4 py-3">
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-600">
                                <?= $f['type']==='dir' ? '📂 DIR' : '📄 FILE' ?>
                            </span>
                        </td>
                        <td class="px-4 py-3">
                            <?php if ($f['confidence']==='high'): ?>
                                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">🔴 High</span>
                            <?php else: ?>
                                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-700">🟡 Medium</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-3 text-xs text-amber-700"><?= htmlspecialchars($f['reason']) ?></td>
                        <td class="px-4 py-3 text-xs text-gray-500"><?= \SppbscanHelper::humanSize($f['size']) ?></td>
                        <td class="px-4 py-3 text-xs text-gray-400"><?= $f['mtime'] ? date('Y-m-d H:i',$f['mtime']) : '—' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🗑 Delete selected
            </button>
            <span class="text-xs text-gray-400">Only items flagged in this scan run can be deleted.</span>
        </div>
    </form>
<?php endif; ?>
<?php sppb_section_close(); ?>

<!-- ── 2. Super Users ─────────────────────────────────────────── -->
<?php sppb_section_open('sec-users', '👤', 'Super User Accounts', $suCount); ?>
<?php if (empty($dbFindings['superusers'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium">No super user accounts found.</span>
    </div>
<?php else: ?>
    <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-3">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-50 border-b border-gray-100">
                    <?php foreach (['ID','Name','Username','Email','Registered','Last Visit','Status'] as $h): ?>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= $h ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-50">
            <?php foreach ($dbFindings['superusers'] as $u): ?>
                <tr class="hover:bg-gray-50/60 transition-colors <?= $u['suspicious'] ? 'bg-red-50/40' : '' ?>">
                    <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= (int)$u['id'] ?></td>
                    <td class="px-4 py-3 font-medium"><?= htmlspecialchars($u['name']) ?></td>
                    <td class="px-4 py-3"><code class="text-xs bg-gray-100 px-1.5 py-0.5 rounded"><?= htmlspecialchars($u['username']) ?></code></td>
                    <td class="px-4 py-3 text-xs text-gray-500"><?= htmlspecialchars($u['email']) ?></td>
                    <td class="px-4 py-3 text-xs text-gray-400"><?= htmlspecialchars($u['registered']) ?></td>
                    <td class="px-4 py-3 text-xs text-gray-400"><?= htmlspecialchars($u['lastvisit']) ?></td>
                    <td class="px-4 py-3">
                        <?php if ($u['suspicious']): ?>
                            <div class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-xs font-bold mb-1">⚠ Suspicious</div>
                            <div class="text-xs text-red-600"><?= htmlspecialchars($u['why']) ?></div>
                        <?php else: ?>
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-100 text-green-700 text-xs font-bold">✓ Normal</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="text-xs text-gray-400">Remove rogue accounts via <strong>Users → Manage</strong> — do not delete your own account.</p>
<?php endif; ?>
<?php sppb_section_close(); ?>

<!-- ── 3. Menu XSS ───────────────────────────────────────────── -->
<?php sppb_section_open('sec-menu', '🔗', 'Menu XSS Injections', $menuCount); ?>
<?php if (empty($dbFindings['menu_xss'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium">No injected menu items found.</span>
    </div>
<?php else: ?>
    <form action="index.php?option=com_sppbscan&task=scanner.cleanmenu" method="post"
          onsubmit="return confirm('Surgically clean XSS from the selected menu rows?');">
        <div class="flex items-center justify-between mb-3">
            <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                       onclick="document.querySelectorAll('.sppb-menu-chk').forEach(c=>c.checked=this.checked)">
                Select all
            </label>
        </div>
        <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-gray-50 border-b border-gray-100">
                        <th class="w-10 px-4 py-3"></th>
                        <?php foreach (['ID','Title','Link','Matched Signatures'] as $h): ?>
                            <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= $h ?></th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-50">
                <?php foreach ($dbFindings['menu_xss'] as $m): ?>
                    <tr class="hover:bg-red-50/40 bg-red-50/20 transition-colors">
                        <td class="px-4 py-3"><input type="checkbox" class="sppb-menu-chk w-4 h-4 rounded border-gray-300" name="menu_xss_ids[]" value="<?= (int)$m['id'] ?>"></td>
                        <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= (int)$m['id'] ?></td>
                        <td class="px-4 py-3 font-medium"><?= htmlspecialchars($m['title']) ?></td>
                        <td class="px-4 py-3"><code class="text-xs break-all text-gray-600"><?= htmlspecialchars($m['link']) ?></code></td>
                        <td class="px-4 py-3 text-xs text-amber-700 font-medium"><?= htmlspecialchars(implode(', ', $m['matches'] ?? [])) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🧹 Clean selected rows
            </button>
            <span class="text-xs text-gray-400">Surgically removes XSS payload — legitimate menu settings are preserved.</span>
        </div>
    </form>
<?php endif; ?>
<?php sppb_section_close(); ?>

<!-- ── 4. SPPB Assets ────────────────────────────────────────── -->
<?php sppb_section_open('sec-assets', '🗄', 'SP Page Builder Asset Table', $assetCount); ?>
<?php if (empty($dbFindings['sppb_assets']) && empty($dbFindings['rogue_iconfont'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium">No suspicious rows found in sppagebuilder_assets.</span>
    </div>
<?php else: ?>
    <?php if (!empty($dbFindings['sppb_assets'])): ?>
        <h4 class="font-bold text-gray-700 mb-3">Injected payload rows</h4>
        <div class="space-y-2 mb-5">
            <?php foreach ($dbFindings['sppb_assets'] as $row): ?>
                <div class="bg-red-50 border border-red-100 rounded-xl p-4">
                    <pre class="text-xs text-red-800 overflow-x-auto"><?= htmlspecialchars(json_encode($row, JSON_PRETTY_PRINT)) ?></pre>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <?php if (!empty($dbFindings['rogue_iconfont'])): ?>
        <form action="index.php?option=com_sppbscan&task=scanner.deleteassets" method="post"
              onsubmit="return confirm('Delete selected rogue iconfont rows?');">
            <div class="flex items-center justify-between mb-3">
                <h4 class="font-bold text-gray-700">Rogue iconfont registrations
                    <span class="ml-1 inline-flex items-center justify-center w-5 h-5 bg-red-500 text-white text-[10px] font-bold rounded-full">
                        <?= count($dbFindings['rogue_iconfont']) ?>
                    </span>
                </h4>
                <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                    <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                           onclick="document.querySelectorAll('.sppb-asset-chk').forEach(c=>c.checked=this.checked)">
                    Select all
                </label>
            </div>
            <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-gray-50 border-b border-gray-100">
                            <th class="w-10 px-4 py-3"></th>
                            <?php foreach (['ID','Name','Title','Created','By','Assets'] as $h): ?>
                                <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= $h ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-50">
                    <?php foreach ($dbFindings['rogue_iconfont'] as $row): ?>
                        <tr class="hover:bg-red-50/40 bg-red-50/20 transition-colors">
                            <td class="px-4 py-3"><input type="checkbox" class="sppb-asset-chk w-4 h-4 rounded border-gray-300" name="rogue_asset_ids[]" value="<?= (int)$row['id'] ?>"></td>
                            <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= (int)$row['id'] ?></td>
                            <td class="px-4 py-3"><code class="text-xs bg-gray-100 px-1.5 py-0.5 rounded"><?= htmlspecialchars($row['name']) ?></code></td>
                            <td class="px-4 py-3 text-sm"><?= htmlspecialchars($row['title']) ?></td>
                            <td class="px-4 py-3 text-xs text-gray-400"><?= htmlspecialchars($row['created']) ?></td>
                            <td class="px-4 py-3 text-xs text-gray-500"><?= (int)$row['created_by'] ?></td>
                            <td class="px-4 py-3"><code class="text-xs text-red-600 break-all"><?= htmlspecialchars($row['assets']) ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🗑 Delete selected
            </button>
        </form>
    <?php endif; ?>
<?php endif; ?>
<?php sppb_section_close(); ?>

<!-- ── 5. Template defacement ────────────────────────────────── -->
<?php sppb_section_open('sec-template', '🖼', 'Template Styles Defacement', $deface); ?>
<?php if (empty($dbFindings['template_defacement'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium">No defacement markers found in template_styles.</span>
    </div>
<?php else: ?>
    <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-3">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-50 border-b border-gray-100">
                    <?php foreach (['ID','Template','Title','Matches'] as $h): ?>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= $h ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-50">
            <?php foreach ($dbFindings['template_defacement'] as $row): ?>
                <tr class="hover:bg-amber-50/40 bg-amber-50/20 transition-colors">
                    <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= (int)$row['id'] ?></td>
                    <td class="px-4 py-3"><code class="text-xs text-gray-600"><?= htmlspecialchars($row['template']) ?></code></td>
                    <td class="px-4 py-3 font-medium"><?= htmlspecialchars($row['title']) ?></td>
                    <td class="px-4 py-3 text-xs text-amber-700 font-medium"><?= htmlspecialchars(implode(', ', $row['matches'])) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="text-xs text-gray-400">Review and restore these template styles from a clean backup.</p>
<?php endif; ?>
<?php sppb_section_close(); ?>

<!-- Footer notice -->
<div class="flex items-center gap-3 bg-gray-50 border border-gray-200 rounded-xl px-5 py-4 mt-2 text-sm text-gray-500">
    <span class="text-xl">🧹</span>
    <span>When you're done, uninstall this component via
        <strong class="text-gray-700">Extensions → Manage → Manage</strong>
        to remove it from your site completely.
    </span>
</div>

<?php endif; // end $this->scanned ?>

</div><!-- #sppbscan-root -->

<script>
(function () {
    var forms   = [document.getElementById('sppbscan-form'), document.getElementById('sppbscan-rescan-form')];
    var overlay = document.getElementById('sppbscan-overlay');
    forms.forEach(function (form) {
        if (!form) return;
        form.addEventListener('submit', function () {
            sppbscanShowOverlay();
        });
    });

    // Close support widget when clicking outside
    document.addEventListener('click', function(e) {
        var widget = document.getElementById('support-widget');
        if (widget && widget.open && !widget.contains(e.target)) {
            widget.removeAttribute('open');
        }
    });
})();

function sppbscanShowOverlay() {
    var overlay  = document.getElementById('sppbscan-overlay');
    var statusEl = document.getElementById('sppbscan-loading-status');

    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
    overlay.classList.add('flex-col');

    var messages = [
        'Starting scan…',
        'Walking media/ and images/…',
        'Checking core entry points…',
        'Scanning extension code…',
        'Checking the database…',
        'Almost done…'
    ];
    var i = 0;
    statusEl.textContent = messages[0];
    // Cycles purely for perceived progress -- the real work is a single
    // synchronous PHP request, this has no connection to actual scan phase.
    setInterval(function () {
        i = (i + 1) % messages.length;
        statusEl.classList.add('opacity-0');
        setTimeout(function () {
            statusEl.textContent = messages[i];
            statusEl.classList.remove('opacity-0');
        }, 200);
    }, 2200);
}
</script>
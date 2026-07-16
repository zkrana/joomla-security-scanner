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
<script>
  // Scope every Tailwind utility class to elements inside #sppbscan-root,
  // and disable Tailwind's global reset (preflight). Without this, the
  // CDN build resets margin/box-sizing/line-height on EVERY element on
  // the admin page (not just ours), and several of its utility class
  // names collide 1:1 with Joomla's own Bootstrap admin classes
  // (.shadow-sm, .gap-2, .rounded, .border, ...) -- which is what was
  // breaking the sidebar, post-install messages, and other admin chrome
  // sitting outside this component.
  tailwind.config = {
    important: '#sppbscan-root',
    corePlugins: { preflight: false },
  };
</script>
<style>
  @keyframes sppbscan-spin { to { transform: rotate(360deg); } }
  @keyframes sppbscan-fade-up { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
  @keyframes sppbscan-pulse-ring { 0%,100%{opacity:.4;transform:scale(1)} 50%{opacity:.8;transform:scale(1.08)} }
  .spinner { animation: sppbscan-spin 0.8s linear infinite; }
  .anim-in { animation: sppbscan-fade-up 0.4s ease both; }
  .shield-pulse { animation: sppbscan-pulse-ring 2.5s ease-in-out infinite; }

  /* Base resets scoped to our component only, replacing what Tailwind's
     preflight would normally do globally (now disabled above). */
  #sppbscan-root, #sppbscan-root * { box-sizing: border-box; }
  #sppbscan-root { line-height: 1.55; -webkit-font-smoothing: antialiased; }
  #sppbscan-root h1, #sppbscan-root h2, #sppbscan-root h3, #sppbscan-root h4, #sppbscan-root p { margin: 0; }
  #sppbscan-root a { color: inherit; text-decoration: none; }
  #sppbscan-root button { font: inherit; cursor: pointer; background: none; border: 0; padding: 0; -webkit-appearance: none; appearance: none; }
  #sppbscan-root table { border-collapse: collapse; width: 100%; }
  #sppbscan-root pre  { white-space: pre-wrap; word-break: break-all; }
  #sppbscan-root code { font-family: ui-monospace, monospace; }

  /* scrollable table wrapper */
  .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

  /* tabs */
  .sppb-tab { color:#4b5563; background:transparent; border:1px solid transparent; cursor:pointer; }
  .sppb-tab:hover { background:#fff; color:#111827; }
  .sppb-tab.active { background:#fff; color:#4338ca; border-color:#e5e7eb; box-shadow:0 1px 2px rgba(0,0,0,.05); }
  .sppb-panel.active { display:block; }

  /* copy-path button feedback */
  .sppb-copy-btn.sppb-copied { color:#16a34a !important; background:#f0fdf4 !important; }

  /* ── Loading overlay & floating support widget ──────────────────
     Deliberately PLAIN CSS (no Tailwind utility classes). Both elements
     get re-parented to <body> at runtime via JS: Joomla's admin template
     applies a CSS transform to the content wrapper while animating the
     collapsible sidebar, and a transformed ancestor breaks
     `position: fixed` (it gets confined to that ancestor's box instead
     of the real viewport -- which is why the overlay was appearing
     pinned near the sidebar instead of centered). Re-parenting to <body>
     escapes that, but also takes these elements outside #sppbscan-root,
     so they can no longer rely on the Tailwind scoping above. */
  #sppbscan-overlay {
    position: fixed; inset: 0; z-index: 999999; display: none;
    align-items: center; justify-content: center;
    background: rgba(15,23,42,.86);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  #sppbscan-overlay.sppbscan-show { display: flex; }
  .sppbscan-overlay-card { display:flex; flex-direction:column; align-items:center; text-align:center; max-width:320px; padding:0 16px; }
  .sppbscan-overlay-icon-wrap { position:relative; width:64px; height:64px; margin-bottom:20px; display:flex; align-items:center; justify-content:center; font-size:30px; }
  .sppbscan-overlay-spinner { position:absolute; inset:0; border-radius:9999px; border:4px solid rgba(255,255,255,.12); border-top-color:#3b82f6; animation: sppbscan-spin .8s linear infinite; }
  .sppbscan-overlay-icon { animation: sppbscan-icon-pulse 1.6s ease-in-out infinite; }
  @keyframes sppbscan-icon-pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
  .sppbscan-overlay-title { color:#fff; font-weight:700; font-size:16px; margin:0 0 8px; }
  .sppbscan-overlay-status { color:#94a3b8; font-size:14px; margin:0 0 20px; min-height:18px; transition:opacity .3s; }
  .sppbscan-overlay-track { width:224px; height:6px; border-radius:9999px; background:rgba(255,255,255,.1); overflow:hidden; margin-bottom:16px; }
  .sppbscan-overlay-bar { height:100%; border-radius:9999px; background:linear-gradient(90deg,#3b82f6,#60a5fa); width:30%; animation: sppbscan-bar-slide 1.8s ease-in-out infinite; }
  @keyframes sppbscan-bar-slide { 0%{width:15%;margin-left:0} 50%{width:55%;margin-left:20%} 100%{width:15%;margin-left:100%} }
  .sppbscan-overlay-note { color:#64748b; font-size:11px; line-height:1.6; margin:0; }

  #support-widget { position: fixed; top: 64px; right: 20px; z-index: 999998; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  #support-widget summary { list-style:none; cursor:pointer; user-select:none; display:flex; align-items:center; gap:8px; background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:8px 16px; font-size:14px; font-weight:600; color:#374151; box-shadow:0 1px 3px rgba(0,0,0,.08); transition:box-shadow .2s; }
  #support-widget summary::-webkit-details-marker { display:none; }
  #support-widget summary:hover { box-shadow:0 4px 10px rgba(0,0,0,.1); }
  #support-widget .sppb-caret { color:#9ca3af; font-size:11px; transition:transform .2s; }
  #support-widget[open] .sppb-caret { transform: rotate(180deg); }
  #support-widget-menu { position:absolute; right:0; margin-top:8px; width:224px; background:#fff; border:1px solid #f3f4f6; border-radius:12px; box-shadow:0 10px 25px rgba(0,0,0,.12); overflow:hidden; }
  #support-widget-menu a { display:flex; align-items:center; gap:8px; padding:12px 16px; font-size:14px; color:#374151; text-decoration:none; border-bottom:1px solid #f9fafb; transition:background .15s; }
  #support-widget-menu a:last-child { border-bottom:0; }
  #support-widget-menu a:hover { background:#f9fafb; }

  /* ── Code-analysis modal ──────────────────────────────────────
     Same plain-CSS + re-parent-to-<body> treatment as the overlay and
     support widget above, for the same reason: Joomla's admin template
     transforms the content wrapper, which breaks `position: fixed`. */
  #sppb-modal { display:none; position:fixed; inset:0; z-index:999997; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  #sppb-modal.sppb-show { display:block; }
  #sppb-modal-backdrop { position:absolute; inset:0; background:rgba(15,23,42,.6); backdrop-filter:blur(2px); -webkit-backdrop-filter:blur(2px); }
  #sppb-modal-dialog { position:relative; max-width:720px; width:calc(100% - 32px); max-height:calc(100% - 64px); margin:32px auto; background:#fff; border-radius:16px; box-shadow:0 20px 50px rgba(0,0,0,.3); display:flex; flex-direction:column; overflow:hidden; }
  #sppb-modal-header { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; padding:18px 20px; border-bottom:1px solid #f1f5f9; }
  #sppb-modal-badge { display:inline-block; font-size:11px; font-weight:700; padding:2px 8px; border-radius:9999px; margin-bottom:6px; }
  #sppb-modal-badge.high { background:#fee2e2; color:#b91c1c; }
  #sppb-modal-badge.medium { background:#fef3c7; color:#92400e; }
  #sppb-modal-path { font-family:ui-monospace,monospace; font-size:12.5px; color:#374151; word-break:break-all; }
  #sppb-modal-close { flex-shrink:0; width:28px; height:28px; border-radius:9999px; background:#f3f4f6; color:#6b7280; font-size:14px; line-height:1; cursor:pointer; border:0; }
  #sppb-modal-close:hover { background:#e5e7eb; color:#111827; }
  #sppb-modal-body { padding:16px 20px 20px; overflow-y:auto; }
  .sppb-reason-block { padding:12px 0; border-bottom:1px solid #f1f5f9; }
  .sppb-reason-block:last-child { border-bottom:0; }
  .sppb-reason-block p { font-size:13px; color:#374151; line-height:1.55; margin:0 0 8px; }
  .sppb-reason-code-label { font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; color:#9ca3af; margin-bottom:4px; }
  .sppb-reason-code { font-family:ui-monospace,monospace; font-size:12px; line-height:1.6; color:#b91c1c; background:#fef2f2; border:1px solid #fee2e2; border-radius:8px; padding:10px 12px; white-space:pre-wrap; word-break:break-all; margin:0; }
</style>

<div id="sppbscan-root" class="font-sans text-gray-800 relative">

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

<!-- ── Loading overlay (re-parented to <body> at runtime, see script) ── -->
<div id="sppbscan-overlay">
    <div class="sppbscan-overlay-card">
        <div class="sppbscan-overlay-icon-wrap">
            <div class="sppbscan-overlay-spinner"></div>
            <span class="sppbscan-overlay-icon">🛡️</span>
        </div>
        <h3 class="sppbscan-overlay-title">Scanning your Joomla installation</h3>
        <p id="sppbscan-loading-status" class="sppbscan-overlay-status">Starting scan…</p>
        <div class="sppbscan-overlay-track"><div class="sppbscan-overlay-bar"></div></div>
        <p class="sppbscan-overlay-note">This usually takes 10–30 seconds depending on site size — please don't close this tab.</p>
    </div>
</div>

<!-- ── Support widget (re-parented to <body> at runtime, see script) ── -->
<details id="support-widget">
    <summary>
        💬 Support
        <span class="sppb-caret">▾</span>
    </summary>
    <div id="support-widget-menu">
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">☕ Buy me a coffee</a>
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">✉️ Email support</a>
        <a href="https://www.linkedin.com/in/zkranadevs/" target="_blank" rel="noopener">💼 LinkedIn</a>
    </div>
</details>

<!-- ── Code-analysis modal (re-parented to <body> at runtime, see script) ── -->
<div id="sppb-modal">
    <div id="sppb-modal-backdrop"></div>
    <div id="sppb-modal-dialog" role="dialog" aria-modal="true">
        <div id="sppb-modal-header">
            <div>
                <div id="sppb-modal-badge"></div>
                <code id="sppb-modal-path"></code>
            </div>
            <button type="button" id="sppb-modal-close" aria-label="Close">✕</button>
        </div>
        <div id="sppb-modal-body"></div>
    </div>
</div>

<?php if (!$this->scanned): ?>
<!-- ══════════════════════════════════════════════════════════════
     SCAN GATE
     ══════════════════════════════════════════════════════════════ -->
<?php
$scanAreas = $this->scanAreas ?? [];
$selAreas  = $this->selectedAreas ?? [];
// Empty previous selection = first visit -> default everything on.
$isAreaChecked = function (string $key) use ($selAreas): bool {
    return empty($selAreas) || in_array($key, $selAreas, true);
};
?>
<?php
$groupIcons = [
    'Upload & media directories'  => ['icon' => '🖼', 'chip' => 'bg-sky-100 text-sky-600'],
    'Extension & template code'   => ['icon' => '🧩', 'chip' => 'bg-violet-100 text-violet-600'],
    'Core &amp; webroot'          => ['icon' => '🏛', 'chip' => 'bg-amber-100 text-amber-600'],
    'Database'                    => ['icon' => '🗄', 'chip' => 'bg-emerald-100 text-emerald-600'],
];
$totalAreaCount = array_sum(array_map('count', $scanAreas));
?>
<div class="anim-in flex flex-col items-center gap-6 py-6">
    <!-- Hero -->
    <div class="w-full max-w-3xl text-center relative overflow-hidden rounded-2xl px-6 py-9"
         style="background:linear-gradient(135deg,#eef2ff 0%,#f5f3ff 55%,#fdf2f8 100%);">
        <div class="relative flex items-center justify-center mb-4">
            <div class="absolute w-24 h-24 rounded-full bg-indigo-200/50 shield-pulse"></div>
            <div class="relative text-5xl">🛡️</div>
        </div>
        <h2 class="text-2xl font-extrabold text-gray-900 mb-2">SP Page Builder Infection Scanner</h2>
        <p class="text-gray-500 text-sm leading-relaxed max-w-lg mx-auto">
            Choose the areas you want to scan, then click <strong class="text-gray-700">Run Scan</strong>.
            Checks the filesystem and database for malware, rogue admin accounts, XSS injections,
            disguised core files, and defacement markers left behind by the SPPB
            <code class="bg-white/70 px-1.5 py-0.5 rounded text-xs">uploadCustomIcon</code> RCE (pre-6.6.2).
        </p>
    </div>

    <form action="<?= Route::_($scanUrl) ?>" method="post" id="sppbscan-form" class="w-full max-w-3xl">
        <?= HTMLHelper::_('form.token') ?>
        <input type="hidden" name="areas_submitted" value="1">

        <div class="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden mb-6">
            <!-- Picker header / master select-all -->
            <div class="flex items-center justify-between gap-3 px-5 py-3 bg-gray-50 border-b border-gray-100">
                <span class="font-bold text-gray-800 text-sm flex items-center gap-2">🗂 Directories &amp; checks to scan</span>
                <label class="flex items-center gap-2 text-sm font-medium text-gray-600 cursor-pointer select-none">
                    <input type="checkbox" id="sppb-area-all"
                           class="w-4 h-4 rounded border-gray-300"
                           onclick="document.querySelectorAll('.sppb-area-chk').forEach(c=>c.checked=this.checked); sppbUpdateAreaCount();">
                    Select all
                </label>
            </div>

            <div class="p-5 grid gap-6 sm:grid-cols-2">
                <?php foreach ($scanAreas as $groupLabel => $areas):
                    $meta = $groupIcons[$groupLabel] ?? ['icon' => '📦', 'chip' => 'bg-gray-100 text-gray-500'];
                ?>
                    <div>
                        <div class="flex items-center gap-2 mb-2.5">
                            <span class="inline-flex items-center justify-center w-6 h-6 rounded-md text-xs flex-shrink-0 <?= $meta['chip'] ?>"><?= $meta['icon'] ?></span>
                            <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400"><?= $groupLabel ?></span>
                        </div>
                        <div class="space-y-1">
                            <?php foreach ($areas as $key => $label): ?>
                                <label class="flex items-start gap-2 text-sm text-gray-700 cursor-pointer hover:bg-gray-50 rounded-lg px-2 py-1.5 -mx-2 transition-colors">
                                    <input type="checkbox" name="scan_areas[]"
                                           value="<?= htmlspecialchars($key) ?>"
                                           class="sppb-area-chk mt-0.5 w-4 h-4 rounded border-gray-300 flex-shrink-0"
                                           onchange="sppbUpdateAreaCount()"
                                           <?= $isAreaChecked($key) ? 'checked' : '' ?>>
                                    <span class="leading-snug"><?= $label ?></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <div class="px-5 py-2.5 bg-gray-50 border-t border-gray-100 text-xs text-gray-400">
                <span id="sppb-area-count"><?= $totalAreaCount ?></span> of <?= $totalAreaCount ?> areas selected
            </div>
        </div>

        <div class="flex flex-col items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-8 py-3.5 bg-indigo-600 hover:bg-indigo-700
                           text-white font-bold rounded-xl shadow-lg hover:shadow-xl
                           transition-all duration-200 hover:-translate-y-0.5 text-base">
                🔍 Run Scan
            </button>
            <div class="flex items-center gap-2 text-xs text-gray-400 bg-gray-50 border border-gray-100 rounded-lg px-4 py-2">
                <span>⏱</span>
                <span>Typically takes 10–30 seconds &nbsp;·&nbsp; Results cached for 5 minutes</span>
            </div>
        </div>
    </form>
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
    <div class="flex items-center gap-2">
        <form action="index.php?option=com_sppbscan&task=scanner.reset" method="post" style="margin:0">
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit"
                    class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-gray-300
                           rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50
                           transition-colors shadow-sm">
                ⚙ Change scan areas
            </button>
        </form>
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
/* ── Tab navigation ── */
$tabs = [
    ['id' => 'files',    'emoji' => '📁', 'title' => 'Suspicious Files', 'count' => $fc],
    ['id' => 'users',    'emoji' => '👤', 'title' => 'Super Users',      'count' => $suCount],
    ['id' => 'menu',     'emoji' => '🔗', 'title' => 'Menu XSS',         'count' => $menuCount],
    ['id' => 'assets',   'emoji' => '🗄', 'title' => 'SPPB Assets',      'count' => $assetCount],
    ['id' => 'template', 'emoji' => '🖼', 'title' => 'Defacement',       'count' => $deface],
];
// Open on the first tab that has findings; otherwise the first tab.
$activeTab = $tabs[0]['id'];
foreach ($tabs as $t) { if ($t['count'] > 0) { $activeTab = $t['id']; break; } }
?>
<div class="anim-in bg-white border border-gray-200 rounded-xl shadow-sm mb-5 overflow-hidden">
    <div class="flex flex-wrap gap-1 p-1.5 bg-gray-50 border-b border-gray-100" role="tablist">
        <?php foreach ($tabs as $t): ?>
            <button type="button"
                    class="sppb-tab flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors"
                    data-tab="<?= $t['id'] ?>" role="tab">
                <span><?= $t['emoji'] ?></span>
                <span><?= $t['title'] ?></span>
                <?php if ($t['count'] > 0): ?>
                    <span class="sppb-tab-badge inline-flex items-center justify-center min-w-5 h-5 px-1.5 bg-red-500 text-white text-[10px] font-bold rounded-full"><?= $t['count'] ?></span>
                <?php else: ?>
                    <span class="sppb-tab-badge inline-flex items-center justify-center w-5 h-5 bg-green-500 text-white text-[10px] font-bold rounded-full">✓</span>
                <?php endif; ?>
            </button>
        <?php endforeach; ?>
    </div>
</div>

<?php
/* ── Helper: tab panel wrapper (ids match the $tabs 'id' above) ── */
function sppb_section_open(string $id, string $emoji, string $title, int $count): void {
    $panel = preg_replace('/^sec-/', '', $id);
    $dot = $count > 0
        ? '<span class="inline-flex items-center justify-center min-w-5 h-5 px-1.5 bg-red-500 text-white text-[10px] font-bold rounded-full ml-2">' . $count . '</span>'
        : '<span class="inline-flex items-center justify-center w-5 h-5 bg-green-500 text-white text-[10px] font-bold rounded-full ml-2">✓</span>';
    echo '<section class="sppb-panel hidden bg-white border border-gray-200 rounded-xl shadow-sm mb-4 overflow-hidden anim-in" data-panel="' . $panel . '">';
    echo '<div class="flex items-center gap-2 font-bold text-gray-800 p-3 border-b border-gray-100">' . $emoji . ' <span>' . $title . '</span>' . $dot . '</div>';
    echo '<div class="p-3">';
}
function sppb_section_close(): void {
    echo '</div></section>';
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
    <form action="index.php?option=com_sppbscan&task=scanner.delete" method="post" id="sppb-files-form">
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
                            <?php
                            $pathDir  = dirname($f['rel']);
                            $pathBase = basename($f['rel']);
                            $isProtectedEntry = in_array($f['rel'], ['index.php', 'administrator/index.php', 'api/index.php', 'includes/app.php'], true)
                                || (bool) preg_match('#^(administrator/)?templates/[^/]+/index\.php$#i', $f['rel']);
                            ?>
                            <div class="flex items-center gap-1.5 max-w-md">
                                <span class="flex-shrink-0 text-sm"><?= $f['type']==='dir' ? '📂' : '📄' ?></span>
                                <div class="min-w-0 flex-1 bg-gray-50 border border-gray-100 rounded-lg px-2.5 py-1.5 overflow-hidden">
                                    <div class="font-mono text-xs break-all leading-snug" title="<?= htmlspecialchars($f['rel']) ?>">
                                        <?php if ($pathDir !== '.'): ?>
                                            <span class="text-gray-400"><?= htmlspecialchars($pathDir) ?>/</span>
                                        <?php endif; ?>
                                        <span class="text-gray-800 font-semibold"><?= htmlspecialchars($pathBase) ?></span>
                                    </div>
                                    <?php if ($isProtectedEntry): ?>
                                        <div class="mt-1 inline-flex items-center gap-1 text-[10px] font-bold text-indigo-600">
                                            🛡 Required file — use Clean, not Delete
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <button type="button"
                                        class="sppb-copy-btn flex-shrink-0 w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 transition-colors"
                                        data-copy="<?= htmlspecialchars($f['rel']) ?>" title="Copy path" aria-label="Copy path">
                                    <span class="sppb-copy-icon">📋</span>
                                </button>
                            </div>
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
                        <td class="px-4 py-3 text-xs">
                            <?php
                            $reasonsList = $f['reasons'] ?? [$f['reason']];
                            $blocksHtml  = array_map(fn($r) => \SppbscanHelper::formatReasonForDisplay($r), $reasonsList);
                            $reasonsJson = htmlspecialchars(json_encode($blocksHtml), ENT_QUOTES);
                            ?>
                            <div class="text-amber-700 mb-1.5"><?= htmlspecialchars(\SppbscanHelper::shortReasonLabel($reasonsList)) ?></div>
                            <button type="button" class="sppb-code-issues-btn inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold bg-gray-100 text-gray-700 hover:bg-gray-200 transition-colors"
                                    data-path="<?= htmlspecialchars($f['rel']) ?>"
                                    data-confidence="<?= htmlspecialchars($f['confidence']) ?>"
                                    data-reasons="<?= $reasonsJson ?>">
                                🧬 Code Issues<?= count($reasonsList) > 1 ? ' (' . count($reasonsList) . ')' : '' ?>
                            </button>
                        </td>
                        <td class="px-4 py-3 text-xs text-gray-500"><?= \SppbscanHelper::humanSize($f['size']) ?></td>
                        <td class="px-4 py-3 text-xs text-gray-400"><?= $f['mtime'] ? date('Y-m-d H:i',$f['mtime']) : '—' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex flex-wrap items-center gap-3">
            <button type="submit"
                    formaction="index.php?option=com_sppbscan&task=scanner.cleancode"
                    onclick="return confirm('Surgically clean the selected files? A timestamped backup of each original is kept alongside it.');"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🧹 Clean code
            </button>
            <button type="submit"
                    formaction="index.php?option=com_sppbscan&task=scanner.delete"
                    onclick="return confirm('Delete selected files/folders? This cannot be undone.');"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🗑 Delete selected
            </button>
            <span class="text-xs text-gray-400">Required core/template entry files can't be deleted — use Clean code to strip injected code instead. Only items flagged in this scan run can be acted on.</span>
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
        <h4 class="font-bold text-gray-700 mb-3">
            Injected payload rows
            <span class="ml-1 inline-flex items-center justify-center w-5 h-5 bg-red-500 text-white text-[10px] font-bold rounded-full">
                <?= count($dbFindings['sppb_assets']) ?>
            </span>
        </h4>

        <div class="space-y-2 mb-5">

            <?php foreach ($dbFindings['sppb_assets'] as $row): ?>
                <details class="bg-red-50 border border-red-100 rounded-xl overflow-hidden">

                    <summary class="cursor-pointer px-4 py-3 flex items-center justify-between hover:bg-red-100/50">
                        <div class="flex items-center gap-3">
                            <span class="text-red-600">⚠️</span>

                            <div>
                                <span class="font-bold text-sm text-gray-800">
                                    #<?= (int)$row['id'] ?>
                                    <?= htmlspecialchars($row['name'] ?? '') ?>
                                </span>

                                <span class="text-xs text-gray-500 ml-2">
                                    <?= htmlspecialchars($row['type'] ?? '') ?>
                                </span>
                            </div>
                        </div>

                        <span class="text-xs text-gray-400">
                            <?= htmlspecialchars($row['created'] ?? '') ?>
                        </span>
                    </summary>

                    <div class="border-t border-red-100 p-4">
                        <pre class="text-xs text-red-800 overflow-x-auto"><?= htmlspecialchars(json_encode($row, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
                    </div>

                </details>
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
    // Re-parent fixed-position elements to <body> so they truly cover the
    // viewport / anchor to the real top-right corner. Joomla's admin
    // template applies a CSS transform to the content wrapper while
    // animating the collapsible sidebar, and a transformed ancestor
    // breaks `position: fixed` for any descendant, confining it to that
    // ancestor's box instead of the actual viewport.
    ['sppbscan-overlay', 'support-widget', 'sppb-modal'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el && el.parentNode !== document.body) {
            document.body.appendChild(el);
        }
    });

    sppbUpdateAreaCount();

    var forms = [document.getElementById('sppbscan-form'), document.getElementById('sppbscan-rescan-form')];
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

    // ── Tabbed results ──────────────────────────────────────────
    var tabs   = document.querySelectorAll('.sppb-tab');
    var panels = document.querySelectorAll('.sppb-panel');
    function activateTab(id) {
        tabs.forEach(function (t) { t.classList.toggle('active', t.getAttribute('data-tab') === id); });
        panels.forEach(function (p) {
            var on = p.getAttribute('data-panel') === id;
            p.classList.toggle('active', on);
            p.classList.toggle('hidden', !on);
        });
    }
    tabs.forEach(function (t) {
        t.addEventListener('click', function () { activateTab(t.getAttribute('data-tab')); });
    });
    if (tabs.length) { activateTab(<?= json_encode($activeTab ?? 'files') ?>); }

    // ── Code-analysis modal ─────────────────────────────────────
    // Event delegation, not per-button listeners -- the button set lives
    // inside a results panel that can be re-rendered/hidden by the tab
    // switcher above, so this stays correct regardless of DOM churn.
    document.addEventListener('click', function (e) {
        var issuesBtn = e.target.closest('.sppb-code-issues-btn');
        if (issuesBtn) { sppbOpenCodeModal(issuesBtn); return; }

        var copyBtn = e.target.closest('.sppb-copy-btn');
        if (copyBtn) { sppbCopyPath(copyBtn); return; }

        if (e.target.id === 'sppb-modal-close' || e.target.id === 'sppb-modal-backdrop') {
            sppbCloseCodeModal();
        }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') sppbCloseCodeModal();
    });
})();

function sppbOpenCodeModal(btn) {
    var modal   = document.getElementById('sppb-modal');
    var badge   = document.getElementById('sppb-modal-badge');
    var pathEl  = document.getElementById('sppb-modal-path');
    var bodyEl  = document.getElementById('sppb-modal-body');
    var conf    = btn.getAttribute('data-confidence') || 'medium';
    var blocks  = [];
    try { blocks = JSON.parse(btn.getAttribute('data-reasons') || '[]'); } catch (err) { blocks = []; }

    badge.textContent = conf === 'high' ? '🔴 High confidence' : '🟡 Needs manual review';
    badge.className = conf === 'high' ? 'high' : 'medium';
    pathEl.textContent = btn.getAttribute('data-path') || '';
    // blocks[] is pre-rendered, escaped HTML built server-side in
    // SppbscanHelper::formatReasonForDisplay() -- nothing user-controlled
    // reaches innerHTML unescaped here.
    bodyEl.innerHTML = blocks.join('');

    modal.classList.add('sppb-show');
    document.body.style.overflow = 'hidden';
}

function sppbCloseCodeModal() {
    var modal = document.getElementById('sppb-modal');
    modal.classList.remove('sppb-show');
    document.body.style.overflow = '';
}

function sppbCopyPath(btn) {
    var text = btn.getAttribute('data-copy') || '';
    var icon = btn.querySelector('.sppb-copy-icon');

    function showCopied() {
        if (!icon) return;
        icon.textContent = '✅';
        btn.classList.add('sppb-copied');
        setTimeout(function () {
            icon.textContent = '📋';
            btn.classList.remove('sppb-copied');
        }, 1200);
    }

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(showCopied).catch(function () { sppbCopyPathFallback(text, showCopied); });
    } else {
        sppbCopyPathFallback(text, showCopied);
    }
}

function sppbCopyPathFallback(text, onDone) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try { document.execCommand('copy'); onDone(); } catch (err) { /* clipboard unavailable -- no-op */ }
    document.body.removeChild(ta);
}

function sppbUpdateAreaCount() {
    var boxes = document.querySelectorAll('.sppb-area-chk');
    if (!boxes.length) return;
    var checked = 0;
    boxes.forEach(function (c) { if (c.checked) checked++; });

    var countEl = document.getElementById('sppb-area-count');
    if (countEl) countEl.textContent = checked;

    var master = document.getElementById('sppb-area-all');
    if (master) {
        master.checked = checked === boxes.length;
        master.indeterminate = checked > 0 && checked < boxes.length;
    }
}

function sppbscanShowOverlay() {
    var overlay  = document.getElementById('sppbscan-overlay');
    var statusEl = document.getElementById('sppbscan-loading-status');

    overlay.classList.add('sppbscan-show');

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
        statusEl.style.opacity = '0';
        setTimeout(function () {
            statusEl.textContent = messages[i];
            statusEl.style.opacity = '1';
        }, 200);
    }, 2200);
}
</script>
<?php
/**
 * @package     com_muruguard
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
use Joomla\CMS\Uri\Uri;

/** @var MuruguardViewScanner $this */
$fileFindings = $this->fileFindings ?? [];
$dbFindings   = $this->dbFindings   ?? [];
$suspiciousSU = !empty($dbFindings['superusers'])
    ? array_filter($dbFindings['superusers'], fn($u) => $u['suspicious'])
    : [];

$scanUrl    = 'index.php?option=com_muruguard&task=scanner.scan';
$rescanUrl  = 'index.php?option=com_muruguard&task=scanner.scan&rescan=1';
?>

<script src="https://cdn.tailwindcss.com"></script>
<script>
  // Scope every Tailwind utility class to elements inside #muruguard-root,
  // and disable Tailwind's global reset (preflight). Without this, the
  // CDN build resets margin/box-sizing/line-height on EVERY element on
  // the admin page (not just ours), and several of its utility class
  // names collide 1:1 with Joomla's own Bootstrap admin classes
  // (.shadow-sm, .gap-2, .rounded, .border, ...) -- which is what was
  // breaking the sidebar, post-install messages, and other admin chrome
  // sitting outside this component.
  tailwind.config = {
    important: '#muruguard-root',
    corePlugins: { preflight: false },
  };
</script>
<style>
  @keyframes muruguard-spin { to { transform: rotate(360deg); } }
  @keyframes muruguard-fade-up { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
  @keyframes muruguard-pulse-ring { 0%,100%{opacity:.4;transform:scale(1)} 50%{opacity:.8;transform:scale(1.08)} }
  .spinner { animation: muruguard-spin 0.8s linear infinite; }
  .anim-in { animation: muruguard-fade-up 0.4s ease both; }
  .shield-pulse { animation: muruguard-pulse-ring 2.5s ease-in-out infinite; }

  /* Base resets scoped to our component only, replacing what Tailwind's
     preflight would normally do globally (now disabled above). */
  #muruguard-root, #muruguard-root * { box-sizing: border-box; }
  #muruguard-root { line-height: 1.55; -webkit-font-smoothing: antialiased; }
  #muruguard-root h1, #muruguard-root h2, #muruguard-root h3, #muruguard-root h4, #muruguard-root p { margin: 0; }
  #muruguard-root a { color: inherit; text-decoration: none; }
  #muruguard-root button { font: inherit; cursor: pointer; background: none; border: 0; padding: 0; -webkit-appearance: none; appearance: none; }
  #muruguard-root table { border-collapse: collapse; width: 100%; }
  #muruguard-root pre  { white-space: pre-wrap; word-break: break-all; }
  #muruguard-root code { font-family: ui-monospace, monospace; }

  /* scrollable table wrapper */
  .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

  /* tabs */
  .muru-tab { color:#4b5563; background:transparent; border:1px solid transparent; cursor:pointer; }
  .muru-tab:hover { background:#fff; color:#111827; }
  .muru-tab.active { background:#fff; color:#4338ca; border-color:#e5e7eb; box-shadow:0 1px 2px rgba(0,0,0,.05); }
  .muru-panel.active { display:block; }

  /* settings sub-tabs (Scheduled Scanning / Setup Guide) */
  .muru-settings-tab { color:#4b5563; background:transparent; border:1px solid transparent; cursor:pointer; }
  .muru-settings-tab:hover { background:#fff; color:#111827; }
  .muru-settings-tab.active { background:#fff; color:#4338ca; border-color:#e5e7eb; box-shadow:0 1px 2px rgba(0,0,0,.05); }

  /* copy-path button feedback */
  .muru-copy-btn.muru-copied { color:#16a34a !important; background:#f0fdf4 !important; }

  /* settings toggle switch */
  .muru-switch { display:inline-flex; cursor:pointer; }
  .muru-switch input { position:absolute; opacity:0; width:0; height:0; }
  .muru-switch-track { width:44px; height:24px; border-radius:9999px; background:#d1d5db; position:relative; transition:background .2s; flex-shrink:0; }
  .muru-switch-thumb { position:absolute; top:2px; left:2px; width:20px; height:20px; border-radius:9999px; background:#fff; box-shadow:0 1px 2px rgba(0,0,0,.15); transition:transform .2s; }
  .muru-switch input:checked + .muru-switch-track { background:#4338ca; }
  .muru-switch input:checked + .muru-switch-track .muru-switch-thumb { transform:translateX(20px); }
  .muru-switch input:focus-visible + .muru-switch-track { box-shadow:0 0 0 3px rgba(67,56,202,.3); }

  /* ── Loading overlay & floating header-actions widget ────────────
     Deliberately PLAIN CSS (no Tailwind utility classes). Both the
     overlay and the header-actions wrapper (Settings + Support) get
     re-parented to <body> at runtime via JS: Joomla's admin template
     applies a CSS transform to the content wrapper while animating the
     collapsible sidebar, and a transformed ancestor breaks
     `position: fixed` (it gets confined to that ancestor's box instead
     of the real viewport -- which is why the overlay was appearing
     pinned near the sidebar instead of centered). Re-parenting to <body>
     escapes that, but also takes these elements outside #muruguard-root,
     so they can no longer rely on the Tailwind scoping above. */
  #muruguard-overlay {
    position: fixed; inset: 0; z-index: 999999; display: none;
    align-items: center; justify-content: center;
    background: rgba(15,23,42,.86);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  #muruguard-overlay.muruguard-show { display: flex; }
  .muruguard-overlay-card { display:flex; flex-direction:column; align-items:center; text-align:center; max-width:320px; padding:0 16px; }
  .muruguard-overlay-icon-wrap { position:relative; width:64px; height:64px; margin-bottom:20px; display:flex; align-items:center; justify-content:center; font-size:30px; }
  .muruguard-overlay-spinner { position:absolute; inset:0; border-radius:9999px; border:4px solid rgba(255,255,255,.12); border-top-color:#3b82f6; animation: muruguard-spin .8s linear infinite; }
  .muruguard-overlay-icon { animation: muruguard-icon-pulse 1.6s ease-in-out infinite; }
  @keyframes muruguard-icon-pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
  .muruguard-overlay-title { color:#fff; font-weight:700; font-size:16px; margin:0 0 8px; }
  .muruguard-overlay-status { color:#94a3b8; font-size:14px; margin:0 0 20px; min-height:18px; transition:opacity .3s; }
  .muruguard-overlay-track { width:224px; height:6px; border-radius:9999px; background:rgba(255,255,255,.1); overflow:hidden; margin-bottom:16px; }
  .muruguard-overlay-bar { height:100%; border-radius:9999px; background:linear-gradient(90deg,#3b82f6,#60a5fa); width:30%; animation: muruguard-bar-slide 1.8s ease-in-out infinite; }
  @keyframes muruguard-bar-slide { 0%{width:15%;margin-left:0} 50%{width:55%;margin-left:20%} 100%{width:15%;margin-left:100%} }
  .muruguard-overlay-note { color:#64748b; font-size:11px; line-height:1.6; margin:0; }

  #muru-header-actions { position: fixed; top: 64px; right: 20px; z-index: 999998; display: flex; align-items: flex-start; gap: 8px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  #muru-settings-btn { display:flex; align-items:center; gap:8px; background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:8px 16px; font-size:14px; font-weight:600; color:#374151; box-shadow:0 1px 3px rgba(0,0,0,.08); transition:box-shadow .2s, background .2s, color .2s; cursor:pointer; }
  #muru-settings-btn:hover { box-shadow:0 4px 10px rgba(0,0,0,.1); }
  #muru-settings-btn.muru-settings-open { background:#4338ca; border-color:#4338ca; color:#fff; }
  #support-widget { position: relative; }
  #support-widget summary { list-style:none; cursor:pointer; user-select:none; display:flex; align-items:center; gap:8px; background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:8px 16px; font-size:14px; font-weight:600; color:#374151; box-shadow:0 1px 3px rgba(0,0,0,.08); transition:box-shadow .2s; }
  #support-widget summary::-webkit-details-marker { display:none; }
  #support-widget summary:hover { box-shadow:0 4px 10px rgba(0,0,0,.1); }
  #support-widget .muru-caret { color:#9ca3af; font-size:11px; transition:transform .2s; }
  #support-widget[open] .muru-caret { transform: rotate(180deg); }
  #support-widget-menu { position:absolute; right:0; margin-top:8px; width:224px; background:#fff; border:1px solid #f3f4f6; border-radius:12px; box-shadow:0 10px 25px rgba(0,0,0,.12); overflow:hidden; }
  #support-widget-menu a { display:flex; align-items:center; gap:8px; padding:12px 16px; font-size:14px; color:#374151; text-decoration:none; border-bottom:1px solid #f9fafb; transition:background .15s; }
  #support-widget-menu a:last-child { border-bottom:0; }
  #support-widget-menu a:hover { background:#f9fafb; }

  /* ── Code-analysis modal ──────────────────────────────────────
     Same plain-CSS + re-parent-to-<body> treatment as the overlay and
     support widget above, for the same reason: Joomla's admin template
     transforms the content wrapper, which breaks `position: fixed`. */
  #muru-modal { display:none; position:fixed; inset:0; z-index:999997; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  #muru-modal.muru-show { display:block; }
  #muru-modal-backdrop { position:absolute; inset:0; background:rgba(15,23,42,.6); backdrop-filter:blur(2px); -webkit-backdrop-filter:blur(2px); }
  #muru-modal-dialog { position:relative; max-width:720px; width:calc(100% - 32px); max-height:calc(100% - 64px); margin:32px auto; background:#fff; border-radius:16px; box-shadow:0 20px 50px rgba(0,0,0,.3); display:flex; flex-direction:column; overflow:hidden; }
  #muru-modal-header { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; padding:18px 20px; border-bottom:1px solid #f1f5f9; }
  #muru-modal-badge { display:inline-block; font-size:11px; font-weight:700; padding:2px 8px; border-radius:9999px; margin-bottom:6px; }
  #muru-modal-badge.high { background:#fee2e2; color:#b91c1c; }
  #muru-modal-badge.medium { background:#fef3c7; color:#92400e; }
  #muru-modal-path { font-family:ui-monospace,monospace; font-size:12.5px; color:#374151; word-break:break-all; }
  #muru-modal-close { flex-shrink:0; width:28px; height:28px; border-radius:9999px; background:#f3f4f6; color:#6b7280; font-size:14px; line-height:1; cursor:pointer; border:0; }
  #muru-modal-close:hover { background:#e5e7eb; color:#111827; }
  #muru-modal-body { padding:16px 20px 20px; overflow-y:auto; }
  .muru-reason-block { padding:12px 0; border-bottom:1px solid #f1f5f9; }
  .muru-reason-block:last-child { border-bottom:0; }
  .muru-reason-block p { font-size:13px; color:#374151; line-height:1.55; margin:0 0 8px; }
  .muru-reason-code-label { font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; color:#9ca3af; margin-bottom:4px; }
  .muru-reason-code { font-family:ui-monospace,monospace; font-size:12px; line-height:1.6; color:#b91c1c; background:#fef2f2; border:1px solid #fee2e2; border-radius:8px; padding:10px 12px; white-space:pre-wrap; word-break:break-all; margin:0; }
  .muru-diff-block { padding:12px 0; border-top:2px dashed #e5e7eb; margin-top:4px; }
  .muru-diff-label { font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; margin-bottom:4px; }
  .muru-diff-label-before { color:#b91c1c; }
  .muru-diff-label-after { color:#15803d; margin-top:10px; }
  .muru-diff-removed { font-family:ui-monospace,monospace; font-size:12px; line-height:1.6; color:#b91c1c; background:#fef2f2; border:1px solid #fee2e2; border-radius:8px; padding:10px 12px; white-space:pre-wrap; word-break:break-all; margin:0; text-decoration:line-through; text-decoration-color:#fca5a5; }
  .muru-diff-added { font-family:ui-monospace,monospace; font-size:12px; line-height:1.6; color:#15803d; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:10px 12px; white-space:pre-wrap; word-break:break-all; margin:0; }

  /* ── Scan-area picker modal -- same fixed/re-parent-to-<body> treatment
     as the code-analysis modal above, for the same reason (Joomla's
     admin template transforms the content wrapper, which breaks
     `position: fixed`). */
  #muru-scan-modal { display:none; position:fixed; inset:0; z-index:999997; align-items:center; justify-content:center; padding:24px; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  #muru-scan-modal.muru-show { display:flex; }
  #muru-scan-modal-backdrop { position:absolute; inset:0; background:rgba(15,23,42,.65); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); animation:muruguard-fade-up .25s ease both; }
  #muru-scan-modal-dialog { position:relative; max-width:840px; width:100%; max-height:calc(100vh - 48px); background:#fff; border-radius:20px; box-shadow:0 25px 60px rgba(15,23,42,.35); display:flex; flex-direction:column; overflow:hidden; animation:muruguard-fade-up .3s ease both; }
  #muru-scan-modal-header { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:20px 24px; background:linear-gradient(135deg,#eef2ff 0%,#f5f3ff 55%,#fdf2f8 100%); border-bottom:1px solid #eef0f4; flex-shrink:0; }
  #muru-scan-modal-header-title { display:flex; align-items:center; gap:12px; }
  #muru-scan-modal-header-icon { flex-shrink:0; display:flex; align-items:center; justify-content:center; width:40px; height:40px; border-radius:12px; background:rgba(255,255,255,.7); font-size:19px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
  #muru-scan-modal-header h3 { font-size:15px; font-weight:800; color:#1f2937; margin:0; }
  #muru-scan-modal-header p { font-size:12px; color:#6b7280; margin:2px 0 0; }
  #muru-scan-modal-close { flex-shrink:0; width:30px; height:30px; border-radius:9999px; background:rgba(255,255,255,.8); color:#6b7280; font-size:14px; line-height:1; cursor:pointer; border:0; transition:background .15s, color .15s; }
  #muru-scan-modal-close:hover { background:#fff; color:#111827; }
  #muru-scan-modal-body { padding:20px 24px; overflow-y:auto; background:#fafbfc; }
  #muru-scan-modal-selectall { display:flex; align-items:center; justify-content:flex-end; gap:8px; margin-bottom:16px; }
  #muru-scan-modal-selectall label { display:inline-flex; align-items:center; gap:7px; font-size:12.5px; font-weight:700; color:#4338ca; background:#eef2ff; border:1px solid #e0e7ff; border-radius:9999px; padding:6px 14px; cursor:pointer; user-select:none; transition:background .15s, box-shadow .15s; }
  #muru-scan-modal-selectall label:hover { background:#e0e7ff; }
  .muru-scan-group { background:#fff; border:1px solid #eef0f4; border-radius:14px; padding:16px; transition:box-shadow .15s, border-color .15s; }
  .muru-scan-group:hover { box-shadow:0 2px 10px rgba(15,23,42,.05); border-color:#e5e7eb; }
  .muru-area-chk { accent-color:#4338ca; }
  #muru-scan-modal-footer { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:16px 24px; border-top:1px solid #eef0f4; background:#fff; flex-shrink:0; }
</style>

<div id="muruguard-root" class="font-sans text-gray-800 relative">

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
<div id="muruguard-overlay">
    <div class="muruguard-overlay-card">
        <div class="muruguard-overlay-icon-wrap">
            <div class="muruguard-overlay-spinner"></div>
            <span class="muruguard-overlay-icon">🛡️</span>
        </div>
        <h3 class="muruguard-overlay-title"><?= Text::_('COM_MURUGUARD_OVERLAY_TITLE') ?></h3>
        <p id="muruguard-loading-status" class="muruguard-overlay-status"><?= Text::_('COM_MURUGUARD_OVERLAY_STARTING') ?></p>
        <div class="muruguard-overlay-track"><div class="muruguard-overlay-bar"></div></div>
        <p class="muruguard-overlay-note"><?= Text::_('COM_MURUGUARD_OVERLAY_NOTE') ?></p>
    </div>
</div>

<!-- ── Settings + Support (re-parented to <body> at runtime, see script) ── -->
<div id="muru-header-actions">
    <button type="button" id="muru-settings-btn" aria-pressed="false">
        ⚙️ <?= Text::_('COM_MURUGUARD_SETTINGS_BTN') ?>
    </button>
    <details id="support-widget">
        <summary>
            💬 <?= Text::_('COM_MURUGUARD_SUPPORT_BTN') ?>
            <span class="muru-caret">▾</span>
        </summary>
        <div id="support-widget-menu">
            <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">☕ <?= Text::_('COM_MURUGUARD_SUPPORT_COFFEE') ?></a>
            <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">✉️ <?= Text::_('COM_MURUGUARD_SUPPORT_EMAIL') ?></a>
            <a href="https://www.linkedin.com/in/zkranadevs/" target="_blank" rel="noopener">💼 <?= Text::_('COM_MURUGUARD_SUPPORT_LINKEDIN') ?></a>
        </div>
    </details>
</div>

<!-- ── Code-analysis modal (re-parented to <body> at runtime, see script) ── -->
<div id="muru-modal">
    <div id="muru-modal-backdrop"></div>
    <div id="muru-modal-dialog" role="dialog" aria-modal="true">
        <div id="muru-modal-header">
            <div>
                <div id="muru-modal-badge"></div>
                <code id="muru-modal-path"></code>
            </div>
            <button type="button" id="muru-modal-close" aria-label="<?= Text::_('COM_MURUGUARD_MODAL_CLOSE') ?>">✕</button>
        </div>
        <div id="muru-modal-body"></div>
    </div>
</div>

<!-- ══════════════════════════════════════════════════════════════
     SETTINGS PANEL -- hidden by default, toggled by #muru-settings-btn.
     Lives outside #muru-main-content (see below) so it works regardless
     of scan state, and is never shown at the same time as the results/
     scan-gate content.
     ══════════════════════════════════════════════════════════════ -->
<div id="muru-settings-panel" class="hidden">
    <div class="flex items-center justify-between mb-6">
        <h2 class="text-lg font-bold text-gray-800 flex items-center gap-2">⚙️ <?= Text::_('COM_MURUGUARD_SETTINGS_HEADING') ?></h2>
        <button type="button" id="muru-settings-back" class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition-colors shadow-sm">
            ← <?= Text::_('COM_MURUGUARD_SETTINGS_BACK') ?>
        </button>
    </div>

    <div class="flex flex-wrap gap-1 p-1.5 bg-gray-50 border border-gray-200 rounded-xl mb-5 w-fit">
        <button type="button" class="muru-settings-tab active flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors" data-settings-tab="protection">
            🛡️ <?= Text::_('COM_MURUGUARD_SETTINGS_TAB_PROTECTION') ?>
            <?php if ($this->shieldEnabled): ?>
                <span class="inline-flex items-center justify-center w-2 h-2 rounded-full bg-emerald-500"></span>
            <?php endif; ?>
        </button>
        <button type="button" class="muru-settings-tab flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors" data-settings-tab="scheduled">
            ⏰ <?= Text::_('COM_MURUGUARD_SETTINGS_TAB_SCHEDULED') ?>
        </button>
        <button type="button" class="muru-settings-tab flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors" data-settings-tab="guide">
            📖 <?= Text::_('COM_MURUGUARD_SETTINGS_TAB_GUIDE') ?>
        </button>
    </div>

    <div class="muru-settings-tabpanel hidden" data-settings-panel="scheduled">
        <?php if (!$this->canAdmin): ?>
        <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
            <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2 mb-3">⏰ <?= Text::_('COM_MURUGUARD_SCHEDULED_TITLE') ?></h3>
            <div class="flex items-center gap-2 text-xs text-gray-500 mb-4">
                <span class="text-base">🔒</span>
                <span><?= Text::_('COM_MURUGUARD_SCHEDULED_READONLY') ?></span>
            </div>
            <div class="text-xs text-gray-600 space-y-1.5">
                <div><?= Text::_('COM_MURUGUARD_STATUS_LABEL') ?>: <span class="font-semibold text-gray-800"><?= $this->cronEnabled ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?></span></div>
                <div><?= Text::_('COM_MURUGUARD_ALERT_EMAIL_STATUS_LABEL') ?>: <span class="font-semibold text-gray-800"><?= $this->alertEmail !== '' ? htmlspecialchars($this->alertEmail) : Text::_('COM_MURUGUARD_NOT_SET') ?></span></div>
                <?php if ($this->lastScheduledRun): ?>
                    <div><?= Text::_('COM_MURUGUARD_LAST_RUN_LABEL') ?>: <span class="font-semibold text-gray-800"><?= date('Y-m-d H:i:s', $this->lastScheduledRun) ?></span></div>
                <?php else: ?>
                    <div><?= Text::_('COM_MURUGUARD_LAST_RUN_LABEL') ?>: <span class="font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_NEVER') ?></span></div>
                <?php endif; ?>
            </div>
        </div>
        <?php else: ?>
        <form action="<?= Route::_('index.php?option=com_muruguard&task=scanner.savesettings') ?>" method="post">
            <?= HTMLHelper::_('form.token') ?>

            <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
                <div class="flex items-start justify-between gap-4 mb-1">
                    <div>
                        <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2">⏰ <?= Text::_('COM_MURUGUARD_SCHEDULED_TITLE') ?></h3>
                        <p class="text-xs text-gray-500 mt-1 max-w-xl"><?= Text::_('COM_MURUGUARD_SCHEDULED_DESC') ?></p>
                    </div>
                    <label class="muru-switch flex-shrink-0" title="<?= $this->cronEnabled ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?>">
                        <input type="checkbox" id="muru-cron-enabled" name="cron_enabled" value="1" <?= $this->cronEnabled ? 'checked' : '' ?>>
                        <span class="muru-switch-track"><span class="muru-switch-thumb"></span></span>
                    </label>
                </div>

                <?php if ($this->lastScheduledRun): ?>
                    <div class="text-xs text-gray-500 mb-4">
                        🕐 <?= Text::_('COM_MURUGUARD_LAST_RUN_LABEL') ?>: <span class="font-semibold text-gray-700"><?= date('Y-m-d H:i:s', $this->lastScheduledRun) ?></span>
                    </div>
                <?php else: ?>
                    <div class="text-xs text-gray-400 mb-4"><?= Text::_('COM_MURUGUARD_SCHEDULED_NEVER_RUN') ?></div>
                <?php endif; ?>

                <div class="grid sm:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-xs font-bold text-gray-600 mb-1.5" for="muru-cron-token"><?= Text::_('COM_MURUGUARD_TOKEN_LABEL') ?></label>
                        <div class="flex gap-2">
                            <input type="text" id="muru-cron-token" name="cron_token" value="<?= htmlspecialchars($this->cronToken) ?>"
                                   placeholder="<?= Text::_('COM_MURUGUARD_TOKEN_PLACEHOLDER') ?>"
                                   class="flex-1 min-w-0 px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400">
                            <button type="button" id="muru-cron-generate" class="flex-shrink-0 px-3 py-2 border border-gray-300 rounded-lg text-xs font-semibold text-gray-600 bg-gray-50 hover:bg-gray-100 transition-colors">🎲 <?= Text::_('COM_MURUGUARD_GENERATE_BTN') ?></button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-600 mb-1.5" for="muru-alert-email"><?= Text::_('COM_MURUGUARD_ALERT_EMAIL_FIELD_LABEL') ?></label>
                        <input type="email" id="muru-alert-email" name="alert_email" value="<?= htmlspecialchars($this->alertEmail) ?>"
                               placeholder="<?= Text::_('COM_MURUGUARD_EMAIL_PLACEHOLDER') ?>"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400">
                    </div>
                </div>

                <div class="mb-5">
                    <label class="block text-xs font-bold text-gray-600 mb-1.5"><?= Text::_('COM_MURUGUARD_WEBCRON_URL_LABEL') ?> <span class="font-normal text-gray-400"><?= Text::_('COM_MURUGUARD_WEBCRON_URL_HINT') ?></span></label>
                    <div class="flex items-center gap-2 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2">
                        <code id="muru-webcron-url" class="flex-1 min-w-0 text-xs text-gray-600 break-all"><?= htmlspecialchars(Uri::root() . 'administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=' . $this->cronToken) ?></code>
                        <button type="button" class="muru-copy-btn flex-shrink-0 w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 transition-colors"
                                data-copy="<?= htmlspecialchars(Uri::root() . 'administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=' . $this->cronToken) ?>" title="<?= Text::_('COM_MURUGUARD_COPY_URL') ?>" aria-label="<?= Text::_('COM_MURUGUARD_COPY_URL') ?>">
                            <span class="muru-copy-icon">📋</span>
                        </button>
                    </div>
                </div>

                <button type="submit" class="inline-flex items-center gap-1.5 px-5 py-2 rounded-lg text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 transition-colors shadow-sm">
                    💾 <?= Text::_('COM_MURUGUARD_SAVE_SETTINGS_BTN') ?>
                </button>
            </div>
        </form>
        <?php endif; ?>
    </div>

    <div class="muru-settings-tabpanel hidden" data-settings-panel="guide">
        <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
            <div class="flex items-start justify-between gap-4 mb-4">
                <div>
                    <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2">📖 <?= Text::_('COM_MURUGUARD_SETUP_GUIDE_TITLE') ?></h3>
                    <p class="text-xs text-gray-500 mt-1 max-w-xl"><?= Text::_('COM_MURUGUARD_SETUP_GUIDE_DESC') ?></p>
                </div>
                <a href="index.php?option=com_config&view=component&component=com_muruguard"
                   class="flex-shrink-0 inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 transition-colors shadow-sm whitespace-nowrap">
                    🔧 <?= Text::_('COM_MURUGUARD_OPEN_GLOBAL_CONFIG') ?>
                </a>
            </div>

            <div class="text-xs text-gray-600 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2 mb-5">
                <?= Text::_('COM_MURUGUARD_GLOBAL_CONFIG_PATH_NOTE') ?>
            </div>

            <div class="space-y-4">
                <div class="border-l-2 border-indigo-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_MAXSIZE_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_MAXSIZE_DESC') ?></p>
                </div>
                <div class="border-l-2 border-indigo-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_EXTRAROOT_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_EXTRAROOT_DESC') ?></p>
                </div>
                <div class="border-l-2 border-indigo-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_IGNOREDPATHS_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_IGNOREDPATHS_DESC') ?></p>
                </div>
                <div class="border-l-2 border-indigo-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_SCHEDULED_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_SCHEDULED_DESC') ?></p>
                </div>
            </div>
        </div>

        <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
            <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2 mb-4">🔐 <?= Text::_('COM_MURUGUARD_GUIDE_ACL_HEADING') ?></h3>
            <div class="space-y-4">
                <div class="border-l-2 border-emerald-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_DESC') ?></p>
                    <ul class="text-xs text-gray-500 mt-2 space-y-1 list-disc pl-4">
                        <li><strong class="text-gray-700"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_MANAGE_LABEL') ?></strong> (core.manage) — <?= Text::_('COM_MURUGUARD_GUIDE_ACL_MANAGE_DESC') ?></li>
                        <li><strong class="text-gray-700"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_EDIT_LABEL') ?></strong> (core.edit) — <?= Text::_('COM_MURUGUARD_GUIDE_ACL_EDIT_DESC') ?></li>
                        <li><strong class="text-gray-700"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_DELETE_LABEL') ?></strong> (core.delete) — <?= Text::_('COM_MURUGUARD_GUIDE_ACL_DELETE_DESC') ?></li>
                        <li><strong class="text-gray-700"><?= Text::_('COM_MURUGUARD_GUIDE_ACL_ADMIN_LABEL') ?></strong> (core.admin) — <?= Text::_('COM_MURUGUARD_GUIDE_ACL_ADMIN_DESC') ?></li>
                    </ul>
                </div>
                <div class="border-l-2 border-emerald-200 pl-3">
                    <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_GUIDE_LANG_TITLE') ?></div>
                    <p class="text-xs text-gray-500 mt-0.5"><?= Text::_('COM_MURUGUARD_GUIDE_LANG_DESC') ?></p>
                </div>
            </div>
        </div>
    </div>

    <div class="muru-settings-tabpanel active" data-settings-panel="protection">
        <?php if (!$this->shieldPluginActive): ?>
        <div class="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 mb-5 text-xs text-amber-800">
            <span class="text-base leading-none">⚠️</span>
            <span><?= Text::_('COM_MURUGUARD_SHIELD_PLUGIN_MISSING') ?></span>
        </div>
        <?php endif; ?>

        <?php if (!$this->canAdmin): ?>
        <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
            <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2 mb-3">🛡️ <?= Text::_('COM_MURUGUARD_SHIELD_TITLE') ?></h3>
            <div class="flex items-center gap-2 text-xs text-gray-500 mb-4">
                <span class="text-base">🔒</span>
                <span><?= Text::_('COM_MURUGUARD_SCHEDULED_READONLY') ?></span>
            </div>
            <div class="text-xs text-gray-600 space-y-1.5">
                <div><?= Text::_('COM_MURUGUARD_SHIELD_ENABLED_STATUS_LABEL') ?>: <span class="font-semibold text-gray-800"><?= $this->shieldEnabled ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?></span></div>
                <div><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_PATTERNS_STATUS_LABEL') ?>: <span class="font-semibold text-gray-800"><?= $this->shieldBlockPatterns ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?></span></div>
                <div><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_BRUTEFORCE_STATUS_LABEL') ?>: <span class="font-semibold text-gray-800"><?= $this->shieldBlockBruteForce ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?></span></div>
            </div>
        </div>
        <?php else: ?>
        <form action="<?= Route::_('index.php?option=com_muruguard&task=scanner.saveshieldsettings') ?>" method="post">
            <?= HTMLHelper::_('form.token') ?>

            <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
                <div class="flex items-start justify-between gap-4 mb-4">
                    <div>
                        <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2">🛡️ <?= Text::_('COM_MURUGUARD_SHIELD_TITLE') ?></h3>
                        <p class="text-xs text-gray-500 mt-1 max-w-xl"><?= Text::_('COM_MURUGUARD_SHIELD_DESC') ?></p>
                    </div>
                    <label class="muru-switch flex-shrink-0" title="<?= $this->shieldEnabled ? Text::_('COM_MURUGUARD_STATUS_ENABLED') : Text::_('COM_MURUGUARD_STATUS_DISABLED') ?>">
                        <input type="checkbox" name="shield_enabled" value="1" <?= $this->shieldEnabled ? 'checked' : '' ?>>
                        <span class="muru-switch-track"><span class="muru-switch-thumb"></span></span>
                    </label>
                </div>

                <div class="flex items-center justify-between gap-4 py-3 border-t border-gray-100">
                    <div>
                        <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_PATTERNS_LABEL') ?></div>
                        <p class="text-xs text-gray-500 mt-0.5 max-w-xl"><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_PATTERNS_DESC') ?></p>
                    </div>
                    <label class="muru-switch flex-shrink-0">
                        <input type="checkbox" name="shield_block_patterns" value="1" <?= $this->shieldBlockPatterns ? 'checked' : '' ?>>
                        <span class="muru-switch-track"><span class="muru-switch-thumb"></span></span>
                    </label>
                </div>

                <div class="flex items-center justify-between gap-4 py-3 border-t border-gray-100">
                    <div>
                        <div class="text-sm font-semibold text-gray-800"><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_BRUTEFORCE_LABEL') ?></div>
                        <p class="text-xs text-gray-500 mt-0.5 max-w-xl"><?= Text::_('COM_MURUGUARD_SHIELD_BLOCK_BRUTEFORCE_DESC') ?></p>
                    </div>
                    <label class="muru-switch flex-shrink-0">
                        <input type="checkbox" name="shield_block_bruteforce" value="1" <?= $this->shieldBlockBruteForce ? 'checked' : '' ?>>
                        <span class="muru-switch-track"><span class="muru-switch-thumb"></span></span>
                    </label>
                </div>

                <div class="grid sm:grid-cols-2 gap-4 mt-4 pt-4 border-t border-gray-100">
                    <div>
                        <label class="block text-xs font-bold text-gray-600 mb-1.5" for="muru-shield-threshold"><?= Text::_('COM_MURUGUARD_SHIELD_THRESHOLD_LABEL') ?></label>
                        <input type="number" id="muru-shield-threshold" name="shield_bruteforce_threshold" min="2" max="50" value="<?= (int) $this->shieldThreshold ?>"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400">
                        <p class="text-xs text-gray-400 mt-1"><?= Text::_('COM_MURUGUARD_SHIELD_THRESHOLD_DESC') ?></p>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-600 mb-1.5" for="muru-shield-window"><?= Text::_('COM_MURUGUARD_SHIELD_WINDOW_LABEL') ?></label>
                        <input type="number" id="muru-shield-window" name="shield_bruteforce_window" min="1" max="1440" value="<?= (int) $this->shieldWindow ?>"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400">
                        <p class="text-xs text-gray-400 mt-1"><?= Text::_('COM_MURUGUARD_SHIELD_WINDOW_DESC') ?></p>
                    </div>
                </div>

                <button type="submit" class="inline-flex items-center gap-1.5 px-5 py-2 mt-5 rounded-lg text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 transition-colors shadow-sm">
                    💾 <?= Text::_('COM_MURUGUARD_SAVE_SETTINGS_BTN') ?>
                </button>
            </div>
        </form>
        <?php endif; ?>

        <?php
        $attackEntries = array_filter($this->attackLog, fn($e) => ($e['type'] ?? '') === 'request');
        $bruteEntries  = array_filter($this->attackLog, fn($e) => ($e['type'] ?? '') === 'bruteforce');
        ?>
        <div class="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-5">
            <div class="flex items-start justify-between gap-4 mb-4">
                <div>
                    <h3 class="text-sm font-bold text-gray-800 flex items-center gap-2">📋 <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_TITLE') ?></h3>
                    <p class="text-xs text-gray-500 mt-1 max-w-xl"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_DESC') ?></p>
                </div>
                <?php if ($this->canAdmin && !empty($this->attackLog)): ?>
                <form action="<?= Route::_('index.php?option=com_muruguard&task=scanner.clearattacklog') ?>" method="post" onsubmit="return confirm('<?= Text::_('COM_MURUGUARD_PROTECTION_LOG_CLEAR_CONFIRM') ?>');">
                    <?= HTMLHelper::_('form.token') ?>
                    <button type="submit" class="flex-shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-semibold text-gray-600 bg-white hover:bg-gray-50 transition-colors">
                        🗑 <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_CLEAR_BTN') ?>
                    </button>
                </form>
                <?php endif; ?>
            </div>

            <?php if (empty($this->attackLog)): ?>
                <div class="text-center py-10 text-gray-400 text-sm">
                    ✅ <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_EMPTY') ?>
                </div>
            <?php else: ?>

                <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2 mt-2"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_SECTION_REQUESTS') ?></h4>
                <?php if (empty($attackEntries)): ?>
                    <div class="text-xs text-gray-400 mb-5">— <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_NONE') ?></div>
                <?php else: ?>
                <div class="overflow-x-auto mb-5 border border-gray-200 rounded-lg">
                    <table class="w-full text-xs">
                        <thead class="bg-gray-50 text-gray-500 uppercase tracking-wider">
                            <tr>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_TIME') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_IP') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_SEVERITY') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_REASON') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_URI') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_STATUS') ?></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            <?php foreach ($attackEntries as $e): ?>
                            <tr class="hover:bg-gray-50/60">
                                <td class="px-3 py-2 text-gray-500 whitespace-nowrap"><?= date('Y-m-d H:i:s', (int) ($e['time'] ?? 0)) ?></td>
                                <td class="px-3 py-2 font-mono text-gray-700"><?= htmlspecialchars((string) ($e['ip'] ?? '')) ?></td>
                                <td class="px-3 py-2">
                                    <?php if (($e['severity'] ?? '') === 'high'): ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">🔴 <?= Text::_('COM_MURUGUARD_CONFIDENCE_HIGH') ?></span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-700">🟡 <?= Text::_('COM_MURUGUARD_CONFIDENCE_MEDIUM') ?></span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-gray-600 max-w-xs"><?= htmlspecialchars((string) ($e['why'] ?? '')) ?></td>
                                <td class="px-3 py-2 text-gray-500 max-w-[220px] truncate font-mono" title="<?= htmlspecialchars((string) ($e['uri'] ?? '')) ?>"><?= htmlspecialchars(mb_strimwidth((string) ($e['uri'] ?? ''), 0, 60, '…')) ?></td>
                                <td class="px-3 py-2">
                                    <?php if (!empty($e['blocked'])): ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-600 text-white">🚫 <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_BLOCKED') ?></span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-gray-100 text-gray-600"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_LOGGED_ONLY') ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>

                <h4 class="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_SECTION_BRUTEFORCE') ?></h4>
                <?php if (empty($bruteEntries)): ?>
                    <div class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_NONE') ?></div>
                <?php else: ?>
                <div class="overflow-x-auto border border-gray-200 rounded-lg">
                    <table class="w-full text-xs">
                        <thead class="bg-gray-50 text-gray-500 uppercase tracking-wider">
                            <tr>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_TIME') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_IP') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_USERNAME') ?></th>
                                <th class="text-left px-3 py-2 font-bold"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_COL_STATUS') ?></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            <?php foreach ($bruteEntries as $e): ?>
                            <tr class="hover:bg-gray-50/60">
                                <td class="px-3 py-2 text-gray-500 whitespace-nowrap"><?= date('Y-m-d H:i:s', (int) ($e['time'] ?? 0)) ?></td>
                                <td class="px-3 py-2 font-mono text-gray-700"><?= htmlspecialchars((string) ($e['ip'] ?? '')) ?></td>
                                <td class="px-3 py-2 text-gray-600"><?= htmlspecialchars((string) preg_replace('/^username:\s*/', '', (string) ($e['matched'] ?? '')) ?: '—') ?></td>
                                <td class="px-3 py-2">
                                    <?php if (!empty($e['blocked'])): ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-600 text-white">🚫 <?= Text::_('COM_MURUGUARD_PROTECTION_LOG_BLOCKED') ?></span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-gray-100 text-gray-600"><?= Text::_('COM_MURUGUARD_PROTECTION_LOG_LOGGED_ONLY') ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Wrapper toggled off when the Settings panel is open -- see the
     #muru-settings-btn handler further down. Wraps BOTH the pre-scan
     gate and the post-scan results below, so Settings works regardless
     of scan state. Pure outer wrap, no internal logic changed. -->
<div id="muru-main-content">
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
    'upload_media'   => ['icon' => '🖼', 'chip' => 'bg-sky-100 text-sky-600'],
    'extension_code' => ['icon' => '🧩', 'chip' => 'bg-violet-100 text-violet-600'],
    'core_webroot'   => ['icon' => '🏛', 'chip' => 'bg-amber-100 text-amber-600'],
    'database'       => ['icon' => '🗄', 'chip' => 'bg-emerald-100 text-emerald-600'],
];
$totalAreaCount = array_sum(array_map(fn($g) => count($g['areas']), $scanAreas));
?>
<div class="anim-in flex flex-col items-center gap-6 py-6">
    <!-- Hero -->
    <div class="w-full max-w-3xl text-center relative overflow-hidden rounded-2xl px-6 py-9"
         style="background:linear-gradient(135deg,#eef2ff 0%,#f5f3ff 55%,#fdf2f8 100%);">
        <div class="relative flex items-center justify-center mb-4">
            <div class="absolute w-24 h-24 rounded-full bg-indigo-200/50 shield-pulse"></div>
            <div class="relative text-5xl">🛡️</div>
        </div>
        <h2 class="text-2xl font-extrabold text-gray-900 mb-2"><?= Text::_('COM_MURUGUARD_TITLE') ?></h2>
        <p class="text-gray-500 text-sm leading-relaxed max-w-lg mx-auto">
            <?= Text::_('COM_MURUGUARD_HERO_DESC') ?>
        </p>
    </div>

    <form action="<?= Route::_($scanUrl) ?>" method="post" id="muruguard-form" class="w-full max-w-3xl flex flex-col items-center gap-3">
        <?= HTMLHelper::_('form.token') ?>
        <input type="hidden" name="areas_submitted" value="1">

        <button type="button" id="muru-open-scan-modal"
                class="inline-flex items-center gap-2 px-8 py-3.5 bg-indigo-600 hover:bg-indigo-700
                       text-white font-bold rounded-xl shadow-lg hover:shadow-xl
                       transition-all duration-200 hover:-translate-y-0.5 text-base">
            🔍 <?= Text::_('COM_MURUGUARD_RUN_SCAN_BTN') ?>
        </button>
        <div class="flex items-center gap-2 text-xs text-gray-400 bg-gray-50 border border-gray-100 rounded-lg px-4 py-2">
            <span>⏱</span>
            <span><?= Text::_('COM_MURUGUARD_SCAN_TIME_NOTE') ?></span>
        </div>
    </form>
</div>

<!-- ══════════════════════════════════════════════════════════════
     SCAN-AREA PICKER MODAL -- opened by #muru-open-scan-modal above.
     Every field inside carries form="muruguard-form" because this
     whole div gets re-parented to <body> at runtime (see script), which
     physically moves it out of that <form>'s DOM subtree; the form=""
     attribute is what keeps these inputs submitting with it regardless
     of where in the document they actually live.
     ══════════════════════════════════════════════════════════════ -->
<div id="muru-scan-modal">
    <div id="muru-scan-modal-backdrop"></div>
    <div id="muru-scan-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="muru-scan-modal-title">
        <div id="muru-scan-modal-header">
            <div id="muru-scan-modal-header-title">
                <span id="muru-scan-modal-header-icon">🗂</span>
                <div>
                    <h3 id="muru-scan-modal-title"><?= Text::_('COM_MURUGUARD_AREAS_HEADER') ?></h3>
                    <p><?= Text::_('COM_MURUGUARD_AREAS_SUBHEADER') ?></p>
                </div>
            </div>
            <button type="button" id="muru-scan-modal-close" aria-label="<?= Text::_('COM_MURUGUARD_MODAL_CLOSE') ?>">✕</button>
        </div>
        <div id="muru-scan-modal-body">
            <div id="muru-scan-modal-selectall">
                <label>
                    <input type="checkbox" id="muru-area-all"
                           class="w-3.5 h-3.5 rounded border-indigo-300 muru-area-chk-all"
                           onclick="document.querySelectorAll('.muru-area-chk').forEach(c=>c.checked=this.checked); muruUpdateAreaCount();">
                    <?= Text::_('COM_MURUGUARD_SELECT_ALL') ?>
                </label>
            </div>

            <div class="grid gap-4 sm:grid-cols-2">
                <?php foreach ($scanAreas as $groupKey => $group):
                    $meta = $groupIcons[$groupKey] ?? ['icon' => '📦', 'chip' => 'bg-gray-100 text-gray-500'];
                ?>
                    <div class="muru-scan-group">
                        <div class="flex items-center gap-2 mb-2.5">
                            <span class="inline-flex items-center justify-center w-7 h-7 rounded-lg text-sm flex-shrink-0 <?= $meta['chip'] ?>"><?= $meta['icon'] ?></span>
                            <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400"><?= $group['label'] ?></span>
                        </div>
                        <div class="space-y-0.5">
                            <?php foreach ($group['areas'] as $key => $label): ?>
                                <label class="flex items-start gap-2 text-sm text-gray-700 cursor-pointer hover:bg-gray-50 rounded-lg px-2 py-1.5 -mx-2 transition-colors">
                                    <input type="checkbox" name="scan_areas[]" form="muruguard-form"
                                           value="<?= htmlspecialchars($key) ?>"
                                           class="muru-area-chk mt-0.5 w-4 h-4 rounded border-gray-300 flex-shrink-0"
                                           onchange="muruUpdateAreaCount()"
                                           <?= $isAreaChecked($key) ? 'checked' : '' ?>>
                                    <span class="leading-snug"><?= $label ?></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div id="muru-scan-modal-footer">
            <span class="text-xs text-gray-400">
                <?= Text::sprintf('COM_MURUGUARD_AREA_COUNT_TEXT', '<span id="muru-area-count">' . $totalAreaCount . '</span>', $totalAreaCount) ?>
            </span>
            <button type="submit" form="muruguard-form" id="muru-scan-modal-run"
                    class="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200 hover:-translate-y-0.5">
                🔍 <?= Text::_('COM_MURUGUARD_RUN_SCAN_BTN') ?>
            </button>
        </div>
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
        <?= Text::_('COM_MURUGUARD_LAST_SCANNED_LABEL') ?>
        <span class="font-bold text-gray-900"><?= date('Y-m-d H:i:s', $this->scanStartedAt) ?></span>
        <span class="text-gray-300">·</span>
        <span class="text-gray-400"><?= Text::_('COM_MURUGUARD_CACHED_5MIN') ?></span>
        <?php if ($this->cronEnabled): ?>
            <span class="text-gray-300">·</span>
            <button type="button" id="muru-cron-status-badge" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-indigo-50 text-indigo-600 hover:bg-indigo-100 transition-colors" title="<?= Text::_('COM_MURUGUARD_CRON_BADGE_TITLE') ?>">
                ⏰ <?= Text::_('COM_MURUGUARD_CRON_ON_BADGE') ?>
            </button>
        <?php endif; ?>
    </div>
    <div class="flex items-center gap-2">
        <form action="index.php?option=com_muruguard&task=scanner.reset" method="post" style="margin:0">
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit"
                    class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-gray-300
                           rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50
                           transition-colors shadow-sm">
                ⚙ <?= Text::_('COM_MURUGUARD_CHANGE_SCAN_AREAS') ?>
            </button>
        </form>
        <form action="<?= Route::_($rescanUrl) ?>" method="post" id="muruguard-rescan-form" style="margin:0">
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit"
                    class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-gray-300
                           rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50
                           transition-colors shadow-sm">
                🔄 <?= Text::_('COM_MURUGUARD_RESCAN_NOW') ?>
            </button>
        </form>
        <button type="button" disabled
                title="<?= Text::_('COM_MURUGUARD_AI_INTEGRATION_TITLE') ?>"
                class="inline-flex items-center gap-1.5 px-4 py-1.5 border border-dashed border-gray-200
                       rounded-lg text-sm font-medium text-gray-400 bg-gray-50 cursor-not-allowed">
            🤖 <?= Text::_('COM_MURUGUARD_AI_INTEGRATION') ?>
            <span class="inline-flex items-center px-1.5 py-0.5 rounded-full bg-gray-200 text-gray-500 text-[10px] font-bold"><?= Text::_('COM_MURUGUARD_SOON_BADGE') ?></span>
        </button>
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
    ['icon'=>'📁', 'num'=>$fc,         'label'=>Text::_('COM_MURUGUARD_LABEL_SUSPICIOUS_FILES'),
     'sub'=>$fc>0 ? Text::sprintf('COM_MURUGUARD_STAT_SUB_HIGH_MEDIUM', $this->highCount, $this->medCount) : Text::_('COM_MURUGUARD_STAT_SUB_FS_CLEAN'),
     'danger'=>$fc>0],
    ['icon'=>'👤', 'num'=>$suCount,    'label'=>Text::_('COM_MURUGUARD_LABEL_ROGUE_SUPER_USERS'),
     'sub'=>$suCount>0 ? Text::_('COM_MURUGUARD_STAT_SUB_SU_REVIEW') : Text::_('COM_MURUGUARD_STAT_SUB_SU_NORMAL'),
     'danger'=>$suCount>0],
    ['icon'=>'🔗', 'num'=>$menuCount,  'label'=>Text::_('COM_MURUGUARD_LABEL_MENU_XSS_ROWS'),
     'sub'=>$menuCount>0 ? Text::_('COM_MURUGUARD_STAT_SUB_MENU_FOUND') : Text::_('COM_MURUGUARD_STAT_SUB_MENU_CLEAN'),
     'danger'=>$menuCount>0],
    ['icon'=>'🗄',  'num'=>$assetCount,'label'=>Text::_('COM_MURUGUARD_LABEL_ROGUE_ASSET_ROWS'),
     'sub'=>$assetCount>0 ? Text::_('COM_MURUGUARD_STAT_SUB_ASSET_TAINTED') : Text::_('COM_MURUGUARD_STAT_SUB_ASSET_CLEAN'),
     'danger'=>$assetCount>0],
    ['icon'=>'🖼',  'num'=>$deface,    'label'=>Text::_('COM_MURUGUARD_LABEL_TEMPLATE_DEFACEMENT'),
     'sub'=>$deface>0 ? Text::_('COM_MURUGUARD_STAT_SUB_TEMPLATE_MODIFIED') : Text::_('COM_MURUGUARD_STAT_SUB_TEMPLATE_INTACT'),
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
                <?= $s['danger'] ? '⚠ ' . Text::_('COM_MURUGUARD_STAT_ALERT') : '✓ ' . Text::_('COM_MURUGUARD_STAT_OK') ?>
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

<?php
/* ── Tab navigation ── */
$sig = \MuruguardHelper::getSignatures();
// Not-deletable = an auto-cleanable infection pattern, OR a genuinely
// required core/template entry file that deleteTargets() refuses to
// touch regardless, OR a known code-area file (component/module/plugin/
// library/template source) flagged ONLY by a content-signature match --
// i.e. a legitimate, actively-used file with something malicious injected
// into it, not a foreign dropped file, so deleting it would break real
// site functionality even though this scanner has no auto-clean pattern
// for this particular infection shape yet. Every finding lands in
// exactly one of the two tabs below -- nothing silently disappears, and
// "Suspicious Files" only ever lists things the Delete button can
// actually safely act on.
$notDeletable = fn($f) => \MuruguardHelper::isCleanablePattern($f['reasons'] ?? [$f['reason']])
    || \MuruguardHelper::isProtectedEntryPath($f['rel'], $sig)
    || \MuruguardHelper::isContentOnlyCodeAreaFinding($f['rel'], $f['reasons'] ?? [$f['reason']], $sig);
$cleanableFindings = array_filter($fileFindings, $notDeletable);
$cleanableCount = count($cleanableFindings);
$deletableFindings = array_filter($fileFindings, fn($f) => !$notDeletable($f));
$deletableCount = count($deletableFindings);
$deletableHigh = count(array_filter($deletableFindings, fn($f) => $f['confidence'] === 'high'));
$deletableMed  = $deletableCount - $deletableHigh;
$tabs = [
    ['id' => 'files',      'emoji' => '📁', 'title' => Text::_('COM_MURUGUARD_LABEL_SUSPICIOUS_FILES'), 'count' => $deletableCount],
    ['id' => 'cleanable',  'emoji' => '🧹', 'title' => Text::_('COM_MURUGUARD_TAB_CLEANABLE_FILES'),     'count' => $cleanableCount],
    ['id' => 'users',      'emoji' => '👤', 'title' => Text::_('COM_MURUGUARD_TAB_SUPER_USERS'),         'count' => $suCount],
    ['id' => 'menu',       'emoji' => '🔗', 'title' => Text::_('COM_MURUGUARD_TAB_MENU_XSS'),            'count' => $menuCount],
    ['id' => 'assets',     'emoji' => '🗄', 'title' => Text::_('COM_MURUGUARD_TAB_SPPB_ASSETS'),         'count' => $assetCount],
    ['id' => 'template',   'emoji' => '🖼', 'title' => Text::_('COM_MURUGUARD_TAB_DEFACEMENT'),          'count' => $deface],
];
// Open on the first tab that has findings; otherwise the first tab.
$activeTab = $tabs[0]['id'];
foreach ($tabs as $t) { if ($t['count'] > 0) { $activeTab = $t['id']; break; } }
?>
<div class="anim-in bg-white border border-gray-200 rounded-xl shadow-sm mb-5 overflow-hidden">
    <div class="flex flex-wrap gap-1 p-1.5 bg-gray-50 border-b border-gray-100" role="tablist">
        <?php foreach ($tabs as $t): ?>
            <button type="button"
                    class="muru-tab flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors"
                    data-tab="<?= $t['id'] ?>" role="tab">
                <span><?= $t['emoji'] ?></span>
                <span><?= $t['title'] ?></span>
                <?php if ($t['count'] > 0): ?>
                    <span class="muru-tab-badge inline-flex items-center justify-center min-w-5 h-5 px-1.5 bg-red-500 text-white text-[10px] font-bold rounded-full"><?= $t['count'] ?></span>
                <?php else: ?>
                    <span class="muru-tab-badge inline-flex items-center justify-center w-5 h-5 bg-green-500 text-white text-[10px] font-bold rounded-full">✓</span>
                <?php endif; ?>
            </button>
        <?php endforeach; ?>
    </div>
</div>

<?php
/* ── Helper: tab panel wrapper (ids match the $tabs 'id' above) ── */
function muru_section_open(string $id, string $emoji, string $title, int $count): void {
    $panel = preg_replace('/^sec-/', '', $id);
    $dot = $count > 0
        ? '<span class="inline-flex items-center justify-center min-w-5 h-5 px-1.5 bg-red-500 text-white text-[10px] font-bold rounded-full ml-2">' . $count . '</span>'
        : '<span class="inline-flex items-center justify-center w-5 h-5 bg-green-500 text-white text-[10px] font-bold rounded-full ml-2">✓</span>';
    echo '<section id="' . $id . '" class="muru-panel hidden bg-white border border-gray-200 rounded-xl shadow-sm mb-4 overflow-hidden anim-in" data-panel="' . $panel . '">';
    echo '<div class="flex items-center gap-2 font-bold text-gray-800 p-3 border-b border-gray-100">' . $emoji . ' <span>' . $title . '</span>' . $dot . '</div>';
    echo '<div class="p-3">';
}
function muru_section_close(): void {
    echo '</div></section>';
}

/** Shared <tr> markup for a file finding -- used by both the Suspicious
 *  Files and Cleanable Files tabs so the two stay visually identical.
 *  $showCleanPreview is only turned on for the Cleanable Files tab, and
 *  only actually renders a preview when the file's CURRENT on-disk
 *  content still has a pattern this scanner can auto-repair -- it never
 *  shows a preview for something Clean can't actually fix. */
function muru_render_file_row(array $f, bool $showCleanPreview = false, bool $showCheckbox = true): void {
    $pathDir  = dirname($f['rel']);
    $pathBase = basename($f['rel']);
    $isProtectedEntry = \MuruguardHelper::isProtectedEntryPath($f['rel'], \MuruguardHelper::getSignatures());
    $reasonsList = $f['reasons'] ?? [$f['reason']];
    $blocksHtml  = array_map(fn($r) => \MuruguardHelper::formatReasonForDisplay($r), $reasonsList);
    $diffHtml = null;
    if ($showCleanPreview && $f['type'] !== 'dir') {
        $diffHtml = \MuruguardHelper::previewCleanDiff($f['abs']);
        if ($diffHtml !== null) $blocksHtml[] = $diffHtml;
    }
    $reasonsJson = htmlspecialchars(json_encode($blocksHtml), ENT_QUOTES);
    ?>
    <tr class="hover:bg-gray-50/60 transition-colors <?= $f['confidence']==='high' ? 'bg-red-50/30' : '' ?>">
        <td class="px-4 py-3">
            <?php if ($showCheckbox): ?>
            <input type="checkbox" class="muru-file-chk w-4 h-4 rounded border-gray-300"
                   name="targets[]" value="<?= htmlspecialchars($f['rel']) ?>">
            <?php endif; ?>
        </td>
        <td class="px-4 py-3">
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
                            🛡 <?= Text::_('COM_MURUGUARD_REQUIRED_FILE_BADGE') ?>
                        </div>
                    <?php endif; ?>
                </div>
                <button type="button"
                        class="muru-copy-btn flex-shrink-0 w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 transition-colors"
                        data-copy="<?= htmlspecialchars($f['rel']) ?>" title="<?= Text::_('COM_MURUGUARD_COPY_PATH') ?>" aria-label="<?= Text::_('COM_MURUGUARD_COPY_PATH') ?>">
                    <span class="muru-copy-icon">📋</span>
                </button>
            </div>
        </td>
        <td class="px-4 py-3">
            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-600">
                <?= $f['type']==='dir' ? '📂 ' . Text::_('COM_MURUGUARD_TYPE_DIR') : '📄 ' . Text::_('COM_MURUGUARD_TYPE_FILE') ?>
            </span>
        </td>
        <td class="px-4 py-3">
            <?php if ($f['confidence']==='high'): ?>
                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">🔴 <?= Text::_('COM_MURUGUARD_CONFIDENCE_HIGH') ?></span>
            <?php else: ?>
                <span class="min-w-[80px] text-center inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-700">🟡 <?= Text::_('COM_MURUGUARD_CONFIDENCE_MEDIUM') ?></span>
            <?php endif; ?>
        </td>
        <td class="px-4 py-3 text-xs">
            <div class="text-amber-700 mb-1.5"><?= htmlspecialchars(\MuruguardHelper::shortReasonLabel($reasonsList)) ?></div>
            <button type="button" class="muru-code-issues-btn inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold <?= $diffHtml !== null ? 'bg-indigo-100 text-indigo-700 hover:bg-indigo-200' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' ?> transition-colors"
                    data-path="<?= htmlspecialchars($f['rel']) ?>"
                    data-confidence="<?= htmlspecialchars($f['confidence']) ?>"
                    data-reasons="<?= $reasonsJson ?>">
                🧬 <?= Text::_('COM_MURUGUARD_CODE_ISSUES_BTN') ?><?= count($reasonsList) > 1 ? ' (' . count($reasonsList) . ')' : '' ?><?= $diffHtml !== null ? ' + 🔍 ' . Text::_('COM_MURUGUARD_PREVIEW_LABEL') : '' ?>
            </button>
        </td>
        <td class="px-4 py-3 text-xs text-gray-500"><?= \MuruguardHelper::humanSize($f['size']) ?></td>
        <td class="px-4 py-3 text-xs text-gray-400"><?= $f['mtime'] ? date('Y-m-d H:i',$f['mtime']) : '—' ?></td>
    </tr>
    <?php
}
?>

<!-- ── 1. Files ──────────────────────────────────────────────── -->
<?php muru_section_open('sec-files', '📁', Text::_('COM_MURUGUARD_SECTION_SUSPICIOUS_FILES_FOLDERS'), $deletableCount); ?>
<?php if (empty($deletableFindings)): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span>
        <span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_DELETABLE_FILES') ?></span>
    </div>
<?php else: ?>
    <?php $tag = $this->canDelete ? 'form' : 'div'; ?>
    <<?= $tag ?><?php if ($this->canDelete): ?> action="index.php?option=com_muruguard&task=scanner.delete" method="post" id="muru-files-form"
          onsubmit="return confirm('<?= Text::_('COM_MURUGUARD_CONFIRM_DELETE_FILES') ?>');"<?php endif; ?>>
        <div class="flex items-center justify-between mb-3">
            <?php if ($this->canDelete): ?>
            <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                       onclick="document.querySelectorAll('#muru-files-form .muru-file-chk').forEach(c=>c.checked=this.checked)">
                <?= Text::_('COM_MURUGUARD_SELECT_ALL') ?>
            </label>
            <?php else: ?>
            <span></span>
            <?php endif; ?>
            <div class="flex items-center gap-2 text-xs text-gray-500">
                <span class="inline-flex items-center gap-1 px-2 py-0.5 bg-red-100 text-red-700 rounded-full font-semibold">🔴 <?= Text::sprintf('COM_MURUGUARD_COUNT_HIGH', $deletableHigh) ?></span>
                <span class="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full font-semibold">🟡 <?= Text::sprintf('COM_MURUGUARD_COUNT_MEDIUM', $deletableMed) ?></span>
            </div>
        </div>
        <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-gray-50 border-b border-gray-100">
                        <th class="w-10 px-4 py-3"></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_PATH') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_TYPE') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_SEVERITY') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_REASON') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_SIZE') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_MODIFIED') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-50">
                <?php foreach ($deletableFindings as $f): muru_render_file_row($f, false, $this->canDelete); endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php if ($this->canDelete): ?>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🗑 <?= Text::_('COM_MURUGUARD_BTN_DELETE_SELECTED') ?>
            </button>
            <span class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_DELETE_HINT') ?></span>
        </div>
        <?php else: ?>
        <div class="flex items-center gap-2 text-xs text-gray-500">
            <span class="text-base">🔒</span>
            <span><?= Text::_('COM_MURUGUARD_LOCKED_DELETE') ?></span>
        </div>
        <?php endif; ?>
    </<?= $tag ?>>
<?php endif; ?>
<?php muru_section_close(); ?>

<!-- ── 1b. Cleanable Files ──────────────────────────────────────── -->
<?php muru_section_open('sec-cleanable', '🧹', Text::_('COM_MURUGUARD_TAB_CLEANABLE_FILES'), $cleanableCount); ?>
<?php if (empty($cleanableFindings)): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span>
        <span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_CLEANABLE_FILES') ?></span>
    </div>
<?php else: ?>
    <div class="flex items-center gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3 mb-4 text-xs text-indigo-800">
        <span class="text-lg flex-shrink-0">ℹ️</span>
        <span><?= Text::_('COM_MURUGUARD_CLEANABLE_INFO') ?></span>
    </div>
    <?php $tag = $this->canEdit ? 'form' : 'div'; ?>
    <<?= $tag ?><?php if ($this->canEdit): ?> action="index.php?option=com_muruguard&task=scanner.cleancode" method="post"
          onsubmit="return confirm('<?= Text::_('COM_MURUGUARD_CONFIRM_CLEAN_FILES') ?>');"<?php endif; ?>>
        <div class="flex items-center justify-between mb-3">
            <?php if ($this->canEdit): ?>
            <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                       onclick="document.querySelectorAll('#sec-cleanable .muru-file-chk').forEach(c=>c.checked=this.checked)">
                <?= Text::_('COM_MURUGUARD_SELECT_ALL') ?>
            </label>
            <?php else: ?>
            <span></span>
            <?php endif; ?>
            <span class="text-xs text-gray-500"><?= $cleanableCount ?> <?= Text::_($cleanableCount === 1 ? 'COM_MURUGUARD_FILES_ELIGIBLE' : 'COM_MURUGUARD_FILES_ELIGIBLE_PLURAL') ?></span>
        </div>
        <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-gray-50 border-b border-gray-100">
                        <th class="w-10 px-4 py-3"></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_PATH') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_TYPE') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_SEVERITY') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_REASON') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_SIZE') ?></th>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_('COM_MURUGUARD_COL_MODIFIED') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-50">
                <?php foreach ($cleanableFindings as $f): muru_render_file_row($f, true, $this->canEdit); endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php if ($this->canEdit): ?>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🧹 <?= Text::_('COM_MURUGUARD_CLEAN_SELECTED_BTN') ?>
            </button>
            <span class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_CLEAN_HINT') ?></span>
        </div>
        <?php else: ?>
        <div class="flex items-center gap-2 text-xs text-gray-500">
            <span class="text-base">🔒</span>
            <span><?= Text::_('COM_MURUGUARD_LOCKED_EDIT_FILES') ?></span>
        </div>
        <?php endif; ?>
    </<?= $tag ?>>
<?php endif; ?>
<?php muru_section_close(); ?>

<!-- ── 2. Super Users ─────────────────────────────────────────── -->
<?php muru_section_open('sec-users', '👤', Text::_('COM_MURUGUARD_SECTION_SUPER_USER_ACCOUNTS'), $suCount); ?>
<?php if (empty($dbFindings['superusers'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_SUPERUSERS_FOUND') ?></span>
    </div>
<?php else: ?>
    <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-3">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-50 border-b border-gray-100">
                    <?php foreach (['COM_MURUGUARD_COL_ID','COM_MURUGUARD_COL_NAME','COM_MURUGUARD_COL_USERNAME','COM_MURUGUARD_COL_EMAIL','COM_MURUGUARD_COL_REGISTERED','COM_MURUGUARD_COL_LAST_VISIT','COM_MURUGUARD_COL_STATUS'] as $h): ?>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_($h) ?></th>
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
                            <div class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-100 text-red-700 text-xs font-bold mb-1">⚠ <?= Text::_('COM_MURUGUARD_SUSPICIOUS_BADGE') ?></div>
                            <div class="text-xs text-red-600"><?= htmlspecialchars($u['why']) ?></div>
                        <?php else: ?>
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-100 text-green-700 text-xs font-bold">✓ <?= Text::_('COM_MURUGUARD_NORMAL_BADGE') ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_REMOVE_ROGUE_NOTE') ?></p>
<?php endif; ?>
<?php muru_section_close(); ?>

<!-- ── 3. Menu XSS ───────────────────────────────────────────── -->
<?php muru_section_open('sec-menu', '🔗', Text::_('COM_MURUGUARD_SECTION_MENU_XSS_INJECTIONS'), $menuCount); ?>
<?php if (empty($dbFindings['menu_xss'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_MENU_ITEMS') ?></span>
    </div>
<?php else: ?>
    <?php $tag = $this->canEdit ? 'form' : 'div'; ?>
    <<?= $tag ?><?php if ($this->canEdit): ?> action="index.php?option=com_muruguard&task=scanner.cleanmenu" method="post"
          onsubmit="return confirm('<?= Text::_('COM_MURUGUARD_CONFIRM_CLEAN_MENU') ?>');"<?php endif; ?>>
        <?php if ($this->canEdit): ?>
        <div class="flex items-center justify-between mb-3">
            <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                       onclick="document.querySelectorAll('.muru-menu-chk').forEach(c=>c.checked=this.checked)">
                <?= Text::_('COM_MURUGUARD_SELECT_ALL') ?>
            </label>
        </div>
        <?php endif; ?>
        <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-gray-50 border-b border-gray-100">
                        <th class="w-10 px-4 py-3"></th>
                        <?php foreach (['COM_MURUGUARD_COL_ID','COM_MURUGUARD_COL_TITLE','COM_MURUGUARD_COL_LINK','COM_MURUGUARD_COL_MATCHED_SIGNATURES'] as $h): ?>
                            <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_($h) ?></th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-50">
                <?php foreach ($dbFindings['menu_xss'] as $m): ?>
                    <tr class="hover:bg-red-50/40 bg-red-50/20 transition-colors">
                        <td class="px-4 py-3"><?php if ($this->canEdit): ?><input type="checkbox" class="muru-menu-chk w-4 h-4 rounded border-gray-300" name="menu_xss_ids[]" value="<?= (int)$m['id'] ?>"><?php endif; ?></td>
                        <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= (int)$m['id'] ?></td>
                        <td class="px-4 py-3 font-medium"><?= htmlspecialchars($m['title']) ?></td>
                        <td class="px-4 py-3"><code class="text-xs break-all text-gray-600"><?= htmlspecialchars($m['link']) ?></code></td>
                        <td class="px-4 py-3 text-xs text-amber-700 font-medium"><?= htmlspecialchars(implode(', ', $m['matches'] ?? [])) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php if ($this->canEdit): ?>
        <?= HTMLHelper::_('form.token') ?>
        <div class="flex items-center gap-3">
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🧹 <?= Text::_('COM_MURUGUARD_CLEAN_SELECTED_ROWS_BTN') ?>
            </button>
            <span class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_CLEAN_MENU_HINT') ?></span>
        </div>
        <?php else: ?>
        <div class="flex items-center gap-2 text-xs text-gray-500">
            <span class="text-base">🔒</span>
            <span><?= Text::_('COM_MURUGUARD_LOCKED_EDIT_MENU') ?></span>
        </div>
        <?php endif; ?>
    </<?= $tag ?>>
<?php endif; ?>
<?php muru_section_close(); ?>

<!-- ── 4. SPPB Assets ────────────────────────────────────────── -->
<?php muru_section_open('sec-assets', '🗄', Text::_('COM_MURUGUARD_SECTION_SPPB_ASSET_TABLE'), $assetCount); ?>
<?php if (empty($dbFindings['sppb_assets']) && empty($dbFindings['rogue_iconfont'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_SPPB_ROWS') ?></span>
    </div>
<?php else: ?>
    <?php if (!empty($dbFindings['sppb_assets'])): ?>
        <h4 class="font-bold text-gray-700 mb-3">
            <?= Text::_('COM_MURUGUARD_INJECTED_PAYLOAD_ROWS') ?>
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
        <?php $tag = $this->canDelete ? 'form' : 'div'; ?>
        <<?= $tag ?><?php if ($this->canDelete): ?> action="index.php?option=com_muruguard&task=scanner.deleteassets" method="post"
              onsubmit="return confirm('<?= Text::_('COM_MURUGUARD_CONFIRM_DELETE_ASSETS') ?>');"<?php endif; ?>>
            <div class="flex items-center justify-between mb-3">
                <h4 class="font-bold text-gray-700"><?= Text::_('COM_MURUGUARD_ROGUE_ICONFONT_HEADING') ?>
                    <span class="ml-1 inline-flex items-center justify-center w-5 h-5 bg-red-500 text-white text-[10px] font-bold rounded-full">
                        <?= count($dbFindings['rogue_iconfont']) ?>
                    </span>
                </h4>
                <?php if ($this->canDelete): ?>
                <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
                    <input type="checkbox" class="w-4 h-4 rounded border-gray-300"
                           onclick="document.querySelectorAll('.muru-asset-chk').forEach(c=>c.checked=this.checked)">
                    <?= Text::_('COM_MURUGUARD_SELECT_ALL') ?>
                </label>
                <?php endif; ?>
            </div>
            <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-4">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-gray-50 border-b border-gray-100">
                            <th class="w-10 px-4 py-3"></th>
                            <?php foreach (['COM_MURUGUARD_COL_ID','COM_MURUGUARD_COL_NAME','COM_MURUGUARD_COL_TITLE','COM_MURUGUARD_COL_CREATED','COM_MURUGUARD_COL_BY','COM_MURUGUARD_COL_ASSETS'] as $h): ?>
                                <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_($h) ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-50">
                    <?php foreach ($dbFindings['rogue_iconfont'] as $row): ?>
                        <tr class="hover:bg-red-50/40 bg-red-50/20 transition-colors">
                            <td class="px-4 py-3"><?php if ($this->canDelete): ?><input type="checkbox" class="muru-asset-chk w-4 h-4 rounded border-gray-300" name="rogue_asset_ids[]" value="<?= (int)$row['id'] ?>"><?php endif; ?></td>
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
            <?php if ($this->canDelete): ?>
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit"
                    class="inline-flex items-center gap-2 px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-xl shadow transition-colors">
                🗑 <?= Text::_('COM_MURUGUARD_BTN_DELETE_SELECTED') ?>
            </button>
            <?php else: ?>
            <div class="flex items-center gap-2 text-xs text-gray-500">
                <span class="text-base">🔒</span>
                <span><?= Text::_('COM_MURUGUARD_LOCKED_DELETE_ASSETS') ?></span>
            </div>
            <?php endif; ?>
        </<?= $tag ?>>
    <?php endif; ?>
<?php endif; ?>
<?php muru_section_close(); ?>

<!-- ── 5. Template defacement ────────────────────────────────── -->
<?php muru_section_open('sec-template', '🖼', Text::_('COM_MURUGUARD_SECTION_TEMPLATE_DEFACEMENT'), $deface); ?>
<?php if (empty($dbFindings['template_defacement'])): ?>
    <div class="flex items-center gap-3 text-green-700 bg-green-50 rounded-xl p-[10px]">
        <span class="text-2xl">✅</span><span class="font-medium"><?= Text::_('COM_MURUGUARD_NO_DEFACEMENT_FOUND') ?></span>
    </div>
<?php else: ?>
    <div class="tbl-wrap rounded-xl border border-gray-100 overflow-hidden mb-3">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-50 border-b border-gray-100">
                    <?php foreach (['COM_MURUGUARD_COL_ID','COM_MURUGUARD_COL_TEMPLATE','COM_MURUGUARD_COL_TITLE','COM_MURUGUARD_COL_MATCHES'] as $h): ?>
                        <th class="px-4 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider"><?= Text::_($h) ?></th>
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
    <p class="text-xs text-gray-400"><?= Text::_('COM_MURUGUARD_DEFACEMENT_NOTE') ?></p>
<?php endif; ?>
<?php muru_section_close(); ?>

<?php endif; // end $this->scanned ?>
</div><!-- /#muru-main-content -->

</div><!-- #muruguard-root -->

<script>
(function () {
    // Re-parent fixed-position elements to <body> so they truly cover the
    // viewport / anchor to the real top-right corner. Joomla's admin
    // template applies a CSS transform to the content wrapper while
    // animating the collapsible sidebar, and a transformed ancestor
    // breaks `position: fixed` for any descendant, confining it to that
    // ancestor's box instead of the actual viewport.
    ['muruguard-overlay', 'muru-header-actions', 'muru-modal', 'muru-scan-modal'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el && el.parentNode !== document.body) {
            document.body.appendChild(el);
        }
    });

    muruUpdateAreaCount();

    var forms = [document.getElementById('muruguard-form'), document.getElementById('muruguard-rescan-form')];
    forms.forEach(function (form) {
        if (!form) return;
        form.addEventListener('submit', function () {
            closeScanModal();
            muruguardShowOverlay();
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
    var tabs   = document.querySelectorAll('.muru-tab');
    var panels = document.querySelectorAll('.muru-panel');
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

    // ── Settings panel ───────────────────────────────────────────
    // Swaps #muru-main-content (whichever of scan-gate/results is
    // currently rendered) for #muru-settings-panel and back -- a plain
    // two-way toggle, independent of the results tab system above.
    var settingsBtn   = document.getElementById('muru-settings-btn');
    var settingsBack  = document.getElementById('muru-settings-back');
    var settingsPanel = document.getElementById('muru-settings-panel');
    var mainContent   = document.getElementById('muru-main-content');
    function openSettings() {
        if (!settingsPanel || !mainContent) return;
        mainContent.classList.add('hidden');
        settingsPanel.classList.remove('hidden');
        settingsBtn.classList.add('muru-settings-open');
        settingsBtn.setAttribute('aria-pressed', 'true');
    }
    function closeSettings() {
        if (!settingsPanel || !mainContent) return;
        settingsPanel.classList.add('hidden');
        mainContent.classList.remove('hidden');
        settingsBtn.classList.remove('muru-settings-open');
        settingsBtn.setAttribute('aria-pressed', 'false');
    }
    if (settingsBtn) settingsBtn.addEventListener('click', openSettings);
    var cronBadge = document.getElementById('muru-cron-status-badge');
    if (cronBadge) cronBadge.addEventListener('click', openSettings);
    if (settingsBack) settingsBack.addEventListener('click', closeSettings);

    // ── Settings sub-tabs (Scheduled Scanning / Setup Guide) ─────
    var settingsTabs   = document.querySelectorAll('.muru-settings-tab');
    var settingsPanels = document.querySelectorAll('.muru-settings-tabpanel');
    settingsTabs.forEach(function (t) {
        t.addEventListener('click', function () {
            var id = t.getAttribute('data-settings-tab');
            settingsTabs.forEach(function (st) { st.classList.toggle('active', st === t); });
            settingsPanels.forEach(function (p) {
                var on = p.getAttribute('data-settings-panel') === id;
                p.classList.toggle('active', on);
                p.classList.toggle('hidden', !on);
            });
        });
    });

    // Live-updates the webcron URL preview as the token field changes,
    // and fills in a fresh random token on Generate -- purely client-side
    // convenience, nothing is saved until the Save Settings button posts.
    var tokenField = document.getElementById('muru-cron-token');
    var urlEl      = document.getElementById('muru-webcron-url');
    var urlCopyBtn = urlEl ? urlEl.closest('div').querySelector('.muru-copy-btn') : null;
    var webcronBase = <?= json_encode(Uri::root() . 'administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=') ?>;
    function refreshWebcronUrl() {
        if (!tokenField || !urlEl) return;
        var url = webcronBase + encodeURIComponent(tokenField.value || '');
        urlEl.textContent = url;
        if (urlCopyBtn) urlCopyBtn.setAttribute('data-copy', url);
    }
    if (tokenField) tokenField.addEventListener('input', refreshWebcronUrl);
    var generateBtn = document.getElementById('muru-cron-generate');
    if (generateBtn && tokenField) {
        generateBtn.addEventListener('click', function () {
            var bytes = new Uint8Array(24);
            (window.crypto || window.msCrypto).getRandomValues(bytes);
            var token = Array.prototype.map.call(bytes, function (b) { return b.toString(16).padStart(2, '0'); }).join('');
            tokenField.value = token;
            refreshWebcronUrl();
        });
    }

    // ── Scan-area picker modal ───────────────────────────────────
    var scanModal   = document.getElementById('muru-scan-modal');
    var openScanBtn = document.getElementById('muru-open-scan-modal');
    function openScanModal() {
        if (scanModal) scanModal.classList.add('muru-show');
    }
    function closeScanModal() {
        if (scanModal) scanModal.classList.remove('muru-show');
    }
    if (openScanBtn) openScanBtn.addEventListener('click', openScanModal);
    document.addEventListener('click', function (e) {
        if (e.target.id === 'muru-scan-modal-close' || e.target.id === 'muru-scan-modal-backdrop') {
            closeScanModal();
        }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeScanModal();
    });

    // ── Code-analysis modal ─────────────────────────────────────
    // Event delegation, not per-button listeners -- the button set lives
    // inside a results panel that can be re-rendered/hidden by the tab
    // switcher above, so this stays correct regardless of DOM churn.
    document.addEventListener('click', function (e) {
        var issuesBtn = e.target.closest('.muru-code-issues-btn');
        if (issuesBtn) { muruOpenCodeModal(issuesBtn); return; }

        var copyBtn = e.target.closest('.muru-copy-btn');
        if (copyBtn) { muruCopyPath(copyBtn); return; }

        if (e.target.id === 'muru-modal-close' || e.target.id === 'muru-modal-backdrop') {
            muruCloseCodeModal();
        }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') muruCloseCodeModal();
    });
})();

function muruOpenCodeModal(btn) {
    var modal   = document.getElementById('muru-modal');
    var badge   = document.getElementById('muru-modal-badge');
    var pathEl  = document.getElementById('muru-modal-path');
    var bodyEl  = document.getElementById('muru-modal-body');
    var conf    = btn.getAttribute('data-confidence') || 'medium';
    var blocks  = [];
    try { blocks = JSON.parse(btn.getAttribute('data-reasons') || '[]'); } catch (err) { blocks = []; }

    badge.textContent = conf === 'high' ? '🔴 High confidence' : '🟡 Needs manual review';
    badge.className = conf === 'high' ? 'high' : 'medium';
    pathEl.textContent = btn.getAttribute('data-path') || '';
    // blocks[] is pre-rendered, escaped HTML built server-side in
    // MuruguardHelper::formatReasonForDisplay() / formatCleanPreview() --
    // nothing user-controlled reaches innerHTML unescaped here.
    bodyEl.innerHTML = blocks.join('');

    modal.classList.add('muru-show');
    document.body.style.overflow = 'hidden';
}

function muruCloseCodeModal() {
    var modal = document.getElementById('muru-modal');
    modal.classList.remove('muru-show');
    document.body.style.overflow = '';
}

function muruCopyPath(btn) {
    var text = btn.getAttribute('data-copy') || '';
    var icon = btn.querySelector('.muru-copy-icon');

    function showCopied() {
        if (!icon) return;
        icon.textContent = '✅';
        btn.classList.add('muru-copied');
        setTimeout(function () {
            icon.textContent = '📋';
            btn.classList.remove('muru-copied');
        }, 1200);
    }

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(showCopied).catch(function () { muruCopyPathFallback(text, showCopied); });
    } else {
        muruCopyPathFallback(text, showCopied);
    }
}

function muruCopyPathFallback(text, onDone) {
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

function muruUpdateAreaCount() {
    var boxes = document.querySelectorAll('.muru-area-chk');
    if (!boxes.length) return;
    var checked = 0;
    boxes.forEach(function (c) { if (c.checked) checked++; });

    var countEl = document.getElementById('muru-area-count');
    if (countEl) countEl.textContent = checked;

    var master = document.getElementById('muru-area-all');
    if (master) {
        master.checked = checked === boxes.length;
        master.indeterminate = checked > 0 && checked < boxes.length;
    }
}

function muruguardShowOverlay() {
    var overlay  = document.getElementById('muruguard-overlay');
    var statusEl = document.getElementById('muruguard-loading-status');

    overlay.classList.add('muruguard-show');

    var messages = <?= json_encode([
        Text::_('COM_MURUGUARD_OVERLAY_STARTING'),
        Text::_('COM_MURUGUARD_SCAN_MSG_2'),
        Text::_('COM_MURUGUARD_SCAN_MSG_3'),
        Text::_('COM_MURUGUARD_SCAN_MSG_4'),
        Text::_('COM_MURUGUARD_SCAN_MSG_5'),
        Text::_('COM_MURUGUARD_SCAN_MSG_6'),
    ]) ?>;
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
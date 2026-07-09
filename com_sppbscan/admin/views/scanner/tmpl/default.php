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

/** @var SppbscanViewScanner $this */
$fileFindings = $this->fileFindings ?? [];
$dbFindings   = $this->dbFindings   ?? [];
$suspiciousSU = !empty($dbFindings['superusers'])
    ? array_filter($dbFindings['superusers'], fn($u) => $u['suspicious'])
    : [];

$scanUrl    = 'index.php?option=com_sppbscan&task=scanner.scan';
$rescanUrl  = 'index.php?option=com_sppbscan&task=scanner.scan&rescan=1';
?>

<style>
/* ── Scan gate / loading overlay ── */
.sppbscan-gate {
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    min-height:340px; gap:20px; text-align:center;
}
.sppbscan-gate .gate-icon  { font-size:56px; line-height:1; }
.sppbscan-gate h2          { font-size:22px; font-weight:700; margin:0; }
.sppbscan-gate p           { color:#666; max-width:480px; margin:0; font-size:14px; line-height:1.6; }
.sppbscan-gate .btn-scan   { font-size:15px; padding:10px 28px; }

#sppbscan-overlay {
    display:none; position:fixed; inset:0; background:rgba(0,0,0,0.55);
    z-index:9999; flex-direction:column; align-items:center; justify-content:center; gap:18px;
}
#sppbscan-overlay.active { display:flex; }
.sppbscan-spinner {
    width:52px; height:52px; border:5px solid rgba(255,255,255,0.25);
    border-top-color:#fff; border-radius:50%; animation:sppb-spin 0.8s linear infinite;
}
@keyframes sppb-spin { to { transform:rotate(360deg); } }
.sppbscan-overlay-text { color:#fff; font-size:15px; font-weight:600; letter-spacing:0.02em; }
.sppbscan-overlay-sub  { color:rgba(255,255,255,0.65); font-size:13px; margin-top:-10px; }

/* ── Stats row ── */
.sppbscan-stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:24px; }
.sppbscan-stat  { background:#fff; border:1px solid #ddd; border-radius:8px; padding:16px 18px; }
.sppbscan-stat .num       { font-size:26px; font-weight:700; line-height:1; margin-bottom:4px; }
.sppbscan-stat.dirty .num { color:#dc3545; }
.sppbscan-stat.clean .num { color:#28a745; }
.sppbscan-stat .label     { font-size:12px; color:#666; }

/* ── Re-scan bar ── */
.sppbscan-rescan-bar {
    display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;
    background:#f8f9fa; border:1px solid #dee2e6; border-radius:6px;
    padding:10px 16px; margin-bottom:20px; font-size:13px; color:#555;
}
.sppbscan-rescan-bar .scan-time { font-weight:600; color:#333; }

/* ── Tables ── */
.sppbscan-reason { font-size:12px; color:#b45309; }
.sppbscan-path   { font-family:monospace; font-size:12px; word-break:break-all; }

/* ── Support widget ── */
.sppbscan-support { position:fixed; top:72px; right:20px; z-index:1000; }
.sppbscan-support summary {
    list-style:none; cursor:pointer; user-select:none;
    background:#fff; border:1px solid #ccc; border-radius:6px;
    padding:6px 14px; font-size:13px; font-weight:600; color:#333;
    box-shadow:0 1px 3px rgba(0,0,0,.1);
}
.sppbscan-support summary::-webkit-details-marker { display:none; }
.sppbscan-support summary::after  { content:" ▾"; }
.sppbscan-support[open] summary::after { content:" ▴"; }
.sppbscan-support-panel {
    position:absolute; right:0; margin-top:6px; min-width:200px;
    background:#fff; border:1px solid #ccc; border-radius:6px;
    box-shadow:0 4px 12px rgba(0,0,0,.15); overflow:hidden;
}
.sppbscan-support-panel a {
    display:block; padding:10px 14px; font-size:13px; color:#333;
    text-decoration:none; border-bottom:1px solid #eee;
}
.sppbscan-support-panel a:last-child { border-bottom:none; }
.sppbscan-support-panel a:hover { background:#f5f5f5; }
</style>

<?php
// ── SPPB version warning banner ─────────────────────────────────────
$w = $this->sppbWarning ?? null;
if ($w !== null && $w['safe'] !== true):
    $version = htmlspecialchars($w['version']);
    $major   = (int)($w['major'] ?? 0);
    if ($w['safe'] === false && $major === 5):
        // 5.x — vulnerable major series, no patch available
        $bannerClass = 'danger';
        $icon        = '🚨';
        $headline    = "SP Page Builder {$version} is installed — this major version is vulnerable and has no patch.";
        $detail      = 'The <code>uploadCustomIcon</code> unauthenticated RCE only affects SPPB 6.x, but SPPB 5.x has its own separate known vulnerabilities. <strong>Update to SPPB 6.6.2+ immediately</strong>, or remove the component if you no longer use it.';
    elseif ($w['safe'] === false):
        // 6.x older than 6.6.2
        $bannerClass = 'danger';
        $icon        = '🚨';
        $headline    = "SP Page Builder {$version} is installed — this version is vulnerable to the uploadCustomIcon RCE.";
        $detail      = 'Unauthenticated attackers can upload PHP webshells via the Custom Icons feature in SPPB 6.x &lt; 6.6.2. <strong>Update to 6.6.2 immediately</strong> via the Joomla Extension Manager before doing anything else — scanning a still-vulnerable site just means cleaning up the same infection again.';
    else:
        // version string unreadable
        $bannerClass = 'warning';
        $icon        = '⚠️';
        $headline    = "SP Page Builder is installed but its version could not be determined.";
        $detail      = 'Check the installed version manually under <strong>Extensions → Manage → Manage</strong> and confirm it is 6.6.2 or newer before proceeding.';
    endif;
?>
<div class="alert alert-<?= $bannerClass ?> d-flex gap-3 align-items-start mb-3" role="alert" style="border-left:4px solid <?= $bannerClass === 'danger' ? '#dc3545' : '#ffc107' ?>">
    <div style="font-size:24px;line-height:1;flex-shrink:0"><?= $icon ?></div>
    <div>
        <strong><?= $headline ?></strong><br>
        <span style="font-size:13px"><?= $detail ?></span><br>
        <a href="index.php?option=com_installer&view=update" class="btn btn-<?= $bannerClass ?> btn-sm mt-2">
            Go to Extension Manager → Update
        </a>
    </div>
</div>
<?php endif; ?>

<!-- Loading overlay (shown while scan POST is in flight) -->
<div id="sppbscan-overlay">
    <div class="sppbscan-spinner"></div>
    <div class="sppbscan-overlay-text">Scanning your Joomla installation…</div>
    <div class="sppbscan-overlay-sub">This may take 10–30 seconds depending on site size.</div>
</div>

<!-- Support widget -->
<details class="sppbscan-support">
    <summary>Support</summary>
    <div class="sppbscan-support-panel">
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">☕ Buy me a coffee(Via Payoneer or PayPal Zoom)</a>
        <a href="mailto:zkranao@gmail.com" target="_blank" rel="noopener">✉️ Need help? Email me</a>
        <a href="https://www.linkedin.com/in/zkranadevs/" target="_blank" rel="noopener">💬 Reach me on LinkedIn</a>
    </div>
</details>

<?php if (!$this->scanned): ?>
<!-- ═══════════════════════════════════════════════════════════════════
     SCAN GATE — no cached results yet, show the "Run Scan" screen
     ═══════════════════════════════════════════════════════════════════ -->
<div class="sppbscan-gate">
    <div class="gate-icon">🛡️</div>
    <h2>SP Page Builder Infection Scanner</h2>
    <p>
        Click <strong>Run Scan</strong> to walk the filesystem and check the database
        for malware, rogue admin accounts, XSS injections, and defacement markers
        left behind by the SPPB <code>uploadCustomIcon</code> RCE (pre-6.6.2).
        The scan typically takes 10–30 seconds.
    </p>
    <form action="<?= Route::_($scanUrl) ?>" method="post" id="sppbscan-form">
        <?= HTMLHelper::_('form.token') ?>
        <button type="submit" class="btn btn-primary btn-scan">
            🔍 Run Scan
        </button>
    </form>
    <p class="text-muted" style="font-size:12px;">
        Results are cached for 5 minutes. Use <strong>Re-scan</strong> to force a fresh run.
    </p>
</div>

<?php else: ?>
<!-- ═══════════════════════════════════════════════════════════════════
     RESULTS — cached scan available
     ═══════════════════════════════════════════════════════════════════ -->

<!-- Re-scan bar -->
<div class="sppbscan-rescan-bar">
    <span>
        Last scanned:
        <span class="scan-time"><?= date('Y-m-d H:i:s', $this->scanStartedAt) ?></span>
        · Results cached for 5 minutes
    </span>
    <form action="<?= Route::_($rescanUrl) ?>" method="post" id="sppbscan-rescan-form" style="margin:0">
        <?= HTMLHelper::_('form.token') ?>
        <button type="submit" class="btn btn-sm btn-outline-secondary">
            🔄 Re-scan now
        </button>
    </form>
</div>

<!-- Stats -->
<div class="sppbscan-stats">
    <?php $fc = count($fileFindings); ?>
    <div class="sppbscan-stat <?= $fc > 0 ? 'dirty' : 'clean' ?>">
        <div class="num"><?= (int)$fc ?></div>
        <div class="label">
            Suspicious files
            <?php if ($fc > 0): ?>(<?= $this->highCount ?> high · <?= $this->medCount ?> medium)<?php endif; ?>
        </div>
    </div>
    <div class="sppbscan-stat <?= count($suspiciousSU) > 0 ? 'dirty' : 'clean' ?>">
        <div class="num"><?= count($suspiciousSU) ?></div>
        <div class="label">Rogue super users</div>
    </div>
    <div class="sppbscan-stat <?= count($dbFindings['menu_xss']) > 0 ? 'dirty' : 'clean' ?>">
        <div class="num"><?= count($dbFindings['menu_xss']) ?></div>
        <div class="label">Menu XSS rows</div>
    </div>
    <div class="sppbscan-stat <?= (count($dbFindings['sppb_assets']) + count($dbFindings['rogue_iconfont'])) > 0 ? 'dirty' : 'clean' ?>">
        <div class="num"><?= count($dbFindings['sppb_assets']) + count($dbFindings['rogue_iconfont']) ?></div>
        <div class="label">Rogue asset rows</div>
    </div>
    <div class="sppbscan-stat <?= count($dbFindings['template_defacement']) > 0 ? 'dirty' : 'clean' ?>">
        <div class="num"><?= count($dbFindings['template_defacement']) ?></div>
        <div class="label">Template defacement</div>
    </div>
</div>

<div class="alert alert-info">
    This is a heuristic scanner. Pair it with a full server-side malware scan (ClamAV / Imunify360) before declaring the site clean.
</div>

<!-- 1. Files -->
<h3>1. Suspicious files &amp; folders</h3>
<div class="card mb-3">
    <div class="card-body">
    <?php if (empty($fileFindings)): ?>
        <p class="text-success">✅ No suspicious files detected.</p>
    <?php else: ?>
        <form action="index.php?option=com_sppbscan&task=scanner.delete" method="post"
              onsubmit="return confirm('Delete selected files/folders? This cannot be undone.');">
            <table class="table table-striped">
                <thead><tr>
                    <th style="width:2%"><input type="checkbox" onclick="document.querySelectorAll('.sppb-file-chk').forEach(c=>c.checked=this.checked)"></th>
                    <th>Path</th><th>Type</th><th>Confidence</th><th>Reason</th><th>Size</th><th>Modified</th>
                </tr></thead>
                <tbody>
                <?php foreach ($fileFindings as $f): ?>
                    <tr>
                        <td><input type="checkbox" class="sppb-file-chk" name="targets[]" value="<?= htmlspecialchars($f['rel']) ?>"></td>
                        <td class="sppbscan-path"><?= htmlspecialchars($f['rel']) ?></td>
                        <td><span class="badge bg-secondary"><?= $f['type'] === 'dir' ? 'DIR' : 'FILE' ?></span></td>
                        <td><span class="badge bg-<?= $f['confidence'] === 'high' ? 'danger' : 'warning' ?>"><?= $f['confidence'] === 'high' ? 'High' : 'Medium' ?></span></td>
                        <td class="sppbscan-reason"><?= htmlspecialchars($f['reason']) ?></td>
                        <td><?= \SppbscanHelper::humanSize($f['size']) ?></td>
                        <td><?= $f['mtime'] ? date('Y-m-d H:i', $f['mtime']) : '—' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit" class="btn btn-danger">🗑 Delete selected</button>
            <span class="text-muted small ms-2">Only items flagged in this scan run can be deleted.</span>
        </form>
    <?php endif; ?>
    </div>
</div>

<!-- 2. Super Users -->
<h3>2. Super User accounts</h3>
<div class="card mb-3">
    <div class="card-body">
    <?php if (empty($dbFindings['superusers'])): ?>
        <p class="text-success">✅ No super user accounts found.</p>
    <?php else: ?>
        <table class="table table-striped">
            <thead><tr><th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Registered</th><th>Last Visit</th><th>Status</th></tr></thead>
            <tbody>
            <?php foreach ($dbFindings['superusers'] as $u): ?>
                <tr>
                    <td><?= (int)$u['id'] ?></td>
                    <td><?= htmlspecialchars($u['name']) ?></td>
                    <td class="sppbscan-path"><?= htmlspecialchars($u['username']) ?></td>
                    <td><?= htmlspecialchars($u['email']) ?></td>
                    <td><?= htmlspecialchars($u['registered']) ?></td>
                    <td><?= htmlspecialchars($u['lastvisit']) ?></td>
                    <td>
                        <?php if ($u['suspicious']): ?>
                            <span class="badge bg-danger">⚠ Suspicious</span>
                            <div class="small text-danger"><?= htmlspecialchars($u['why']) ?></div>
                        <?php else: ?>
                            <span class="badge bg-success">✓ Normal</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="text-muted small">Remove rogue accounts via Users → Manage — do not delete your own account.</p>
    <?php endif; ?>
    </div>
</div>

<!-- 3. Menu XSS -->
<h3>3. Menu XSS injections</h3>
<div class="card mb-3">
    <div class="card-body">
    <?php if (empty($dbFindings['menu_xss'])): ?>
        <p class="text-success">✅ No injected menu items found.</p>
    <?php else: ?>
        <form action="index.php?option=com_sppbscan&task=scanner.cleanmenu" method="post"
              onsubmit="return confirm('Surgically clean XSS from the selected menu rows?');">
            <table class="table table-striped">
                <thead><tr>
                    <th style="width:2%"><input type="checkbox" onclick="document.querySelectorAll('.sppb-menu-chk').forEach(c=>c.checked=this.checked)"></th>
                    <th>ID</th><th>Title</th><th>Link</th><th>Matched signatures</th>
                </tr></thead>
                <tbody>
                <?php foreach ($dbFindings['menu_xss'] as $m): ?>
                    <tr>
                        <td><input type="checkbox" class="sppb-menu-chk" name="menu_xss_ids[]" value="<?= (int)$m['id'] ?>"></td>
                        <td><?= (int)$m['id'] ?></td>
                        <td><?= htmlspecialchars($m['title']) ?></td>
                        <td class="sppbscan-path"><?= htmlspecialchars($m['link']) ?></td>
                        <td class="sppbscan-reason"><?= htmlspecialchars(implode(', ', $m['matches'] ?? [])) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?= HTMLHelper::_('form.token') ?>
            <button type="submit" class="btn btn-danger">🧹 Clean selected rows</button>
            <span class="text-muted small ms-2">Surgically removes XSS payload from params — legitimate menu settings are preserved.</span>
        </form>
    <?php endif; ?>
    </div>
</div>

<!-- 4. SP Page Builder assets -->
<h3>4. SP Page Builder asset table</h3>
<div class="card mb-3">
    <div class="card-body">
    <?php if (empty($dbFindings['sppb_assets']) && empty($dbFindings['rogue_iconfont'])): ?>
        <p class="text-success">✅ No suspicious rows found in sppagebuilder_assets.</p>
    <?php else: ?>
        <?php if (!empty($dbFindings['sppb_assets'])): ?>
            <h4>Injected payload rows</h4>
            <table class="table table-striped">
                <thead><tr><th>Row data</th></tr></thead>
                <tbody>
                <?php foreach ($dbFindings['sppb_assets'] as $row): ?>
                    <tr><td><pre style="white-space:pre-wrap;font-size:11px;"><?= htmlspecialchars(json_encode($row, JSON_PRETTY_PRINT)) ?></pre></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        <?php if (!empty($dbFindings['rogue_iconfont'])): ?>
            <form action="index.php?option=com_sppbscan&task=scanner.deleteassets" method="post"
                  onsubmit="return confirm('Delete selected rogue iconfont rows?');">
                <h4>Rogue iconfont registrations (<?= count($dbFindings['rogue_iconfont']) ?>)</h4>
                <table class="table table-striped">
                    <thead><tr>
                        <th style="width:2%"><input type="checkbox" onclick="document.querySelectorAll('.sppb-asset-chk').forEach(c=>c.checked=this.checked)"></th>
                        <th>ID</th><th>Name</th><th>Title</th><th>Created</th><th>Created By</th><th>Assets</th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($dbFindings['rogue_iconfont'] as $row): ?>
                        <tr>
                            <td><input type="checkbox" class="sppb-asset-chk" name="rogue_asset_ids[]" value="<?= (int)$row['id'] ?>"></td>
                            <td><?= (int)$row['id'] ?></td>
                            <td><code><?= htmlspecialchars($row['name']) ?></code></td>
                            <td><?= htmlspecialchars($row['title']) ?></td>
                            <td><?= htmlspecialchars($row['created']) ?></td>
                            <td><?= (int)$row['created_by'] ?></td>
                            <td><code><?= htmlspecialchars($row['assets']) ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?= HTMLHelper::_('form.token') ?>
                <button type="submit" class="btn btn-danger">🗑 Delete selected</button>
            </form>
        <?php endif; ?>
    <?php endif; ?>
    </div>
</div>

<!-- 5. Template defacement -->
<h3>5. Template styles defacement</h3>
<div class="card mb-3">
    <div class="card-body">
    <?php if (empty($dbFindings['template_defacement'])): ?>
        <p class="text-success">✅ No defacement markers found in template_styles.</p>
    <?php else: ?>
        <table class="table table-striped">
            <thead><tr><th>ID</th><th>Template</th><th>Title</th><th>Matches</th></tr></thead>
            <tbody>
            <?php foreach ($dbFindings['template_defacement'] as $row): ?>
                <tr>
                    <td><?= (int)$row['id'] ?></td>
                    <td class="sppbscan-path"><?= htmlspecialchars($row['template']) ?></td>
                    <td><?= htmlspecialchars($row['title']) ?></td>
                    <td class="sppbscan-reason"><?= htmlspecialchars(implode(', ', $row['matches'])) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="text-muted small">Review and restore these template styles from a clean backup.</p>
    <?php endif; ?>
    </div>
</div>

<div class="alert alert-secondary">
    When you're done, uninstall this component via <strong>Extensions → Manage → Manage</strong> to remove it from your site completely.
</div>

<?php endif; // end $this->scanned ?>

<script>
(function () {
    // Show the loading overlay when either scan form is submitted
    var forms = [document.getElementById('sppbscan-form'), document.getElementById('sppbscan-rescan-form')];
    var overlay = document.getElementById('sppbscan-overlay');
    forms.forEach(function (form) {
        if (!form) return;
        form.addEventListener('submit', function () {
            overlay.classList.add('active');
        });
    });
})();
</script>
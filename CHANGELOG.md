# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

Each release on GitHub pulls its description directly from this file — see `scripts/release.sh`, which refuses to cut a release without a matching entry here.

## [Unreleased]

## [2.4.6] - 2026-07-24

### Fixed

- **2.4.5's new "no templateDetails.xml means fake template" check false-positived on Joomla's own bundled `system` fallback template** (`templates/system/` and `administrator/templates/system/` — `offline.php`, `error.php`, `fatal.php`, and friends, used for maintenance/error pages). This folder is core Joomla, never installed via the extension installer, so it legitimately has no manifest — unlike every other template folder. It's now explicitly exempted from the no-manifest junk check; a file inside it is still flagged normally if the actual content-signature scan finds something genuinely injected.

## [2.4.5] - 2026-07-24

### Fixed

- **This scanner flagged its own former self as suspicious.** A leftover `administrator/components/com_sppbscan/` directory (this extension's name before the 2.2.0 rebrand to MuRu Guard) got no exemption from content scanning, so its `helpers/sppbscan.php` and `models/scanner.php` self-matched multiple high-confidence signatures -- unavoidable, since this scanner's own `CONTENT_SIGNATURES` table necessarily contains the literal marker text (`xss.report`, `secure.local`, `FilesMan`, ...) it's matching against, and a raw content scan of its own source finds "matches" against itself. The current-named copy only ever escaped this by coincidence, via an existing safe-path exemption for its live install path. Added the same exemption for the old `com_sppbscan` path.
- **A real, in-the-wild mass webshell-drop pattern was completely missed, and worse, actively protected from deletion.** Attackers created folders like `templates/beez3_degj/`, `templates/cassiopeia_hhnm/`, `templates/responsive_jsox/` -- an existing template's own name plus a random 4-character suffix -- each containing nothing but a tiny backdoor `index.php`. These aren't real templates (no `templateDetails.xml`, nothing Joomla ever installed), but every `templates/<name>/index.php` was unconditionally treated as "Required — use Clean, not Delete" purely by path pattern, with no check that the folder was ever a real template at all. The existing junk-folder check also only recognized the `tmpl_xxxxxx` auto-generated naming style, not this "real name + random suffix" variant. Both checks now verify the folder actually has a `templateDetails.xml` manifest; a `templates/<name>/index.php` without one is flagged as a junk template folder and is now deletable like any other suspicious file, instead of being steered toward a "clean" action that never made sense for a folder with no legitimate content to preserve in the first place.

## [2.4.4] - 2026-07-24

### Fixed

- **The scan-area picker modal's inner content (checkboxes, area labels, the Run Scan button) had no visible styling.** The whole modal is moved to be a direct child of `<body>` at runtime so its `position: fixed` isn't broken by a `transform`-ed ancestor in Joomla's admin template — but that also takes it outside `#muruguard-root`, which is what Tailwind's utility classes are scoped to. The dialog chrome (backdrop, header, footer) already had a plain-CSS fallback for exactly this reason; the modal's inner content, added later, didn't. Added the missing plain CSS, scoped under `#muru-scan-modal` specifically so it can't leak into the rest of the Joomla admin page.
- **The Template Defacement tab had no way to act on findings** — every other findings tab (Files, Cleanable Files, Menu XSS, SPPB Assets) has row selection and a clean/delete action; this one was read-only, telling you to go delete rows manually via phpMyAdmin/SQL. It now has the same select-all/per-row checkboxes and a delete button as the other tabs — but only rows independently re-confirmed as junk (an orphaned template reference or an auto-generated `tmpl_xxxxxx` name) are actually deleted; rows flagged only for defacement *text* are skipped even if selected, since a text match alone isn't a reliable enough signal to safely auto-delete a row that could otherwise be legitimate.

## [2.4.3] - 2026-07-24

### Fixed

- **The `#__sppagebuilder_assets` payload scan (`eval(`, `base64_decode`, `xss.report`, script tags, event handlers) was checking a column that doesn't exist.** It read `$row['asset_value']`, but the real table column is `assets` -- `asset_value` was always `null`/empty on every real install, so this entire check has never actually inspected real row content, for any row, regardless of name. A row named exactly `icofont` (SP Page Builder's own legitimate default) skipped the separate name-based "non-default iconfont" check too, so in combination it had zero chance of ever being flagged no matter what it actually contained. Fixed the column name, and the payload checks now run against every row's real content unconditionally -- a "known good" name is no longer a bypass for content inspection.
- Also now checks `css_path` (the other attacker-controllable text field on this table) the same way, plus a new check that it only ever references an actual `.css` file -- a path ending in `.php`/`.phtml`/other executable extension is flagged directly, since nothing else on this table would have caught a malicious file smuggled in through that field.

## [2.4.2] - 2026-07-24

### Fixed

- **The `#__template_styles` scan missed a real, active compromise pattern.** It only matched classic defacement text ("Hacked by", "Owned by", ...) inside the `params` column. A batch of dozens of injected junk rows -- randomly named `tmpl_xxxxxx`, titled `"<name> - 默认"` ("- Default" in Chinese regardless of the site's actual language), params usually just `{}` -- went completely undetected, since there's no defacement text in them at all. Added a second, independent check: a row's `template` column is compared against the actual template folders present on disk (`templates/` for the frontend, `administrator/templates/` for the admin) -- a legitimate Joomla install never has a style row pointing at a template that isn't installed, so a row that does is flagged as an orphaned/injected reference. Combined with a check for the `tmpl_xxxxxx` auto-generated naming pattern itself for a second, corroborating signal.
- **The filesystem scan had the matching blind spot on the other side of the same attack.** `templates/` is scanned in signature-only "code" mode (`.php` is expected there), so a whole `templates/tmpl_xxxxxx/` folder full of dropped files went undetected as long as their *content* didn't happen to match a known webshell pattern -- even though the folder name itself (matching the exact junk pattern above, one-to-one with the fake database row of the same name) is a dead giveaway on its own. Added a location-based check, alongside the existing core-masquerade check, that flags anything inside a top-level `templates/<name>` or `administrator/templates/<name>` folder whose `<name>` matches the `tmpl_xxxxxx` pattern -- independent of file content, so it still catches the drop even when the payload itself doesn't match any known signature.

### Changed

- **Modernized the scan-area picker modal.** Gradient header matching the hero, icon in a rounded badge, a pill-styled "Select all", card-style grouped sections with hover elevation, and a proper vertically-*and*-horizontally centered dialog (it previously only centered horizontally and sat pinned near the top of the viewport).
- Clicking **Run** inside that modal now closes the modal immediately before showing the scanning overlay, instead of leaving it open underneath.

## [2.4.1] - 2026-07-21

### Changed

- **Simplified the scan-gate screen.** Opening the scanner now shows just the hero (icon, title, description) and a single **🔍 Run a Scan** button, instead of the full directory/checks picker sitting inline on the page. Clicking the button opens a modal with the same "🗂 Directories & checks to scan" picker (Select all + the 4 grouped sections), with its own **Run** button that starts the scan -- the picker itself didn't change, just where it lives.
- **Settings → Protection is now the default tab**, ahead of Scheduled Scanning and Setup Guide, since it's the primary place most people will want to land after installing Protection Mode.

## [2.4.0] - 2026-07-21

### Added

- **Protection Mode: real-time attack detection and blocking.** A new companion plugin, **System - MuRu Guard Shield** (`plg_system_muruguardshield`), checks every incoming request against known attack patterns -- webshell interaction, a direct probe against the SP Page Builder `uploadCustomIcon` RCE, known malware-drop filenames, path traversal probes, and known scanner User-Agents -- and tracks failed backend logins per IP. It ships as a **separate extension** because a component only runs when someone visits its own admin page; real-time, every-request protection has to live in a plugin instead.
- **Settings → Protection tab.** A master **Protection Mode** switch (log-only, zero risk of blocking real visitors when this is the only switch on), plus two independent opt-in switches to actually reject traffic: **block high-confidence attack patterns** (403 on a webshell/RCE/malware-filename match) and **block brute-force login attempts** (reject further backend logins from an IP once it crosses a configurable failed-attempt threshold and time window). All three are off by default. Already-authenticated, non-guest sessions are exempt from request-pattern blocking so a legitimate admin action can never trip a false block and lock them out of their own site -- brute-force blocking has no such exemption, since it only ever targets pre-authentication attempts.
- **Protection Log**, sectioned by type (Attack Pattern Matches / Brute-Force Login Attempts), showing IP address, timestamp, severity, matched rule/reason, request URI, and whether each entry was actually blocked or only logged -- the last 500 entries, newest first, with a Clear Log action. Gated behind the same Change Settings (`core.admin`) permission as everything else in Settings, since it's a security audit trail, not just a scan result.
- The plugin has no settings screen of its own -- it reads `com_muruguard`'s params directly (`ComponentHelper::getParams('com_muruguard')`), so Protection Mode is configured entirely from this component's Settings panel. It fails open, silently, if the component isn't installed or a check throws, since a bug in a security feature that runs on every single page load must never be able to take the whole site down.

## [2.3.1] - 2026-07-19

### Fixed

- **The Permissions tab never appeared on System → Global Configuration → MuRu Guard, no matter what `access.xml` declared.** Confirmed by reading Joomla core's own `com_config` source directly: a component's Permissions tab isn't generated automatically just because `access.xml` exists -- each component's own `config.xml` has to explicitly ask for it via a `<fieldset name="permissions">` containing a `<field type="rules" component="com_muruguard" section="component">`, the same way core components like `com_cache`/`com_redirect` do it. That fieldset was simply never added when the 4 ACL actions were introduced in 2.3.0, so `access.xml` alone had nothing to render into.
- The Global Configuration page title showed the raw, untranslated string `com_muruguard_configuration` instead of a real title -- the specific language key Joomla's `com_config` view requests (`Text::_($component . '_configuration')`) was never defined. Added `COM_MURUGUARD_CONFIGURATION`.

## [2.3.0] - 2026-07-19

### Added

- **Joomla ACL support.** Access is no longer all-or-nothing (`core.manage` deciding everything). `access.xml` now declares four actions -- **View & Scan** (`core.manage`, the base gate every group needs), **Clean** (`core.edit`, repairs infected files/menu items), **Delete** (`core.delete`, removes flagged files/rows), and **Change Settings** (`core.admin`, edits scheduled-scanning config) -- configurable per User Group the standard Joomla way, on the **Permissions** tab of System → Global Configuration → MuRu Guard (Joomla generates that tab automatically from `access.xml`, nothing custom to open). A group with only View & Scan can see every finding but every action button is replaced with a "you have view access but not X permission" notice instead of a control that would just 403 on click.
- **Multilingual support.** Every string in the scanner page -- headings, buttons, table columns, tab labels, confirm dialogs, placeholders, the loading-overlay progress messages, and every Delete/Clean/Settings flash message -- now routes through Joomla's language system instead of being hardcoded English. Only `en-GB` ships today, but the interface follows whichever language an admin's account is set to, and a translator can add another by copying `administrator/language/en-GB/en-GB.com_muruguard.ini` into a new language's folder and translating the values.
- The in-page **Setup Guide** tab (Settings → Setup Guide) now documents both of the above: what each of the 4 permission actions controls and where to set them, and how to add a translation.

## [2.2.3] - 2026-07-17

### Fixed

- **The Settings screen's "Scheduled Scanning" / "Setup Guide" tabs didn't switch — clicking "Setup Guide" did nothing.** The tab markup and panels had been added but never wired up: there was no `.muru-settings-tab.active` styling and no click handler to toggle between panels, so the page just sat on whichever tab rendered first. Added the matching CSS active state (mirroring the existing results-tab styling) and a click handler that toggles the clicked tab and its matching panel, following the same active/hidden pattern already used elsewhere in the template.

### Changed

- **Renamed leftover `sppb-` CSS classes, JS functions, and PHP template helpers to `muru-`/`muru_`.** These were internal naming left over from the old SPPB Scan codebase (`sppb-tab`, `sppb-diff-block`, `sppbOpenCodeModal`, `sppb_section_open`, etc.) that the 2.2.0 rebrand had missed. Left untouched anything that names the actual third-party SP Page Builder extension being scanned — `sppbWarning`, `getSppbVersionWarning`, the `sppb_assets` finding key, and the `codex-sppb-*`/`codex_sppb*` malware filename patterns — since those refer to the real extension, not this app's own branding.

## [2.2.2] - 2026-07-17

### Fixed

- **v2.2.1's fix wasn't enough — confirmed on a live install that "Run Scan" (and every other button) still 404'd.** The inheritance-based fix assumed `BaseController::getInstance()` would make every task method reflectable one way or another; on this real site it didn't. The entry point now bypasses Joomla's own "prefix.method" task resolution entirely for every `scanner.*` task: it parses the prefix itself, instantiates `MuruguardControllerScanner` directly, and calls the named method by hand. No more dependency on assumptions about how a given Joomla version resolves that dot-notation — verified against every action (`scan`, `delete`, `scheduledcheck`, and by extension `cleancode`/`cleanmenu`/`deleteassets`/`savesettings`) with a test harness built around the actual entry-point file.

## [2.2.1] - 2026-07-17

### Fixed

- **"Run Scan" (and every other button — Delete, Clean, Clean menu XSS, Delete assets) did nothing on a real install, silently falling through to a "404 View not found: muruguard" error.** `BaseController::getInstance()` always instantiates the base `MuruguardController` class; it does *not* automatically switch to `MuruguardControllerScanner` just because the task carries a `scanner.` prefix — Joomla only strips that prefix to get the method name, then looks for it as a reflectable method on the object it already created. Since `scan()`, `delete()`, `cleancode()`, `cleanmenu()`, `deleteassets()`, `scheduledcheck()`, and `savesettings()` all lived on the separate `MuruguardControllerScanner` class, none of them were ever actually reachable. `MuruguardController` now extends `MuruguardControllerScanner` instead of the base Joomla controller directly, so every task method is inherited onto the exact object Joomla dispatches to. This bug predates the MuRu Guard rebrand — it was present in the SPPB Scan codebase too, just never caught since nothing in this project's history had been run against real, unmocked Joomla task dispatch until now.

## [2.2.0] - 2026-07-17

### ⚠️ Breaking: SPPB Scan is rebranded to MuRu Guard

**SPPB Scan is rebranded to MuRu Guard** in this version. The Joomla extension element changes (`com_sppbscan` → `com_muruguard`), along with every class name, the language file, and the admin menu entry (now **MuRu Guard**). Joomla treats this as a **different extension**, not an in-place upgrade: on a site that already has the old `com_sppbscan` installed, uninstall it first, then install this package fresh. Scan history and settings do not carry over automatically since they live under the old element name.

### Added

- **Core-file checksum verification.** The scanner now detects your exact installed Joomla version (from `administrator/manifests/files/joomla.xml`) and compares `index.php`, `administrator/index.php`, `api/index.php`, `includes/app.php`, `includes/framework.php`, `robots.txt.dist`, `htaccess.txt`, and `web.config.txt` against bundled official SHA-256 hashes for the latest patch of the 4.4 LTS, 5.x, and 6.x Joomla lines. A mismatch is byte-for-byte proof of tampering, independent of every pattern-based check — and it already caught a real gap: a backdoor appended after a file's closing `?>` tag (no `base64_decode`, no recognizable signature) that every existing heuristic missed entirely. An unlisted Joomla version simply skips this check — never a false positive from missing coverage.
- **Clean preview.** In the Cleanable Files tab, the 🧬 Code Issues modal now shows a 🔍 Preview section with the exact bytes Clean would remove (and what replaces them, if anything) for any file with a recognized auto-fix pattern — computed read-only against the file's current content, never written to disk. Files with no recognized auto-fix pattern correctly show no preview button, so the UI never promises a fix that won't happen.
- **Scheduled scanning via webcron**, with a dedicated in-page **⚙️ Settings panel** (next to the existing 💬 Support button — click it to swap the whole page for a Settings view, click "← Back to scanner" to return). From there you can flip a switch to enable/disable scheduled scanning, generate a secret token with one click, set an alert email, and copy the ready-to-use webcron URL — no trip to Global Configuration required (though System → Global Configuration → MuRu Guard still works too, and both stay in sync). Point any cron system (server crontab, host control panel, or a free external cron service) at that URL with `curl`/`wget` — no SSH, no login, no CSRF token needed. Runs the same detection as a manual scan and emails only when something new appears since the last run — never on every run, and never on the very first run (which just records a baseline). A status badge on the main dashboard shows "⏰ Scheduled scanning ON" whenever it's active, click it to jump straight into Settings.

### Fixed

- **Scheduled scanning was completely unreachable.** Found during a self-directed security review of this component: the admin entry point required a logged-in Super User session for *every* task, including the new webcron endpoint — so a real cron/curl request (which has no Joomla session) was rejected before its own secret-token check ever ran. The entry point now exempts only that one task from the blanket session check; every other action is gated exactly as before.
- The scheduled-scan history (used to compute "what's new since last run") was being stored inside this component's own config params — the exact same storage System → Global Configuration saves to. Saving Global Configuration for any reason would have silently wiped that history with no warning, since Joomla's config save replaces the whole params blob with just the declared fields. It now lives in its own small file instead, immune to that entirely.

### Removed

- The "pair this with ClamAV/Imunify360" and "uninstall when you're done" footer notices, from both the scanner page and this README — noise, not signal.

## [2.1.11] - 2026-07-17

### Fixed

- **A legitimate, actively-used component/module/plugin/library/template file with a backdoor snippet injected into it could land in the "Suspicious Files" tab with only a Delete option.** That's a real, needed file with malicious content added, not a foreign dropped file — deleting it would break the site. Findings inside real code directories that are flagged *only* by a content-signature match (no filename/location red flag alongside it) are now routed to the "Cleanable Files" tab instead, where the safe outcome is either an auto-clean or a clear "no pattern recognized, review manually" message — never an outright delete.

## [2.1.10] - 2026-07-16

### Changed

- Rewrote `<head>` script-injection detection and repair to share a single implementation based on plain string search instead of two independently-maintained regexes, so the two can never silently disagree on the same file.
- The Clean code result message now uses the right severity color (red for failures/warnings, yellow for skips, green for success) instead of always rendering as flat blue info text.

### Fixed

- **Clean code could silently do nothing on a read-only file.** Added an explicit writability check before attempting a repair, with a clear message pointing at file ownership/permissions — the most common real-world reason a "successful" clean doesn't actually stick on shared hosting.
- **Clean code now verifies its own write.** After writing the repaired file, it's re-read from disk and re-checked; if the infection pattern is somehow still present (a cache, a file-integrity/restore tool, or anything else reverting the change), you now get an explicit warning instead of a false "CLEANED" result.

## [2.1.9] - 2026-07-16

### Added

- **"AI Integration — coming soon"** preview button in the re-scan bar.

### Changed

- Removed the redundant **Clean code** button from the Suspicious Files tab — cleaning now lives exclusively in the Cleanable Files tab, so each tab has exactly one clear action (Delete vs. Clean).
- Added a shared `SppbscanHelper::isProtectedEntryPath()` helper and switched both the model's `deleteTargets()` and the results-table row renderer to use it, removing a duplicated (and slightly drifting) inline check.

### Fixed

- **Suspicious Files tab no longer lists files it can't actually delete.** Auto-cleanable files and required core/template entry files (`index.php`, `administrator/index.php`, a template's own root `index.php`, ...) were still showing up in the Suspicious Files list even though Delete would just skip them — they now appear only in the Cleanable Files tab. Every finding still lands in exactly one of the two tabs; nothing is dropped.
- **"Select all" did nothing in the Cleanable Files tab.** The tab's `<section>` wrapper never actually had the `id="sec-cleanable"` attribute the checkbox handler was targeting (only a `data-panel` attribute) — every `sppb_section_open()` panel now gets a real `id`.

## [2.1.8] - 2026-07-16

## Fixed and Improved

- Add file content preview snippets to suspicious file findings to display matched code in the admin UI.
- Introduce a new Cleanable Files tab in the scanner view that lists files with safely auto-repairable infections (code prepended before Joomla's bootstrap or head tag injections).
- Add helper functions for detecting cleanable patterns and rendering shared file rows across tabs to reduce code duplication.
- Refactor existing file listing UI code to use the shared render function.
- Update the checkCoreMasquerade helper to accept an absolute path parameter and append preview text to findings.
- Bump the package version from 2.1.7 to 2.1.8.


## [2.1.7] - 2026-07-16

### Fixed

- False positives on genuine Joomla core files: `libraries/cms.php`, `libraries/web.config`, `cli/web.config`, `bin/web.config`, and `templates/system/fatal.php` were flagged as core-path disguises because the loose-file allowlist backing that check was incomplete.
- False positive on `.phpstorm.meta.php` (and similar IDE-metadata files) shipped inside third-party `libraries/vendor/*` packages — the "hidden dot-file with an executable extension" check didn't distinguish these well-known benign convention files from an attacker-planted hidden file.

## [2.1.6] - 2026-07-16

### Added

- **Directory-selection picker before scanning.** Choose which areas to scan (upload/media directories, extension & template code, core & webroot, database) instead of always scanning everything.
- **Core-file masquerade detection.** Flags files whose *path* impersonates legitimate Joomla core (`libraries/system.php`, `bin/cms.php`, `cli/cli.php`, `templates/*/network.php`, hidden dot-files with executable extensions, unexpected loose files in `libraries/`/`cli`/`bin`) even when the content itself looks harmless — a common real-world disguise technique.
- **Stray/masquerade `index.php` detection.** Any `index.php` outside a template's own root is expected to be Joomla's blank access-guard stub; non-stub content is now flagged. A known real-world artifact — a `features/index.php` planted in a template that has no such folder — is flagged unconditionally on location alone, regardless of content, since attackers can trivially fake a blank stub.
- **Auto-clean for infected core/template entry files.** `index.php` (root), `administrator/index.php`, `api/index.php`, `includes/app.php`, and any template's own root `index.php` are now *protected from deletion* and instead get a surgical **Clean code** action that strips a prepended payload (code injected before Joomla's bootstrap/access guard) while leaving 100% of the legitimate file untouched. A timestamped `.bak` backup is written before every repair. The same prepended-payload detection now also runs against *any* Joomla PHP file (core libraries, extensions), not just the four named entry points.
- **Code-analysis modal.** Suspicious file rows now show a short summary + a "🧬 Code Issues" button that opens a modal with the exact matched code for every triggered signature, plus a plain-language explanation of why it matched — instead of a wall of text crammed into a table cell.
- **Copy-path button** and a breadcrumb-styled path column (muted directory / bold filename) in the Suspicious Files table.
- **Tabbed results UI** replacing the old stacked-accordion layout.

### Changed

- Content-signature detections are now severity-tiered per signature instead of "any match = High confidence." Patterns with a plausible legitimate explanation (e.g. a dev-config file mentioning `secure.local`, a legitimate extension using a `zip://`/`phar://` stream wrapper) are now Medium ("needs manual review") instead of automatically High, so a real webshell isn't diluted next to false alarms.
- Reworked the whole admin UI: Tailwind is now scoped to the component root and preflight is disabled, so it no longer resets styling on the rest of the Joomla admin page (sidebar, post-install messages, dashboard widgets). The scan-progress overlay and floating support widget are re-parented to `<body>` at runtime to fix positioning broken by Joomla's own transformed sidebar-animation wrapper.

### Fixed

- **False positives on large legitimate photos.** The `<?=` short-tag polyglot check previously scanned the *entire* binary content of image files — in megabytes of high-entropy JPEG/PNG data that 3-byte sequence turns up by pure chance. Signature scanning on images is now windowed to the first/last few KB (matching how real polyglot payloads are actually planted — prepended or appended, never buried mid-stream), and the short tag must be followed by a plausible PHP token.
- **False positives on real images with mismatched-format bytes** (e.g. a `.jpg` that's actually WebP data from an image optimizer). Image integrity checking now trusts `getimagesize()`'s actual format sniff as ground truth instead of a strict per-extension magic-byte match.

## [2.1.5] - 2026-07-14

### Added

- Code analysis modal and copy buttons for scan results.

## [2.1.4] - 2026-07-13

### Added

- Improved malware detection signatures and reporting.

## [2.1.3] - 2026-07-11

### Added

- Detection for stray `index.php` files outside expected locations.

## [2.1.2] - 2026-07-10

### Fixed

- False positives in image scans.

## [2.1.1] - 2026-07-09

### Added

- Image scanning, UI, and styling fixes.

[Unreleased]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.6...HEAD
[2.1.6]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.5...v2.1.6
[2.1.5]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.4...v2.1.5
[2.1.4]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.3...v2.1.4
[2.1.3]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.2...v2.1.3
[2.1.2]: https://github.com/zkrana/joomla-security-scanner/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/zkrana/joomla-security-scanner/releases/tag/v2.1.1

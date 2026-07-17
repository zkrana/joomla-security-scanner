# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

Each release on GitHub pulls its description directly from this file — see `scripts/release.sh`, which refuses to cut a release without a matching entry here.

## [Unreleased]

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

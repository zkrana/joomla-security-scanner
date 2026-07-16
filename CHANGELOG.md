# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

Each release on GitHub pulls its description directly from this file — see `scripts/release.sh`, which refuses to cut a release without a matching entry here.

## [Unreleased]

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

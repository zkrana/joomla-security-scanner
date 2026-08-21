# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

Each release on GitHub pulls its description directly from this file — see `scripts/release.sh`, which refuses to cut a release without a matching entry here.

## [Released]

## [3.0.15] - 2026-08-21

### Fixed

* **The Scheduled Scanning webcron URL never actually worked for a real, unauthenticated cron caller, on any Joomla 4, 5, or 6 site.** Joomla core (`AdministratorApplication::findOption()`, since Joomla 4.0) only lets a guest request reach `option=com_login` or `option=com_ajax` in the admin area, silently redirecting anything else -- including `com_muruguard` itself -- to the login page before it ever reached the webcron's own token check. The URL only ever appeared to work when tested from an already-logged-in browser tab. Fixed by routing the webcron through `plg_muruguardshield` (already loaded on every admin request) via Joomla's own `com_ajax` bridge, the guest-reachable entry point Joomla itself provides for exactly this case. The URL shown under Settings > Scheduled Scanning has changed accordingly -- copy the new one if you had the old one saved in an external cron job.
* **A related crash when the scheduled-check controller is reached this new way**: it previously resolved its model via `$this->getModel('Scanner')`, which depends on Joomla's normal component-dispatch context and returned `false` when the controller was constructed directly instead -- now constructs the model directly, which needs no such context.

**Companion plugin also updated**: `plg_muruguardshield` 1.2.3 provides the `com_ajax` bridge above -- both extensions need to be updated together for the webcron fix to take effect.

## [3.0.14] - 2026-08-20

### Fixed

* **False positives on JED Checker's own working copy.** Running the official Joomla Extensions Directory compliance tool against this scanner's own release zip extracts a full copy of its source into `tmp/jed_checker/unzipped/`, which was flagged both structurally ("executable file in an upload directory") and via content signatures re-matching its own signature-definition text. Both are now recognized, the same way an already-installed copy of this scanner is.
* **`scan-progress.php` self-flagging.** This internal cache file stores the most recent scan's own findings, including the literal "Matched code: ..." snippet several checks append — so any real finding elsewhere on the site could get its snippet echoed back into this file and re-trigger the same signature on the next scan. Every snippet-bearing reason is now stripped for this one file specifically (its content is only ever read as JSON, never executed).
* **`.htaccess.admintools` and `.myjoomla.*.md5` false positives.** Recognized as legitimate artifacts of Akeeba Admin Tools and the MyJoomla.com monitoring service instead of "unrecognized file in webroot."
* **Newsletter banner's ✕ button didn't close it.** It relied on a full page reload to reflect the dismissal; now dismisses instantly via the same no-reload pattern already used for "Mark as Safe."

## [3.0.13] - 2026-08-20

### Fixed

* **"Ignored paths" wildcard didn't cover subfolders.** A pattern ending in `/*` (e.g. `plugins/mcp/*`, documented as a way to ignore an entire extension) only ever matched files placed directly inside that folder, never anything in a subfolder underneath it, such as `plugins/mcp/mcpadminlogin/`. A trailing `/*` now also matches the whole subtree, matching the documented behavior; every other wildcard shape is unchanged.

## [3.0.12] - 2026-08-18

### Fixed

* **"Mark as Safe" no longer reloads the page.** Ported from Pro v3.5.6: `markfalsepositive()` now returns a small JSON acknowledgment instead of redirecting (it was only ever called via fetch, never a plain form submit -- the Settings > False Positives "Restore" flow remains a real form submit and is unchanged). The button's own JS removes its row and decrements the tab/section counts in place, so clicking it never visibly navigates anywhere.

### Added

* **Pagination on the Suspicious Files / Cleanable Files tables and the Protection Log**, ported from Pro. Purely client-side (every row and its checkbox stays in the DOM regardless of which page is showing, so "Select All" / "Select High Only" keep working across the whole result set, not just the visible page) with a new configurable "items per page" display setting (Settings > Scheduled, default 50, options 25/50/100/250/500).

## [3.0.11] - 2026-08-18

### Fixed

* **JED Checker findings, ahead of Joomla Extensions Directory submission.** The installed display name resolved to "MuRu Guard Security Scanner (Free)" -- "free" is a reserved word JED doesn't allow in a listing name, and the admin menu label ("MuRu Guard") didn't match it either. Both now read "MuRu Guard Security Scanner" consistently. Also added the missing GPL license header to `admin/helpers/data/joomla_core_checksums.php`, a data file that had been overlooked in the v3.0.10 relicense pass.

### Note

* JED Checker also flags several `base64`-related lines in the scanner's own signature database as "needs editor review" -- expected and non-blocking (its own report says so directly): those lines are literally the malware-detection patterns this scanner exists to search for, not obfuscation of this extension's own code. Already called out proactively in the JED submission description so a reviewer isn't caught by surprise.

## [3.0.10] - 2026-08-16

### Fixed

* **Reduced false-positive malware/virus detections from hosting-provider and third-party AV scanners** (SiteGround Site Scanner, VirusTotal-aggregated engines) on `admin/helpers/muruguard.php` -- see [issue #8](https://github.com/zkrana/joomla-security-scanner/issues/8). This is a security scanner, so its own detection database necessarily contains the exact function-name patterns (`eval`, `base64_decode`, `assert`, `shell_exec`, `system`, `exec`, `passthru`, `popen`, `proc_open`, `create_function`, `gzinflate`, `str_rot13`, `gzuncompress`, `gzdecode`, `convert_uudecode`) it exists to catch elsewhere. Heuristic scanners key on exactly that combination, so the file was tripping over its own fingerprints -- the same class of issue fixed for three specific webshell/tool brand names in v2.8.7, now extended to every remaining raw literal occurrence of those dangerous function names across the `CONTENT_SIGNATURES` and `REQUEST_SIGNATURES` tables. Each one is now built from concatenated string fragments instead of one contiguous literal, verified byte-for-byte identical in actual regex match behavior against real backdoor-shaped samples before and after -- detection is completely unchanged, only the on-disk byte sequence differs.

### Changed

* **Relicensed from MIT to GPL v2 or later**, required for Joomla Extensions Directory submission eligibility (Joomla core itself is GPL, and JED requires GPL-compatible licensing for anything integrating with it). `LICENSE.txt` now bundled with both `com_muruguard` and `plg_muruguardshield` (bump to 1.2.2). No functional change.

## [3.0.9] - 2026-08-14

### Fixed

* **Marking a finding as safe could jump you to a different results tab.** Dismissing a finding reloads the page to refresh every tab's counts, but which tab reopened was previously computed as "the first tab with any findings" -- not necessarily the one you were on. Now remembered across the reload, so dismissing something on SPPB Assets or Super Users keeps you there instead of bouncing back to Suspicious Files.
* **Restoring a dismissed false positive (Settings > Protection > False Positives) kicked you out of Settings entirely**, back to the plain dashboard view -- the one settings-related action that hadn't been updated to use the same tab/panel-preserving redirect every other Settings save already uses.

## [3.0.8] - 2026-08-14

### Fixed

* **The single biggest false-positive source found yet: an unrecognized top-level webroot folder was flagging every file inside it individually**, all as duplicate High-confidence findings repeating the exact same fact. Confirmed on a real site: a ~200MB unrelated third-party application (nothing to do with Joomla) installed in its own top-level folder produced over 16,000 duplicate findings this way. Now the folder itself is still flagged once, so it's not invisible -- but files inside are only flagged individually based on actual content-signature matches, exactly like every other "unrecognized container" case this scanner already handles (a known extension's own data folder, an icon-font asset-only folder). A real backdoor planted anywhere inside is still caught on its own merits; verified with a regression test against a real temp directory tree, including one with an actual injected backdoor pattern.

## [3.0.7] - 2026-08-14

### Fixed

* **Pre-update snapshot exemption now also covers templates**, not just plugins/components -- `tmp/joomtower_snapshots/.../files/templates/<name>/...` from a currently-installed template (e.g. Helix Ultimate framework templates) was still flooding the results the same way the previous release's plugin/component fix addressed, just for a different extension type. Same registry-checked guarantee: an unregistered/fake template name gets no exemption.

## [3.0.6] - 2026-08-13

### Fixed

* **Massive false-positive flood from site-management "pre-update snapshot" backups.** Tools that snapshot an extension's entire source tree into `tmp/` before updating it (e.g. `tmp/joomtower_snapshots/<label>/files/...`) were having every single vendor PHP file inside individually flagged as "executable file inside an upload directory" -- thousands of ordinary, unmodified plugin/component files on a real site, none of them actually suspicious. Now recognized narrowly: a snapshot path is only exempted from that specific structural check when it names a plugin or component that is CURRENTLY actually installed (checked against the live `#__extensions` registry), so a fake snapshot folder imitating this naming convention for something that isn't really installed gets no exemption. Content-signature scanning is completely unaffected either way -- a real backdoor planted inside a snapshot folder is still caught the same as anywhere else.

## [3.0.5] - 2026-08-13

### Fixed

* **Version badge and "Check for updates" link readability.** The link previously sat on its own row in light gray text, hard to read and visually disconnected from the version pill above it. Merged into a single clickable pill (`v3.0.5 | Check for updates`), one row instead of two.
* **"Built for SP Page Builder & Helix Sites" hero callout was low-contrast, floating text.** Boxed it with a visible background and border and darkened the text so it reads clearly against the hero's gradient background.

## [3.0.4] - 2026-08-13

### Added

* **"Check for updates" link next to the version badge.** New releases have always been delivered through Joomla's own Extensions update system rather than a separate download, but nothing on the dashboard said so. A small link now sits right under the version badge, pointing straight at System > Manage > Update.

## [3.0.3] - 2026-08-13

### Fixed

* **The version badge and "Get security alerts" newsletter banner showed up on the Settings and Support panels too, not just the dashboard.** Both live outside the dashboard's own content area (so they're visible before a first scan has ever run), which meant opening Settings/Support -- which only ever hid the dashboard content itself -- never hid them either. Now hidden/restored together with the panel switch.

## [3.0.2] - 2026-08-13

### Fixed

* **Site Protection settings could be toggled and saved even when the MuRu Guard Shield plugin isn't installed or enabled**, silently doing nothing while looking fully configured. Every toggle in that form is now disabled in the UI when the plugin isn't active, and the save itself is refused server-side too (not just a UI courtesy -- a direct POST couldn't bypass it either).

## [3.0.1] - 2026-08-12

### Fixed

* **"Run a Scan" threw `closeScanModal is not defined` in the browser console and never started a scan.** The new chunked-scan JS (`muruRunChunkedScan()`) was declared in the page's outer script scope while `closeScanModal()` is scoped inside an IIFE elsewhere on the page -- calling it from outside that IIFE fails regardless of call order, since JS closures resolve by where a function is *defined*, not by where it's called from. Moved the chunked-scan functions inside the same IIFE so they share scope with it.

## [3.0.0] - 2026-08-12

### Added

* **Chunked, resumable scanning.** A "Run a Scan" click no longer runs the entire filesystem+database scan inside one blocking HTTP request. Instead, the scan is broken into small pieces (one directory area, the webroot/core-entry checks, or the database scan at a time), each bounded to a fixed wall-clock budget server-side, driven by a progress-bar loop in the browser. No single request can ever run long enough to hit a host's execution-time limit, regardless of how large the site is -- this is the direct fix for scans that could previously come back as a bare "500 - Whoops" on a large filesystem with no results at all. Progress is persisted to disk between calls, so it survives even if a single very large folder takes several chunk calls to get through. If a folder is so large that even its own chunk call runs out of budget partway through, that area is reported as scanned-up-to-the-time-budget rather than silently passing as complete. Falls back to the previous one-request behaviour automatically if JavaScript/fetch isn't available.

## [2.8.9] - 2026-08-12

### Fixed

* **Scanning could crash with a generic "500 - Whoops" error on hosts that disable `set_time_limit()`** (common on shared hosting specifically to stop scripts overriding execution time). The scan controller's own attempt to raise its execution-time limit called `set_time_limit()` unconditionally, `@`-suppressed on the assumption that would silence any failure -- but calling a function listed in `disable_functions` is an uncaught fatal `Error` ("Call to undefined function"), not a warning, and `@` does nothing to stop that. Now guarded with `function_exists()` first.
* **The version badge and the new "Get security alerts & updates" banner only appeared after running at least one scan** -- both lived inside the post-scan results view, so a site that hadn't scanned yet saw neither. Moved both to a persistent header shown regardless of scan state.

### Added

* **Server-limits advisory on the pre-scan screen.** If the host won't let the scan raise its execution-time or memory limit (the same condition that caused the crash above), a warning now shows *before* running a scan -- current values, which one(s) are locked, and a `.user.ini` snippet to fix it -- instead of only finding out after the scan fails partway through.

## [2.8.8] - 2026-08-12

### Added

* **Optional "Get security alerts & updates" banner on the dashboard.** Dismissible, asks only for name (optional) and email, and never shows again once dismissed or subscribed. Submits to the same subscriber list the main Lyzerslab site's own newsletter form uses (tagged with a distinct source so they're identifiable), so Free users can opt in to hear about new threats and updates without needing an account or license key -- Free has neither.

## [2.8.7] - 2026-08-12

### Changed

* **Removed the "AI Integration" and "Security Report" toolbar buttons.** Both were Pro-only links out to the marketing site with a static "PRO" badge -- not a working feature on Free, so they were just clutter. `.htaccess Hardening` (a real Free feature) stays.

### Fixed

* **Static-assets-only custom webroot folders (e.g. a template's `/fonts` folder) still showed up as a Medium-confidence finding**, requiring an individual "Mark as False Positive" click per file even though the underlying content is provably inert. Now given the same treatment as a known extension's own companion data folder: no structural flag at all, but every file inside is still fully content-scanned, so an actual payload disguised with one of these extensions is still caught.
* **AV/hosting-scanner false positives on this scanner's own `admin/helpers/muruguard.php`** (Huorong via VirusTotal, SiteGround Site Scanner -- reported on the Pro release's GitHub issue thread, but Free carried the same unsplit literals). `gsocket_indicator`, `webshell_generic`, and `phpkoru_encoder` all still contained their trigger brand names as one contiguous literal string on Free (Pro already had `gsocket_indicator`/`phpkoru_encoder` split from an earlier, unrelated cleanup). Split into concatenated fragments, same technique already used elsewhere in this file -- detection behaviour is unchanged, only the on-disk byte sequence differs. Also caught and fixed several explanatory code comments that had reintroduced the exact same literal strings while documenting the fix.

## [2.8.6] - 2026-08-12

### Added

* **Native Joomla update detection.** MuRu Guard now shows up directly in Extensions > Manage > Update, like any other Joomla extension -- no more manually checking for a new version.

### Fixed

* **"Mark as False Positive" appeared to do nothing.** The dismissal was being saved correctly, but the scan-results page reads from a 5-minute session cache on every load rather than re-scanning -- marking a finding safe never invalidated that cache, so the very next reload just showed the same stale pre-dismissal list. Same fix applied to un-marking a false positive (it now reappears immediately instead of waiting for the cache to expire).
* **dompdf's own `Helpers.php` (bundled by multiple unrelated extensions -- com_dpcalendar, ConvertForms' PDF tool, com_rsseo, and others) flagged High as `stream_wrapper_payload`.** It legitimately parses `phar://`/`file://` resource URLs as part of normal PDF asset loading. Added a narrow, per-file, per-signature exemption matched by dompdf's own stable internal path (`dompdf/dompdf/src/Helpers.php`), not a blanket "don't scan this vendor folder" skip -- every other signature still runs fully against these files.

## [2.8.5] - 2026-08-12

### Fixed

* **Multiple confirmed false positives in the malware/suspicious-file scan:**
  * `webshell_generic` matched "FilesMan" as a bare substring, so any code declaring an ordinary `$filesManager` variable (confirmed on a real Joomla GDPR component's Controller classes) was flagged High as a webshell. Now requires word boundaries, so only the standalone webshell banner token matches.
  * A top-level `.DS_Store` file (macOS Finder metadata, ubiquitous on any Mac-managed site) was flagged High as an "unrecognized file in the webroot."
  * A top-level custom folder made up entirely of static assets (e.g. a template's `/fonts` folder) was flagged High exactly like a malware staging directory, both the folder itself and every file inside it, purely because the reason text contained the word "unrecognized" (which auto-escalates confidence). Asset-only folders are now worded and scored as a lower-confidence "custom folder" finding instead.
  * ConvertForms' own `convertforms_<FormAlias>/` custom-code folders (a real, documented ConvertForms feature) were flagged High as an unrecognized directory. Now recognized by name **only when ConvertForms is actually installed** on the scanned site — the folder's contents still get a full content-signature scan either way, so a dropped shell can't dodge detection by copying the name on a site that doesn't have ConvertForms.
  * The image-polyglot check (`php_tag_in_image_file`) accepted the 2-3 byte `<?=` short tag as well as `<?php`, which can turn up by pure chance in the megabytes of high-entropy pixel data a large photo contains. Narrowed to require the full 5-byte `<?php`, matching Pro.
* **"Mark as False Positive" silently not working for root-level findings** (`.DS_Store`, backup config files, unrecognized root files/directories, and everything inside them). The dismissal was being recorded correctly, but the "Shallow webroot scan" pass that produces exactly these findings never checked the false-positive list before re-adding them on the next scan — every other finding category already did. Fixed; dismissed root-level findings now stay dismissed until the underlying content actually changes.

### Changed

* **"Mark as False Positive" button is now a labeled button** (✅ + "False Positive" text), not a bare emoji icon, so it reads as an obviously clickable action instead of a decorative checkmark.
* **Removed the "Pro" promo tab from Settings.** Settings now only holds Site Protection, IP Access List, Scheduled Scanning, and the Setup Guide -- the Pro upsell already has its own place under the Support panel.

## [2.8.4] - 2026-08-06

### Changed

- **IP Access List moved out of Site Protection into its own Settings tab**, with an entry-count badge. Settings → Site Protection now holds only the active-blocking feature (pattern/brute-force/country blocking, Backend Access, Emergency Mode); the manual allow/block list is general access-control configuration, not part of that.
- **Settings sub-tabs now remember which one you were on** after saving/adding/removing something in them (Site Protection, IP Access List, Scheduled Scanning, Guide) -- previously every save always bounced back to the Site Protection tab regardless of where the action came from.

### Fixed

- **Adding or removing an IP Access List entry redirected to the main Dashboard panel instead of back to Settings.**

## [2.8.3] - 2026-08-06

### Fixed

- **Backend Access's activation error now says explicitly when the Shield plugin isn't the reason.** If the self-test still fails after upgrading to 2.8.2 and `plg_muruguardshield` isn't installed/enabled, the error now leads with that directly ("On any server other than Apache, this plugin is what actually enforces Backend Access -- install/enable it, then try again") instead of only ever showing the generic Apache/Nginx troubleshooting text, which looked identical whether or not the 2.8.2 fix was even present yet.

## [2.8.2] - 2026-08-06

### Fixed

- **Backend Access (MuRu Shield Hardening) never actually worked on Nginx.** `.htaccess` is an Apache-only mechanism -- on Nginx (or any Apache host with `AllowOverride None` or a missing `mod_auth_basic`), the `.htaccess` block Backend Access writes was silently ignored, so activation always failed with "an unauthenticated request should have been rejected with 401 but got 200 instead," no matter how many times you tried. `plg_muruguardshield` (bump to 1.2.1) now enforces the same Basic Auth gate at the PHP layer, checked on every request regardless of web server, reading the exact same credentials the component already writes -- Backend Access now activates and works identically on Apache, Nginx, and LiteSpeed, as long as the Shield plugin is installed and enabled.

## [2.8.1] - 2026-08-06

MuRu Guard v2.8.1 Free. Brings MuRu Shield Hardening down from Pro into the free tier, alongside a couple of general scanner and UI improvements.

### Added

- **MuRu Shield Hardening, now free**: Backend Access (an HTTP Basic Auth gate in front of `/administrator`, verified with a real test request before it's ever treated as active, with automatic rollback on any failure) and Emergency Mode (extends the same protection to the whole site). Lives in Settings → Site Protection, below the existing IP Access List.
- **Settings renamed to "MuRu Settings"** throughout the admin sidebar and panel heading, to read less like a generic Joomla settings screen.
- **New "Pro" tab in Settings** — an always-visible card describing what MuRu Guard Pro adds (Smart AI Assistant, Fleet Dashboard, Instant Alerts, priority support), with a link to the Pro product page and a direct contact option. Not a locked/upgrade flow — this is the free tier, there's nothing to unlock in-app.
- **New known-malicious filename signature**: `kill.gif` / `kill.png` — a recognized attacker calling-card filename, flagged on the exact bare filename alone regardless of content.
- **Pro promo banner in Support** — a card pointing at the Pro product page and a direct contact option, matching the new Settings → Pro tab.

### Changed

- **"Protection Mode" renamed to "Site Protection"** (settings tab, section title, and status labels) — the old name didn't make it obvious this feature actively blocks attacks against the whole site, not just a passive mode toggle.
- **Re-scan toolbar restyled** to match the color-coded button treatment already used on Pro (Re-scan in indigo, .htaccess Hardening in emerald), and the disabled "AI Integration (Soon)" button is now a real link to the Pro product page with a "PRO" badge, alongside a new "Security Report" button (also Pro, badged the same way).

### Fixed

- **Backend Access activation failures now name the actual problem.** The self-test's failure message used to list three generic possibilities (Nginx, `AllowOverride None`, missing `mod_auth_basic`) with no way to tell which applied. It now reads the web server's own `Server` response header and calls it out by name when it's Nginx or LiteSpeed, and separately detects a redirect (a caching layer or security plugin intercepting the request) instead of lumping it in with the same generic message.
- **The admin submenu (Dashboard / MuRu Settings / Support) could vanish after every update, only to reappear after a full uninstall+reinstall.** Root cause: a bare `return;` used as an early-exit inside the install script's ACL-defaults step was exiting the *entire* `postflight()` method, not just that step -- and on any update (not a fresh install), the ACL rules already exist from the original install, so that early-exit branch was hit every single time, silently skipping the code that (re)creates the submenu entirely. Fixed by moving the ACL step into its own method so its early returns can only ever exit themselves. Also hardened the submenu-creation logic itself: it now recalculates the admin menu's internal tree structure on every run (not just when a brand-new item was created), and correctly recovers if Joomla's own installer ever leaves a duplicate top-level menu row behind on a reinstall.
- **Re-scan toolbar wrapped onto two rows** on narrower admin layouts. The action buttons now stay on one row; only the informational text (last-scanned time, cron/version badges) truncates or scrolls if space is tight.
- **Image-polyglot detection hardened**: the check for a PHP open tag hidden inside a file with an image extension now scans the entire file instead of only a head+tail window, closing a gap where a large image with PHP appended past the tail window could have slipped past undetected.

## [2.8.0] - 2026-08-04

Five issues reported against 2.7.1, four of them genuine security findings. Thank you to `@degiosa` and `@PhilETaylor` for the reports.

### Security

- **`helpers/data/*.json` was readable, unauthenticated, on any non-Apache stack.** That folder (attack log, failed-login usernames, the manual IP allow/block list, every visitor IP ever geolocated) was protected only by a shipped `.htaccess`, which nginx, Caddy/FrankenPHP, LiteSpeed running in its nginx-compatible mode, and IIS all ignore outright -- on any of those, every one of those files was a plain `GET` away with no session required. Every data file this component owns is now a `.php` file that starts with an executable stub (`http_response_code(403); exit('Forbidden');`) -- requesting it directly now executes that stub and returns a 403 on literally any server capable of running Joomla at all, which is the only protection that doesn't depend on a specific web server or its configuration being correct. The `.htaccess` stays as defence in depth on Apache, it's just no longer the only thing standing between this data and the internet. Existing installs migrate automatically: the first read/write after upgrading carries old `*.json` content into the new stub-protected `*.php` file and deletes the legacy file outright, rather than leaving an abandoned, still-readable copy sitting next to it.
- **Protection Mode was fully bypassed for any authenticated user, not just admins.** `runShieldCheck()` returned before pattern-matching, country-blocking, and logging for any non-guest session -- Joomla ships frontend user registration on by default, so an attacker could self-register, log in, and every subsequent request-pattern rule was skipped entirely, with nothing even logged. The exemption now requires `core.login.admin` -- the exact permission Joomla itself uses to decide who can log into the administrator at all -- so a self-registered low-privilege account gets full protection, identical to a guest. A genuinely admin-capable user is still never *blocked* by a pattern/country match (avoiding a real admin's own action, or their own travel/VPN IP, locking them out), but that match is now always logged regardless, so this exemption can no longer become a silent blind spot.
- **Brute-force IP blocking had no proxy awareness**, keying purely on `REMOTE_ADDR`. Behind Cloudflare, a load balancer, or NAT, every visitor can share one edge IP -- a handful of failed logins from any one of them crossed the threshold and returned a plain 403 to the entire site for everyone behind that IP. Added an opt-in (off by default) "Trusted proxy header" setting in Settings → Protection, letting an admin who has verified their site is genuinely always behind a specific proxy select which header (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`) carries the real visitor IP. Left on "None", behaviour is unchanged from before. The header value is only ever trusted when explicitly configured -- never by default, since blindly trusting a client-supplied header would let any visitor spoof their own IP.
- **The Protection Log's 500-entry ring buffer could be flushed by the same attacker it was logging.** Evicting the oldest entry to make room for a new one meant roughly 500 cheap follow-up requests could age a real intrusion's log entries out of the only copy that ever existed -- erasing the evidence the log exists to preserve. Entries evicted from the live 500-entry view are now appended to a separate, equally stub-protected archive file (capped at 20,000) instead of being discarded, raising the cost of "erase the evidence" by 40x. The Protection Log now shows a note when older entries exist in the archive.

### Fixed

- **`components/com_jce/editor/libraries/views/plugin/index.php` (JCE's own core file) was flagged High confidence as a disguised webshell.** Confirmed against several real, current JCE installs: this file is JCE's own legitimate HTML wrapper layout for its editor plugin dialog windows, using JCE's `defined('JPATH_PLATFORM') or die` access-guard convention rather than Joomla's own blank `_JEXEC` stub -- structurally indistinguishable from an actual disguised webshell to the "non-standard index.php" heuristic, which had no exemption for it. Added a precise, path-exact exemption from this one structural check only; the ordinary content-signature scan still runs on this file regardless, so an actual backdoor dropped at this exact path is still caught.

### Investigated

- **A downloaded release zip was flagged by Microsoft Defender as `Backdoor:JS/Chopper.GG!dha`.** This scanner's own JavaScript (the admin template's inline `<script>` blocks) contains no `eval`, `Function()`, `document.write`, or obfuscation of any kind -- reviewed line by line, nothing resembling that signature is actually present. The far more likely explanation is the same false-positive class already seen on this project (see the 2.4.5 entry above, and a similar report against a third-party scanner): the component's own malware-detection signature database necessarily contains the literal text of the patterns it detects (`eval(base64_decode`, `gsocket`, `FilesMan`, `c99shell`, ...) inside PHP string literals, repeated again in prose in the README and CHANGELOG -- exactly the kind of keyword density a cloud heuristic classifier can misjudge. This isn't something a code change on our end can reliably fix (the classification happens entirely on Microsoft's end); if you hit this, the effective path is Microsoft's own file-submission/false-positive review at https://www.microsoft.com/en-us/wdsi/filesubmission.

## [2.7.2] - 2026-08-03

### Added

- **Detects a `.profile` file dropped directly in the Joomla webroot.** `.profile` is a Unix shell-startup dotfile with no legitimate reason to exist there -- Joomla never creates one, and a real account `.profile` lives in the hosting account's home directory, not the public webroot -- making it an easy way to hide a backdoor behind a filename that looks like routine account configuration rather than site content. Flagged on presence alone, regardless of content. Also fixed the same underlying gap `.htaccess` had: `.profile`'s (and `.htaccess`'s) actual content is now scanned against the normal content signatures too, instead of being silently skipped -- both were falling through `scanFileContent()`'s text-file check because PHP's `pathinfo()` treats everything after a leading dot in a bare dotfile name as its "extension" ("profile"/"htaccess"), neither of which was in the scanned-extensions list.
- **New known-malicious filename signatures**: `filefuns.php`, `elp.php`, and `*.php.json` (including stacked `*.php.json.json`) -- the latter confirmed against real backdoor samples using a double-extension trick to slip past filters that only block `.php`. These filename checks (along with the existing ones) now also run across `components/`, `modules/`, `plugins/`, `libraries/`, and `templates/`, not just upload folders -- malware doesn't respect that distinction.
- **Detects a `.htaccess` rewriting a non-PHP extension to execute as PHP** (e.g. `<FilesMatch "\.json$"> SetHandler application/x-httpd-php </FilesMatch>`), confirmed against a real backdoor sample -- the technique that makes the `*.php.json` trick above actually work. Carefully scoped to not flag the ordinary, common `<FilesMatch "\.php$"> ... SetHandler application/x-httpd-php` directive.
- **New webshell signature**: `"H3K | Tiny File Manager"` banner -- a full filesystem-access file-manager backdoor.
- **"High threat only" quick-select** button next to "Select all" in Suspicious Files & Folders, to select every High-confidence row in one click without hand-picking through a long list.

## [2.7.1] - 2026-07-30

### Fixed

- Version badge styling: fixed a missing space between two Tailwind classes (`bg-[#EF89EB]text-gray-200`) that merged them into one invalid class, silently dropping both the background and text color.

## [2.7.0] - 2026-07-30

### Added

- **"Mark as Safe" on every finding row** (Suspicious Files, Cleanable Files, Super Users, Menu XSS, SPPB Assets, Rogue Iconfont, Template Defacement) -- dismisses a specific finding as a false positive so it's no longer flagged on future scans. Deliberately NOT a simple path/row-id suppression: every dismissal is fingerprinted against the exact reasons text reviewed at the time (`MuruguardHelper::fingerprintReasons()`), so if the same file/row later matches something DIFFERENT (e.g. an attacker overwrites a previously-dismissed path with a real backdoor), the fingerprint no longer matches and it reappears as a fresh finding rather than staying silently hidden forever -- verified with an explicit test simulating exactly that scenario. New "False Positives" management section in Settings lists every current dismissal with a one-click restore. Same edit-level permission as Clean.

### Security

- **`administrator/components/com_muruguard/helpers/data/` (attack log, IP allow/block list, login attempts, GeoIP cache, and now the false-positives list) had no protection against direct HTTP access to a known filename** -- the folder's `index.html` only ever blocked directory *listing*, not a direct request for e.g. `.../data/attack-log.json`. Added `.htaccess` denying all direct access to this folder outright (both modern and legacy Apache syntax), found and fixed while reviewing where the new false-positives data would live.

### Fixed

- **False positive: the MuRu Guard Shield plugin's own folder flagged as a fake/malicious plugin when its files are present but not yet installed through Joomla** (e.g. uploaded via FTP but Install was never clicked in Extensions > Manage). Added a specific, accurate, non-alarming message explaining exactly what this is and how to resolve it (install the plugin), replacing the generic "no matching #__extensions row" wording -- still shown, not silently hidden, so the admin is prompted to actually finish activating real-time protection.

## [2.6.3] - 2026-07-30

### Fixed

- **The 2.6.2 admin submenu was missing an explicit "Dashboard"/"Overview" item** -- confirmed working (arrow icon, expandable, Settings + Support both present) via the site's own rendered HTML, but Dashboard was deliberately left out on the assumption that clicking the parent "MuRu Guard" item itself was enough; that's not what's actually expected here. Added as a third child, positioned first. Idempotency is now checked PER ITEM (by exact link) rather than "does the parent already have any children at all" -- sites that already got Settings/Support from 2.6.2 will only have the new Dashboard item added on their next update, not duplicate rows for the two that already exist.

## [2.6.2] - 2026-07-30

### Fixed

- **The 2.6.0 sidebar submenu didn't actually appear as an expandable dropdown under "MuRu Guard" in the primary left admin menu tree** (confirmed via the site's own rendered HTML: `class="no-dropdown"`, no child items). `HTMLHelper::_('sidebar.addEntry', ...)` populates a different, separate in-page panel -- it was never going to produce the arrow-icon/expandable-children behavior seen on components like SP Page Builder. That requires actual child rows in Joomla's admin menu table (`#__menu`) sharing the same `parent_id` as the component's own auto-created menu item. Added this properly via the install script (`script.php`), using Joomla's own nested-set-safe `Table\Menu` API (`setLocation()` + `rebuild()`) rather than raw SQL, since `#__menu`'s lft/rgt columns are shared by every admin menu item on the whole site -- a wrong raw INSERT could corrupt the entire admin sidebar, not just this component's part of it. Adds "Settings" and "Support" as children (no separate "Dashboard" child needed -- the parent item's own link already goes straight there). Idempotent: only runs once, never touches an already-populated submenu, so it's safe on repeated updates. This only takes effect on an actual install/update through Joomla's installer, same as the ACL default from 2.6.0.
- Moved the version badge out of the floating top-right corner into the existing scan-results toolbar (next to "Last scanned" / cron status), instead of a separate floating element.

## [2.6.1] - 2026-07-30

### Changed

- Settings and Support are now reached ONLY through the new left-sidebar submenu (under the MuRu Guard menu item) added in 2.6.0, not duplicated as floating buttons in the top-right corner. The top-right area now shows just the version badge.

## [2.6.0] - 2026-07-30

### Security

- **This scanner's own files were completely invisible to itself.** `SAFE_COMPONENT_PATHS` blanket-skipped ALL scanning (not just content signatures -- every structural check too) for `administrator/components/com_muruguard/` and its pre-rebrand name `com_sppbscan/`, meaning a real backdoor injected into the scanner's own code would never have been detected. Replaced with `SELF_CONTENT_SIGNATURE_EXEMPTIONS`, a narrow, per-file, per-signature allow-list covering ONLY the specific, empirically-verified content-signature matches that come from `helpers/muruguard.php` and `models/scanner.php` legitimately containing their own signature definitions and marker strings as source text (e.g. the literal text `"xss.report"`, `"FilesMan"`, `"gsocket"`). Every other content signature and every structural check now runs normally against this scanner's own files, including these same two files. Verified with a real backdoor injection test: `eval(base64_decode($_POST['cmd']))` appended to the scanner's own helper file is correctly caught, while the genuine, unmodified files stay clean.

### Added

- **Left-sidebar submenu** (Dashboard / Settings / Support), the same navigation pattern used by SP Page Builder and other multi-page components, instead of everything living behind floating header buttons only.
- **Component version badge** in the top-right header, read live from the installed manifest.
- **"Support This Project" page** with real funding details (Payoneer, PayPal Zoom/bKash) plus direct contact links, reached from the new Support submenu entry.
- **Restricted to Super Users by default.** A fresh install now denies `core.admin`/`core.manage`/`core.delete`/`core.edit` for the standard Manager and Administrator groups via a new install script (`script.php`), leaving only Super Users able to see or use the component out of the box -- they always bypass ACL entirely regardless of configuration. Only applied when the component's ACL is still completely untouched, so upgrading never silently overwrites a site owner's own already-customised permissions; access can always be granted back to any group afterwards via System > Users > Access Levels/Permissions.

## [2.5.5] - 2026-07-30

### Fixed

- **False positive: an `#__sppagebuilder_assets` row named "icomoon" flagged "Non-default iconfont" and listed as a rogue/deletable registration.** The docblock already documented "icofont, icomoon, ..." as known-legitimate iconfont names, but the actual comparison only ever checked against the single name `icofont` -- `icomoon` (IcoMoon's own extremely common icon-font export tool name, already allow-listed on the filesystem side) was never actually in the list it was compared against. Added a proper `KNOWN_GOOD_ICONFONT_NAMES` list covering both; a genuinely unrecognized name is still surfaced for review as before, and the underlying content checks (base64_decode/eval/script tags/PHP tags/event handlers) still run against every row regardless of name either way.

## [2.5.4] - 2026-07-30

### Fixed

- **False positive: `modules/index.html` and `templates/index.html` (Joomla's own "prevent directory listing" blank stubs sitting directly at the group root) flagged as fake module/template folders.** Same class of bug already fixed for `plugins/<group>/index.html` -- a bare file directly at the modules/ or templates/ root was being read as if its filename were itself a module/template name. Fixed for both.
- **False positive: `media/.../iconfont/icomoon` flagged "Unrecognized folder inside icon-font asset directory".** "icomoon" is IcoMoon's own icon-font export/build tool name -- a legitimate, common vendor subfolder (SP Page Builder's bundled icon picker uses it), not a red flag. Added to the allow-list.
- **Real gap found while fixing the above: files nested two or more levels inside an `iconfont/` tree (e.g. `iconfont/icomoon/whatever.ext`) were never checked against the icon-font file-type allow-list at all** -- only files directly at the immediate `iconfont/` level were. A non-executable-but-unexpected file type (anything other than the standard font/css/json/doc extensions) hidden inside an allowed subfolder like `icomoon/` would previously slide through undetected by this check. Now checked at any depth, closing the gap the "icomoon" fix above would otherwise have introduced -- allow-listing a folder name is no longer a free pass for what's placed inside it.
- **False positive: `libraries/vendor/symfony/http-client-contracts/Test/Fixtures/web/index.php` (a legitimate Symfony package's own test-fixture HTTP server script) flagged "Non-standard index.php".** `libraries/vendor/` is Joomla's bundled Composer dependency tree -- hundreds of third-party packages that don't follow Joomla's own "blank stub" index.php convention; a package's test fixtures/dev tooling can legitimately ship a fully functional index.php. This one structural signal isn't reliable for arbitrary vendor code; the ordinary content-signature scan (which runs on every file regardless of location) still catches an actual malicious payload dropped there.

## [2.5.3] - 2026-07-30

### Fixed

- **The MuRu Guard Shield plugin flagged its own file (`plugins/system/muruguardshield/muruguardshield.php`) as a suspected webshell.** A code comment explaining why user-agent blocking has its own toggle used `eval(base64_decode())` as an illustrative example -- literal text that matches the `eval_encoded_blob` content signature. Same class of bug as the earlier `com_sppbscan` self-flagging issue, just via a comment instead of the signature table itself. Reworded the comment to avoid the literal pattern; see also the v1.1.1 Shield plugin release, which ships the corrected file.
- **Widespread false positives on legitimate Joomla core/vendor files** (`templates/system/*.html`, `media/system/html/noxml.html`, `com_finder`'s HTML parser, `libraries/vendor/php-debugbar/.../JavascriptRenderer.php`, `libraries/vendor/symfony/error-handler/.../exception_full.html.php`, Helix Ultimate's `comingsoon.php` layouts) **flagged as "obfuscated script injected right after `<head>` tag".** The check searched for a `<script>` tag ANYWHERE later in the file after the first `<head>`, not actually adjacent to it -- so any file with both a `<head>` tag and an unrelated large/JS-heavy `<script>` block *anywhere else* in the document (a near-universal combination in real HTML-rendering code) matched, even when nothing was actually injected. Now requires the `<script>` tag to sit immediately after `<head...>` (only whitespace in between) -- the actual shape of a real head-injection defacement, which plants its payload as the very first thing in `<head>` specifically so it runs on every page. Verified: genuine immediate-injection patterns (including with realistic whitespace/newlines before the script tag) still correctly flagged; all five reported false-positive file shapes no longer match.

## [2.5.2] - 2026-07-30

### Added

- **MuRu Guard Shield: manual IP Access List.** Admin-managed persistent list of IPs/CIDR ranges to always block or always allow, independent of pattern/brute-force/country checks. Checked first, ahead of everything else -- an allow entry bypasses every other check; a block entry rejects unconditionally. IPv4 exact-address and CIDR entries are supported (IPv6 exact-address only, no CIDR containment).
- **MuRu Guard Shield: bad user-agent blocking.** Known scanner/bot user agents (sqlmap, nikto, acunetix, ...) were previously only ever logged. A new, separately-toggleable switch lets these be actively rejected, kept distinct from the general pattern-block switch since a User-Agent string alone is more prone to spoofing/false positives than an actual attack payload.
- **MuRu Guard Shield: country blocking.** Rejects requests from a configured list of countries, resolved via a free IP-to-country lookup (ip-api.com) cached indefinitely per IP -- a one-time network call per unique visitor IP ever seen, not a per-request dependency, and fails open (never blocks) if the lookup service is unreachable. Never applied to your own logged-in admin session, or to private/reserved IP ranges (localhost, LAN, ...). No GeoIP database is bundled -- deliberately avoids MaxMind licensing/staleness questions in favor of an on-demand, cached lookup.

### Fixed

- Adding the ".htaccess Hardening" advisory as a 7th results tab pushed the tab bar to a second line. Moved it out of the tab bar entirely into its own modal, opened from a new "🛡 .htaccess Hardening" button in the toolbar (next to Change Scan Areas / Re-scan Now / AI Integration). Back to 6 tabs on one line. (Re-released as its own version number rather than an in-place update to 2.5.1, to avoid any ambiguity from a cached/stale download of a previously-issued version.)

## [2.5.1] - 2026-07-30

### Added

- **New ".htaccess Hardening" tab** — a read-only advisory that reads the site's actual root `.htaccess` and checks it against a fixed set of recommended directives: blocking PHP execution inside writable upload-style directories (media/images/uploads/tmp/cache — the single most directly relevant check, since a dropped webshell still runs the moment it's requested unless the server refuses to execute PHP there), disabling directory listing, blocking direct access to sensitive files (.env, .git, composer.json/lock, .sql/.bak), plus advisory security headers (X-Content-Type-Options, Permissions-Policy, HSTS -- only shown once the site is actually on HTTPS, Content-Security-Policy with an explicit caution about testing before enabling). Each missing check shows a copy-ready suggested rule. This tool never writes to `.htaccess` itself — a wrong edit to this specific file can take the whole site down with no way to test a rewrite rule server-side before it's live, so it only reports and suggests.

## [2.5.0] - 2026-07-30

### Fixed

- **Selecting a large batch (e.g. "Select all" on ~1800 flagged files) and clicking Delete/Clean failed with "The most recent request was denied because it had an invalid security token", alongside a PHP warning about `max_input_vars` being exceeded.** Every bulk delete/clean form (Suspicious Files, Cleanable Files, Menu XSS, SPPB Assets, Template Defacement) submitted one POST field per selected checkbox — at scale this blew past PHP's default `max_input_vars` (1000) before Joomla ever saw the request, silently truncating the POST body, which could drop the CSRF token field along with it. The confusing "invalid token" message had nothing to do with the token actually being wrong.
- On submit, every checked box's value is now consolidated client-side into a single JSON-encoded hidden field, and the checkboxes' own `name` attributes are stripped so they never also submit individually — capping each request at a small, constant number of fields regardless of how many rows are selected (verified with a simulated 1800-target request: 1 POST field instead of 1800). The controller reads this consolidated field first and falls back to the original one-field-per-row array when it's absent (JS-disabled browsers, cached old page loads), so nothing regresses for smaller selections.

## [2.4.13] - 2026-07-29

### Fixed

- **A confirmed, live webshell (`libraries/init/init.php`, dropped via the "PHPkoru" obfuscation service and confirmed malicious) sat in the Cleanable Files tab reporting "SKIPPED (no auto-cleanable pattern recognized)" on Clean, instead of Suspicious Files where Delete works.** Root cause, more general than this one file: `libraries/` has no `#__extensions`-style registry to structurally cross-reference the way templates/modules/plugins/components now do, so a file there with no OTHER structural red flag fell entirely on content-signature matching -- and `isContentOnlyCodeAreaFinding()` downgraded ANY content-signature-only finding in a code area to "Cleanable, review manually", regardless of whether the matched signature was `medium` (genuinely ambiguous, e.g. a commercial extension self-obfuscating for license protection) or `high` (this codebase's own existing severity tagging already calls that "unambiguous enough... to mark the whole file High confidence"). A `high`-severity content match now always routes to Suspicious Files/Delete, even with zero location-based corroboration — only genuinely ambiguous `medium` matches still get the cautious Cleanable/manual-review treatment. This is a general fix, not specific to one file or folder: it applies wherever a code-area file (components, modules, plugins, libraries, templates) is flagged purely by content.
- Added a dedicated, zero-false-positive-risk content signature for the "PHPkoru" obfuscation/encoding service specifically (`[PHPkoru_Code]` marker, `phpkoru.com` branding) — no legitimate Joomla file is ever processed through this tool, so this alone is now a `high`-severity match.

## [2.4.12] - 2026-07-29

### Fixed

- **False positive: Joomla/Helix Ultimate's own disk-cache files (`cache/helixultimate/<hash>-cache-helixultimate-<hash>.php`) flagged as "Executable file inside an upload directory".** This is Joomla core's standard cache-storage file naming convention (`<md5>-cache-<group>-<md5>.php`), used by core page caching and template frameworks like Helix Ultimate alike — not a compromise. `cache/` now recognizes this exact shape and exempts it from the structural upload-directory check; content scanning still runs on it regardless, so a real backdoor merely named to mimic the pattern is still caught.
- **False positive: `administrator/components/com_akeebabackup/backup/index.php` (Akeeba Backup's own non-blank protection stub) flagged "Non-standard index.php".** `com_akeeba` (Akeeba's legacy Joomla 3 component id) was already a trusted `SAFE_COMPONENT_PATHS` entry; `com_akeebabackup` (the current Joomla 4/5 id, same vendor) was simply missing from the list. Added.
- **False positive: `plugins/captcha/index.html`** (Joomla's standard "prevent directory listing" stub sitting directly in a plugin *group* folder, not inside any specific plugin) **was matched as if "index.html" were a plugin name**, and flagged since no plugin is ever registered under that name. Bare files sitting directly at the group level are no longer treated as a plugin-name lookup.
- **False positive: an entire, genuinely-installed, legitimate plugin folder (`plugins/system/xformea`, an admin-renamed copy of a real "Formea" plugin) flagged as fake.** Renaming a plugin's folder (prefixing "x", "_", etc.) to disable it without touching the database is a common, legitimate Joomla admin technique — the `#__extensions` row survives under the plugin's *original* element, which no longer matches the renamed folder. Before concluding a plugin folder is fake, its own manifest XML (if present — Joomla's installer convention names it `<element>.xml`, unaffected by a later folder rename) is now also checked against the registry, so a renamed-but-real plugin resolves correctly while a genuinely fake, unregistered folder (no matching manifest either) is still flagged exactly as before.

## [2.4.11] - 2026-07-29

### Fixed

- **False positive: real, stock Joomla plugins that ship disabled by default (`plugins/api-authentication/basic`, `plugins/authentication/ldap`, and others) were flagged as suspicious.** The 2.4.9 `#__extensions` cross-check treated "disabled" as a fake-plugin signal, copying the logic that works for templates — but unlike templates, several genuinely core Joomla plugins are shipped disabled out of the box, so this flagged completely unmodified installs. The disabled-row check is removed for plugins; only a completely *missing* `#__extensions` row (never installed at all) is still flagged, which has no legitimate-install false-positive case.
- **Fake `components/com_xxx` folders (confirmed malicious, matching the exact 2.4.9 `eval_encoded_blob` compromise) were landing in the Cleanable Files tab labeled "needs manual review" instead of Suspicious Files, where Delete actually works.** Root cause: components were the one extension type with no structural (location-based) check at all — the 2.4.9 changelog flagged this as a known open gap, since that attack's fake component `#__extensions` rows were left `enabled = 1`, unlike its disabled fake template/plugin rows. Added `getRegisteredComponents()`, cross-referencing `manifest_cache` instead of `enabled` — Joomla's installer always populates this JSON blob from the extension's manifest at install time; a directly-inserted fake row has no reason to also forge it. A `components/com_xxx` folder with a missing `#__extensions` row, or a row with no populated `manifest_cache`, now gets the same structural finding templates/modules/plugins already get, which correctly routes it to Suspicious Files instead of Cleanable.

## [2.4.10] - 2026-07-29

### Fixed

- **The 2.4.8 changelog claimed a fix ("index.php delete-safeguard") that was never actually committed.** Confirmed fake template-root `index.php` files (real template name + random suffix, or `tmpl_xxxxxx`) were still landing in the Cleanable Files tab instead of Suspicious Files, where Clean correctly reported "SKIPPED (no auto-cleanable pattern recognized)" for every one of them, since there genuinely is no auto-repair pattern for a dropped file — only deletion applies. `default.php`'s tab-routing logic now treats `isProtectedEntryPath()`'s determination for a template-root `index.php` as authoritative, routing confirmed-fake ones to Suspicious Files (where Delete works) instead of Cleanable.
- **The view layer's Suspicious/Cleanable tab routing wasn't using the `#__extensions` registry check at all** — only `scanFilesystem()`, `scanDatabase()`, and `deleteTargets()` were (since 2.4.8/2.4.9). `getRegisteredTemplates()` is now exposed to the view (`view.html.php`), and both `isProtectedEntryPath()` call sites in `default.php` now pass it through, so the strongest available signal is used consistently everywhere a file gets classified, not just at delete-time.
- **`cleanTemplateDefacement()` (the Template Defacement tab's Clean action) didn't check the `#__extensions` registry**, while `scanDatabase()`'s *reporting* of the same rows already did (since 2.4.8) — a `#__template_styles` row flagged *only* because its registry record is missing/disabled (manifest present, non-junk name) would show up as a finding but then always get skipped as "review manually" when the user tried to clean it. Both now use the same registry-aware logic.

## [2.4.9] - 2026-07-27

### Fixed

- **A confirmed real compromise (32 files, found by a competing scanner after this one reported nothing) went completely undetected.** Every file used the exact same shape: a commercial PHP obfuscation tool wrapping a fully-encoded backdoor in `eval(base64_decode('...'))`, decoding its own embedded string rather than reading `$_POST`/`$_GET` directly. The only existing signature for `eval()` + `base64_decode()` required a superglobal read in the same call (`eval_base64_post`), so this exact "encrypted, self-decoding" pattern -- arguably the most common real-world PHP malware shape there is -- had no matching signature at all. Added a new, broader content signature (`eval_encoded_blob`, medium severity, since a handful of legitimate commercial extensions self-obfuscate the same way purely for license protection) that catches `eval()` wrapping `base64_decode`/`str_rot13`/`gzuncompress`/`gzdecode`/`convert_uudecode` in any combination, regardless of what's being decoded. Verified against all 32 real files from this compromise (100% match) and against Joomla core/vendor/stock-extension code (zero false positives).
- **Dropped fake `modules/<name>` and `plugins/<group>/<name>` folders (holding the same backdoor) would have been routed to "Cleanable Files" instead of "Delete"**, the same class of bug fixed for templates in 2.4.4-2.4.8 -- a finding whose only reason is a content-signature match inside a code-area path is treated as "real file with injected code, don't delete outright". Added the same location-based structural check used for templates, adapted per extension type: a `modules/` folder not named with Joomla's required `mod_` prefix is disqualified on naming alone (no legitimate module is ever named otherwise); a `plugins/<group>/<name>` folder is cross-referenced against `#__extensions` the same way templates are. `components/` is deliberately NOT covered by an equivalent check yet -- the same attack also faked `components/com_feed`, `com_stat`, `com_base`, `com_track`, `com_util` with matching `#__extensions` rows, but left those `enabled = 1` (unlike the disabled fake template/plugin rows), so the "registered but disabled" signal that works elsewhere doesn't discriminate for components. Those files are still caught by the content-signature fix above; only the Delete-tab routing for them remains an open gap.

## [2.4.8] - 2026-07-24

### Fixed

- **The fake-template detection added in 2.4.2 could itself be defeated.** On a live, escalating attack, every on-disk signal it relied on -- the template folder, a `templateDetails.xml` manifest inside it, even the folder name itself (real template names plus a random suffix, e.g. `beez3_rkgf`, `cassiopeia_tmzd`, instead of the more obviously-fake `tmpl_xxxxxx`) -- had all been faked at once, so nothing was flagged (`template_defacement` correctly showed 0 when it should not have). Added a check against Joomla's own `#__extensions` table -- the actual source of truth for "is this template really installed" -- comparing each `#__template_styles` row and each `templates/<name>` folder against a matching, *enabled* extension record. The attacker was able to fake matching `#__extensions` rows too, but left every one of them `enabled = 0`, unlike the site's real templates -- so this is checked as the primary signal, ahead of (not instead of) the on-disk checks, since it's the one layer that couldn't also be silently spoofed. Verified against the real data this was found on: 264 of 269 fake template folders and 264 of 267 fake `#__template_styles` rows now correctly flagged, with the 5 genuinely legitimate templates (including one disabled-by-necessity core fallback) correctly left alone.
- **Files inside a fake template folder were showing up in "Cleanable Files" instead of "Delete".** Root cause: the folder-naming check that decides Clean-vs-Delete routing used the same narrow `tmpl_xxxxxx` pattern above, so a `beez3_rkgf`-style fake folder produced no location-based reason at all -- only a content-signature match, which routes to "review/clean" by design (that's correct for a real file with injected code, wrong for an entirely fake file with nothing legitimate to preserve). Now that the extension-registry check fires for these folders regardless of naming, affected files correctly land in Delete. Also fixed the same underlying assumption in the delete safeguard that protects a template's own root `index.php` from deletion -- it now checks the same registry instead of trusting that file's own folder's (fakeable) manifest, so a fake template's `index.php` is deletable like any other dropped file, while a real template's stays protected.


## [2.4.7] - 2026-07-24

### Fixed

- **The `#__template_styles` DB scan missed the exact same "existing template name + random suffix" attack pattern that 2.4.5 fixed on the filesystem side** (rows like `system_jizu`, `core_cokx`, `bootstrap_base_ychp`, `beez3_nfbj`, each titled `"<name> - 默认"` with empty `params`). The DB-side check only verified the referenced template folder existed on disk (`is_dir()`) — but a real mass-injection attack creates both the fake DB row *and* a matching folder together, so `is_dir()` alone never caught these. It now checks for a `templateDetails.xml` manifest instead, the same fix already applied to the filesystem scan: no manifest means Joomla never actually installed it as a real template, whether or not a folder happens to exist. The "Clean" action for this tab (added in 2.4.4) now recognizes these rows as deletable too, instead of skipping them for manual review.

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

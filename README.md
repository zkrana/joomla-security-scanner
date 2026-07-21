# 🛡️ MuRu Guard Security Scanner (Joomla Extension)

![Downloads](https://img.shields.io/github/downloads/zkrana/joomla-security-scanner/total)

A Joomla extension that detects and helps remove malware left behind by the **SP Page Builder `uploadCustomIcon` unauthenticated RCE vulnerability** (versions prior to 6.6.2). It also checks the **JCE editor component (`com_jce`)**, which has been reported as a secondary infection vector on sites compromised through SPPB.

Installs like any other Joomla extension. Runs inside the Joomla administrator, behind Joomla's own authentication and ACL — no separate access key, no public-facing scanner file, nothing to remember to delete afterward.

Need Help? <a href="https://www.linkedin.com/in/zkranadevs/">Reach Me</a> or Email me at <a href="mailto:zkranao@gmail.com">zkranao@gmail.com</a>

---

## 🚧 Temporary: GitHub Releases are currently down

GitHub is having a platform-side GitHub Actions outage — workflow runs stuck in "Queued" indefinitely or failing at startup before any job even runs. This isn't specific to this repo's code or workflow config (already checked billing, permissions, and runner config, and reported it to GitHub Support); it's blocking the automated pipeline from publishing new release zips to the [Releases](../../releases) page.

**Until GitHub resolves it, grab the latest installable zips directly from the [`dist/`](dist) folder in this repo instead** — they're built the exact same way the release pipeline normally would, just committed here as a stand-in. This now includes **two** zips (see below): the scanner component itself, and its new companion real-time protection plugin. This notice comes down once Releases are working again.

---

## ⚠️ Critical security notice

In June 2026, a critical unauthenticated RCE was disclosed in SP Page Builder versions below 6.6.2. The flaw allowed attackers to upload PHP webshells without any login, read `configuration.php`, create rogue Super User accounts, and inject Stored XSS payloads into Helix Ultimate mega-menu items — often within minutes of finding a vulnerable site.

**Before doing anything else:**

1. **Update SP Page Builder to 6.6.2 or later.** Scanning a site that's still vulnerable just means cleaning up the same infection again tomorrow.
2. **Update or remove JCE** if installed. Several hosts have reported malware appearing inside `com_jce` on sites also hit by the SPPB exploit — most likely the same attacker reusing JCE's file-browser upload path as a fallback once they had a foothold.
3. **Take a full backup** and, if possible, run your first scan on a staging copy of the site rather than production.

---

## ✨ What it does

| Category | Detail |
|---|---|
| 🛡️ **Protection Mode (new)** | A companion plugin checks **every request to the site in real time** — not just when you open the scanner — for webshell interaction, the SPPB `uploadCustomIcon` RCE, known malware-drop filenames, path-traversal probes, and brute-force login attempts, with independent opt-in switches to actually block high-confidence matches and brute-force IPs. Everything detected shows up in a sectioned **Protection Log** (IP, time, rule, severity, blocked/logged-only). See [🛡️ Protection Mode](#-protection-mode-real-time-attack-blocking) below |
| 🗂 Filesystem scan | Walks `media/`, `images/`, `templates/`, `tmp/`, `cache/`, the SPPB and JCE component directories, core Joomla entry points, and the webroot itself |
| 🧬 Content signatures | Flags known webshell patterns (`eval(base64_decode(...))`, `assert($_POST...)`, `gsocket`, generic shells like c99/r57/WSO), stream-wrapper payload loading (`zip://`, `phar://`, `compress.zlib://`), `chr()`-from-byte-array decoding, string-lookup obfuscation, self-replicating dropper logic, and `<head>`-tag script injection |
| 🚪 Core entry-point integrity | Checks `index.php`, `administrator/index.php`, `api/index.php`, and `includes/app.php` for any code executing *before* Joomla's `_JEXEC` bootstrap — the exact pattern used by real-world "prepended payload" infections |
| 📛 Filename patterns | Matches known malicious naming conventions from real SPPB compromises (e.g. `codex-sppb-*.php`), plus backup/duplicate `configuration.php` files (`configuration.bak.php`, etc.) that leak the same credentials as the live config |
| 🔢 Numeric drop folders | Flags randomly-named numeric folders in `templates/`, `media/`, or `images/` — a common automated-drop pattern — while correctly ignoring legitimate date-based upload folders (`images/2026/06/17/`) |
| 🎭 Fake `index.php` detection | Joomla's standard `index.php` stub is a one-line "no direct access" guard; anything beyond that is flagged as a likely disguised webshell |
| 🌐 Webroot hygiene | Any unrecognized top-level folder or loose file sitting directly next to `configuration.php` is flagged — with a built-in exclusion for Google Search Console site-verification files (`google*.html`) |
| 🎯 Confidence scoring | Every finding is labeled **High** or **Medium** so you can triage quickly instead of guessing |
| 🧩 JCE coverage | Same heuristics applied to `media/com_jce`, `administrator/components/com_jce`, `components/com_jce`, and `plugins/editors/jce`, with allow-lists tuned to avoid flagging JCE's own legitimate core/MVC files |
| 👤 Rogue Super Users | Flags accounts with attacker-pattern usernames (`webmanager83`, `codex*`) or `@secure.local` email domains |
| 🗄 Database scan | Checks `#__menu` for Helix Ultimate mega-menu XSS injections (broad signature set, not just one known payload string), `#__sppagebuilder_assets` for injected `eval`/`base64_decode` content and rogue iconfont registrations, and `#__template_styles` for defacement messages |
| 🧹 Guided cleanup | Built-in delete action for files/folders (scoped only to items flagged in the current scan run), a **surgical params cleaner** for injected menu items (see below), and a delete action for rogue asset rows |

---

## 📦 Installation

This ships as **two** standard Joomla extension packages — no manual file uploads, no key generation, no separate URL to protect:

- **`com_muruguard`** — the scanner component itself. Required.
- **`plg_muruguardshield`** — the companion real-time Protection Mode plugin. Optional, but install it too if you want live attack/brute-force blocking, not just on-demand scanning — see [🛡️ Protection Mode](#-protection-mode-real-time-attack-blocking) below.

### 1. Download the packages

> ⚠️ **Releases are currently down** (see the notice at the top of this page) — grab **both** `com_muruguard-X.X.X.zip` and `plg_muruguardshield-X.X.X.zip` from the [`dist/`](dist) folder in this repo instead of the Releases page, until that's fixed.

### 2. Install via the Joomla administrator

1. Log into your Joomla administrator as a Super User.
2. Go to **System → Import → Extensions** (or **System → Manage → Install** on older Joomla versions).
3. Upload `com_muruguard-X.X.X.zip` first, then `plg_muruguardshield-X.X.X.zip` (or point Joomla at either one via **Install from Folder / URL**).
4. Once installed, the scanner appears under **Components → MuRu Guard** in the admin sidebar.
5. If you installed the plugin, enable it under **System → Manage → Plugins**, search "MuRu Guard Shield", and toggle it on. It does nothing until enabled here *and* until Protection Mode is turned on from the scanner's own Settings panel — see below.

### 3. Set permissions (optional but recommended)

By default, only Super Users can access the component. If you want to delegate scanning to a trusted admin without granting full Super User rights, go to **System → Users → Access Levels / Permissions** and grant the `com_muruguard` **Manage**, **Clean**, **Delete**, or **Change Settings** permission to the relevant user group.

### 4. Run a scan

Open **Components → MuRu Guard → Scan**. Click **🔍 Run a Scan** — this opens a modal where you pick which directories and checks to include (or just leave everything selected), then click **Run** inside it. Results are shown grouped by confidence level, with checkboxes for the items you want to act on.

No API keys, no separate login screen, no public URL to lock down afterward — access control is entirely handled by Joomla's existing user/session/ACL system, and the component is only reachable by an authenticated admin session with the right permission, the same as any other Joomla component.

---

## 🧪 Detection details

### Filesystem

- PHP/phtml/phar files dropped into `media/`, `images/`, or icon-font asset folders
- Content matching `eval(base64_decode($_POST...))`, cookie-gated backdoors, `gsocket` indicators, generic webshell signatures, stream-wrapper payload loading, and `chr()`-from-byte-array obfuscation
- **Core entry-point tampering** — any executable code found before Joomla's `_JEXEC` bootstrap in `index.php` or the other core entry points is treated as a confirmed, actively-running compromise, not a low-confidence heuristic
- **Core-file checksum verification** — for `index.php`, `administrator/index.php`, `api/index.php`, `includes/app.php`, `includes/framework.php`, `robots.txt.dist`, `htaccess.txt`, and `web.config.txt`, the scanner detects your exact installed Joomla version and compares each file's SHA-256 against the bundled hash from the official `joomla/joomla-cms` release. A mismatch is unambiguous, byte-for-byte proof of tampering — independent of, and stronger than, every pattern-based check above. Currently covers the latest patch of the 4.4 LTS, 5.x, and 6.x lines; an unlisted version simply skips this check (falls back to the pattern-based checks), never a false positive.
- Numeric-named folders inside `templates/`, `media/`, or `images/` (e.g. `features/252692/`) — flagged unless they match a standard date-folder pattern
- Any `index.php` whose content is more than Joomla's one-line access guard, outside a template's own root layout file
- `.shtml` files and backup/duplicate `configuration.php` files anywhere in the webroot (Joomla never ships these by default)
- Small near-empty marker/flag `.txt` files at webroot — a common dropper-toolkit artifact
- A "cluster" note when 3+ new items appear in the same folder within a couple of minutes — a strong signal of an automated drop
- **Known-safe exclusion:** Google Search Console verification files (`google[a-f0-9]{16,}.html`) are recognized and never flagged

### Users

- Super User accounts with usernames matching known attacker patterns or email domains ending in `@secure.local`

### Database

- `#__menu` rows matching a broad set of Helix Ultimate mega-menu Stored XSS signatures — not just one known payload string, but the underlying attack primitives (inline `<script>` tags, `onerror`/`onload` handlers, `localStorage` exfiltration/injection calls, `MutationObserver`-based persistence, `<img src=x>` payloads, and known marker domains). This catches variants of the payload, not just the exact one first seen in the wild.
- `#__sppagebuilder_assets` rows containing `eval(`, `base64_decode`, or known exfiltration domains, plus rogue iconfont registrations (random name, `created_by = 0`, not the legitimate `icofont` entry)
- `#__template_styles` rows with defacement messages (e.g., "Hacked by", "Owned by") in the `params` field

---

## 🧹 Cleanup workflow

If the scan finds something:

1. **Don't panic-delete.** Review High-confidence findings first, then Medium. If unsure, copy a file elsewhere before removing it.
2. **A core entry-point finding is the top priority.** It means every page load is currently executing attacker code — treat the site as actively compromised right now, not just historically infected.
3. **Delete confirmed file/folder malware** using the checkboxes and the Delete button — only files flagged by the current scan run can be removed, and top-level Joomla folders are hard-protected regardless of what gets flagged.
   - Before cleaning, click **🧬 Code Issues** on any row in the Cleanable Files tab — if the scanner recognizes an auto-fixable pattern in that file's *current* on-disk content, the same modal shows a **🔍 Preview** section with the exact bytes Clean would remove (and what, if anything, replaces them), so you can verify the fix before running it.
4. **Clean (not delete) injected menu items.** The Menu XSS section has its own **"Clean selected"** action. This surgically strips only the known injection markers (`<script>` tags, event-handler attributes, `localStorage` calls, `MutationObserver`, marker domains) out of the `params` JSON, field by field, and leaves every legitimate Helix Ultimate/SPPB layout setting on that menu item untouched. It also enforces that `item_id` is always a plain integer — if a payload replaced it with markup, that field is blanked rather than left as garbage, since there's nothing safe to salvage there. If a row's `params` can't be safely parsed as JSON at all, it's skipped with a note so you can review it by hand instead of risking corruption.
5. **Delete rogue iconfont/asset rows** using the checkboxes in the SP Page Builder asset table section.
6. **Remove rogue Super Users** manually via Joomla Admin → Users → Manage.
7. **Clean template styles defacement** directly via phpMyAdmin/SQL (this section is report-only, since defacement text sits alongside legitimate template settings that vary too much to auto-clean safely).
8. **Rotate every credential** readable from `configuration.php` (and any backup copies found): database password, SMTP password, API keys, and Joomla's `secret` value.
9. **Force-logout all sessions** by truncating `#__session` or using Users → Sessions → Destroy.
10. **Check cron jobs** (`crontab -l` via SSH, or your hosting panel) for anything you didn't add.
11. **Re-scan** after cleanup, and again in a few days — some droppers re-create themselves via a leftover scheduled task or a second, undiscovered backdoor.

---

## 🛡️ Protection Mode (real-time attack blocking)

On-demand scanning finds an infection *after* it's already happened. Protection Mode, via the companion **`plg_muruguardshield`** plugin, checks every single request to your site as it happens — the only extension type Joomla runs on every page load, before routing even happens.

1. Install and enable `plg_muruguardshield` (see Installation above) — it does nothing on its own, it's entirely controlled from the scanner's own Settings panel.
2. In **Components → MuRu Guard → ⚙️ Settings → 🛡️ Protection** (this is the default tab), turn on:
   - **Protection Mode** — the master switch. Detects and logs every match. Safe to leave on by itself: zero risk of blocking a real visitor.
   - **Actively block high-confidence attack patterns** *(opt-in)* — rejects webshell interaction, a direct probe against the SPPB `uploadCustomIcon` RCE, and known malware-drop filenames with a 403, instead of only logging them. Lower-confidence matches (path-traversal probes, known scanner User-Agents) are always logged only, never auto-blocked, since those are broad enough to occasionally match legitimate traffic.
   - **Block brute-force login attempts** *(opt-in)* — rejects further backend login attempts from an IP once it crosses a threshold (default 5 failures in 15 minutes, both configurable).
3. Everything detected — blocked or not — appears in the **Protection Log** right below those switches, sectioned into **Attack Pattern Matches** and **Brute-Force Login Attempts**, each row showing IP, timestamp, severity, matched rule, and whether it was actually blocked.

All three switches are **off by default**. Already-authenticated, non-guest admin sessions are exempt from request-pattern blocking, so a legitimate action can never trip a false block and lock you out of your own site — brute-force blocking has no such exemption, since it only ever targets pre-authentication login attempts.

> ⚠️ If your site sits behind a reverse proxy or CDN that doesn't forward the real client IP, every visitor can appear as one IP to this plugin — check that your setup forwards `REMOTE_ADDR` correctly before relying on brute-force blocking in production.

---

## ⏰ Scheduled scanning (webcron alerts)

Point any cron system at a webcron URL and get an email only when something **new** shows up — not on every run, and never on the very first run (which just records a baseline).

1. Click **⚙️ Settings** in the top-right corner of the scanner page (next to Support). Flip the **scheduled scanning switch** on, click **🎲 Generate** to fill in a secret token, set an **Alert email address**, then **💾 Save Settings**. (The same 3 fields also live under **System → Global Configuration → MuRu Guard**, if you prefer that route — both stay in sync.)
2. Copy the webcron URL shown right there in the Settings panel (there's a 📋 button), or build it yourself:
   ```
   https://yoursite.example/administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=YOUR_TOKEN
   ```
3. Add a job to your server's crontab, your host's "Cron Jobs" control panel, or a free external cron service (e.g. cron-job.org) that fetches that URL once a day. A plain `curl` or `wget` works — no login, no CSRF token, no SSH access to the server needed. A crontab entry looks like:
   ```
   0 3 * * * curl -fsS "https://yoursite.example/administrator/index.php?option=com_muruguard&task=scanner.scheduledcheck&token=YOUR_TOKEN" >/dev/null
   ```
4. The switch is the master control — turning it off stops scheduled scanning immediately without losing your token/email, and an empty token is never accepted even when the switch is on. Off by default.

This reuses the same detection logic as a manual scan (including the core-checksum verification above), it just tracks what's new between runs and only emails when the new-findings count is greater than zero.

---

## 🔐 Hardening

The most effective server-level fix is blocking PHP execution in directories that should only ever hold static assets. Add this to your site's `.htaccess`:

```apache
<DirectoryMatch "/(media|images|uploads|tmp|cache|assets|icons|fonts)(/|$)">
  AllowOverride None
  <FilesMatch "(?i)\.(php|phtml|phar|php[0-9]?|php\..*|shtml)$">
    Require all denied
  </FilesMatch>
</DirectoryMatch>
```

Even if a webshell makes it onto the server, this returns a 403 instead of executing it.

Other recommendations:

- Enable 2FA on Joomla admin, your hosting panel, and any linked email accounts
- Keep every extension updated — most real-world Joomla compromises trace back to a known, already-patched vulnerability that was simply never applied
- Audit any other extension with file-upload capability for the same class of weakness, not just SPPB and JCE
- Consider a Joomla firewall component (Akeeba Admin Tools Pro, RSFirewall) for ongoing protection

---

## 🗑️ Uninstalling

Since these are standard Joomla extensions, removal is a normal uninstall — no separate cleanup step needed:

**System → Manage → Extensions**, filter by "MuRu Guard", select the component (and the `plg_muruguardshield` plugin, if installed), and click **Uninstall**. This removes each extension's files and database records in one action. Uninstalling the plugin alone (keeping the component) simply turns off real-time protection while leaving on-demand scanning intact.

---

## 📋 Recommended order of operations

1. Back up the full site
2. Update SP Page Builder to 6.6.2+
3. Update or remove JCE if installed
4. Install the extension via the Joomla administrator
5. Run the scan, review findings carefully — start with core entry-point findings if any exist
6. Clean injected menu items, delete confirmed malware files, and remove rogue asset rows
7. Remove rogue Super Users and clean template defacement
8. Rotate all credentials
9. Apply the `.htaccess` hardening rule
10. Uninstall the extension once you're confident the site is clean (optional — it's safe to leave installed for future re-scans)

---

## 🔒 Security model

- Access is governed entirely by Joomla's own authentication and ACL — there is no separate secret key, login screen, or public-facing URL to protect
- Only users with the `com_muruguard` component permission (Super Users by default) can view results or trigger actions
- All state-changing actions (delete, clean, Protection Mode settings) require a Joomla CSRF token, consistent with core Joomla components
- File deletion is restricted to paths the **current scan run** actually flagged — a compromised admin session still cannot be turned into a general-purpose file browser or delete tool
- Menu params cleaning only ever removes matched injection patterns (or blanks a corrupted `item_id`) — it never touches fields that don't match a known signature
- No file content is ever executed or included — only read as text for pattern matching
- Scan and action logs are stored in the extension's own database tables, viewable from the component's admin screens
- `plg_muruguardshield` has no settings of its own — it is entirely configured from the component's Settings panel, wraps every check in a try/catch, and fails open (silently does nothing) if the component isn't installed or a check throws, since a bug in a plugin that runs on every page load must never be able to take the whole site down

---

## ❤️ Support this project

If this tool saved you time, consider supporting continued development:

[☕ Buy me a coffee (via Payoneer or PayPal Zoom)](zkranao@gmail.com)

And if you found it useful, a ⭐ on the repository helps others find it too.

---

## 📝 Feedback

If you have any feedback or suggestions, please open an issue on the repository.

**Got a feature you'd like to see next?** More detection coverage, deeper auto-cleanup, better reporting, something else entirely — [open an issue](../../issues) and let me know what would actually be useful to you.

---

## 🙏 Thanks to

**MD. Toufiqur Rahman**, **Paul Frankowski**, **Ofi Khan**, and **Md. Atick Eashrak Shuvo**, for your valuable support and contributions in helping me to improve this tool.

- [ZKRANA](https://github.com/zkrana)

## 👨‍💻 Author

**ZKRANA**

---

## 📄 License

MIT
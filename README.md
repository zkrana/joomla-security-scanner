# 🛡️ SP Page Builder Infection Scanner

A self-contained PHP scanner for Joomla sites that detects and helps remove malware left behind by the **SP Page Builder `uploadCustomIcon` unauthenticated RCE vulnerability** (versions prior to 6.6.2). It also checks the **JCE editor component (`com_jce`)**, which has been reported as a secondary infection vector on sites compromised through SPPB.

No dependencies. No installation. Upload one file, scan, clean up, delete.

Need Help? <a href="https://www.linkedin.com/in/zkranadevs/">Reach Me</a> or Email me at <a href="mailto:zkranao@gmail.com">zkrana@gmail.com</a>

---

## ⚠️ Critical security notice

In June 2026, a critical unauthenticated RCE was disclosed in SP Page Builder versions below 6.6.2. The flaw allowed attackers to upload PHP webshells without any login, read `configuration.php`, and create rogue Super User accounts — often within minutes of finding a vulnerable site.

**Before doing anything else:**

1. **Update SP Page Builder to 6.6.2 or later.** Scanning a site that's still vulnerable just means cleaning up the same infection again tomorrow.
2. **Update or remove JCE** if installed. Several hosts have reported malware appearing inside `com_jce` on sites also hit by the SPPB exploit — most likely the same attacker reusing JCE's file-browser upload path as a fallback once they had a foothold.
3. **Take a full backup** and, if possible, run your first scan on a staging copy of the site rather than production.

---

## ✨ What it does

| Category | Detail |
|---|---|
| 🗂 Filesystem scan | Walks `media/`, `images/`, `templates/`, `tmp/`, `cache/`, the SPPB and JCE component directories, and the webroot itself |
| 🧬 Content signatures | Flags known webshell patterns (`eval(base64_decode(...))`, `assert($_POST...)`, `gsocket`, generic shells like c99/r57/WSO) |
| 📛 Filename patterns | Matches known malicious naming conventions from real SPPB compromises (e.g. `codex-sppb-*.php`) |
| 🔢 Numeric drop folders | Flags randomly-named numeric folders in `templates/`, `media/`, or `images/` — a common automated-drop pattern — while correctly ignoring legitimate date-based upload folders (`images/2026/06/17/`) |
| 🎭 Fake `index.php` detection | Joomla's standard `index.php` stub is a one-line "no direct access" guard; anything beyond that is flagged as a likely disguised webshell |
| 🎯 Confidence scoring | Every finding is labeled **High** or **Medium** so you can triage quickly instead of guessing |
| 🧩 JCE coverage | Same heuristics applied to `media/com_jce`, `administrator/components/com_jce`, `components/com_jce`, and `plugins/editors/jce`, with allow-lists tuned to avoid flagging JCE's own legitimate core/MVC files |
| 👤 Rogue Super Users | Flags accounts with attacker-pattern usernames (`webmanager83`, `codex*`) or `@secure.local` email domains |
| 🗄 Database scan | Checks `#__menu` for the Helix Ultimate mega-menu XSS payload and `#__sppagebuilder_assets` for injected `eval`/`base64_decode` content |
| 🧹 Guided cleanup | Built-in delete action (scoped only to items flagged in the current scan run) plus a self-destruct button to remove the tool when you're done |

This is a **heuristic scanner**, not a guarantee. Pair it with a fresh extension download + checksum comparison, and a full server-side malware scan (ClamAV, Imunify360, or your host's scanner) before declaring victory.

---

## 📦 Installation

### 1. Generate a secret key

```bash
php -r "echo bin2hex(random_bytes(32));"
```

This prints a random 64-character string, e.g.:

```
47f475d52f1edaf1607159aaafdf9581fb524ac2a16c0059d9353da96c1b3df4
```

### 2. Set the key in the scanner

Open `security-scanner.php` and replace the placeholder:

```php
$ACCESS_KEY = 'PASTE_YOUR_GENERATED_KEY_HERE';
```

The scanner refuses to run until this is changed to a unique value of at least 32 characters — this is intentional, not a bug.

### 3. Upload to the Joomla root

Upload the single file to the same directory as `index.php` and `configuration.php` (usually `public_html/`). Serve it over **HTTPS only**.

### 4. Open it in your browser

```
https://yoursite.com/security-scanner.php
```

You'll land on a login screen. Enter the key from step 1 — you'll be redirected once and the key will be stripped from the URL so it never sits in browser history.

---

## 🧪 Detection details

### Filesystem

- PHP/phtml/phar files dropped into `media/`, `images/`, or icon-font asset folders
- Content matching `eval(base64_decode($_POST...))`, cookie-gated backdoors, `gsocket` indicators, and generic webshell signatures
- Numeric-named folders inside `templates/`, `media/`, or `images/` (e.g. `features/252692/`) — flagged unless they match a standard date-folder pattern
- Any `index.php` whose content is more than Joomla's one-line access guard, outside a template's own root layout file
- `.shtml` files anywhere in the webroot (Joomla never ships these by default)
- A "cluster" note when 3+ new items appear in the same folder within a couple of minutes — a strong signal of an automated drop

### Users

- Super User accounts with usernames matching known attacker patterns or email domains ending in `@secure.local`

### Database

- `#__menu` rows containing the Helix Ultimate mega-menu Stored XSS payload
- `#__sppagebuilder_assets` rows containing `eval(`, `base64_decode`, or known exfiltration domains

---

## 🧹 Cleanup workflow

If the scan finds something:

1. **Don't panic-delete.** Review High-confidence findings first, then Medium. If unsure, copy a file elsewhere before removing it.
2. **Delete confirmed malware** using the checkboxes and the Delete button — only files flagged by the current scan run can be removed, and top-level Joomla folders are hard-protected regardless of what gets flagged.
3. **Remove rogue Super Users** manually via Joomla Admin → Users → Manage.
4. **Clear injected menu/asset rows** directly via phpMyAdmin/SQL, not through the Joomla admin UI (which may try to render an XSS payload while you're editing it).
5. **Rotate every credential** readable from `configuration.php`: database password, SMTP password, API keys, and Joomla's `secret` value.
6. **Force-logout all sessions** by truncating `#__session` or using Users → Sessions → Destroy.
7. **Check cron jobs** (`crontab -l` via SSH, or your hosting panel) for anything you didn't add.
8. **Re-scan** after cleanup, and again in a few days.

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

## 🧨 When you're done: self-destruct

Leaving a security scanner reachable on a live server is itself a risk. Once cleanup is finished, click **Self-destruct** at the bottom of the scanner page — it permanently deletes the script and its log files in one click. You can also remove it manually via FTP/SSH.

---

## 📋 Recommended order of operations

1. Back up the full site
2. Update SP Page Builder to 6.6.2+
3. Update or remove JCE if installed
4. Upload and configure the scanner
5. Run the scan, review findings carefully
6. Remove confirmed threats and rogue accounts
7. Rotate all credentials
8. Apply the `.htaccess` hardening rule
9. Self-destruct the scanner

---

## 🔒 Security model

- A single secret key (set by you) gates access; after first use, auth is handed off to a secure `HttpOnly`, `SameSite=Strict` session cookie
- Repeated failed key attempts trigger a temporary lockout
- All state-changing actions (delete, logout, self-destruct) require a CSRF token bound to the session
- File deletion is restricted to paths the **current scan run** actually flagged — a stolen session cannot be used as a general-purpose delete tool
- No file content is ever executed or included — only read as text for pattern matching
- Strict response headers (CSP, no-store, X-Frame-Options) are sent on every response

---

## ❤️ Support this project

If this tool saved you time, consider supporting continued development:

[☕ Buy me a coffee (via Payoneer or PyaPal Zoom)](zkranao@gmail.com)

And if you found it useful, a ⭐ on the repository helps others find it too.

---

## 👨‍💻 Author

**ZKRANA**

---

## 📄 License

MIT

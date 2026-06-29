# 🛡️ SP Page Builder Infection Scanner for Joomla

A lightweight but powerful **Joomla security scanner** built to detect and remove malware caused by the **SP Page Builder uploadCustomIcon RCE vulnerability (pre-6.6.2)** — including secondary infections found inside the **JCE editor component (com_jce)**.

## ❤️ Support

If you find this project helpful, consider supporting my work.

<p align="center">
  <a href="[BUY ME A COFFEE](https://www.supportkori.com/zkranao)" target="_blank" style="text-decoration: none;">
    <span style="display: inline-block; vertical-align: middle;">
      <img
        src="https://plus.unsplash.com/premium_photo-1674327105076-36c4419864cf?q=80&w=987&auto=format&fit=crop"
        alt="Coffee"
        width="45"
        height="45"
        style="border-radius: 8px; vertical-align: middle;"
      />
       <span> Buy Me A COFEE </span>
    </span>
  </a>
</p>

This tool helps you quickly identify:
- Webshell backdoors
- Rogue Joomla Super Users
- Suspicious PHP uploads
- Malicious files inside the JCE editor's upload paths
- Database injections
- Known SPPB exploit patterns

---

## ⚠️ Critical Security Notice

A major vulnerability was discovered in **SP Page Builder (< 6.6.2)**:

- Unauthenticated Remote Code Execution (RCE)
- Malicious ZIP upload bypass
- Silent PHP webshell deployment
- Unauthorized admin account creation

👉 **Always update to SP Page Builder 6.6.2 or higher before scanning**

Several hosts have also reported malicious files appearing inside the **JCE editor component (com_jce)** on sites compromised via SPPB — most likely the same attacker reusing JCE's own file-browser upload path as a secondary drop point once a foothold was established.

👉 **If you run JCE, update it to the latest version — or remove it entirely if it's unused**

---

## 📥 Download

### 🔗 Get the Scanner Code
👉 Download or clone the repository:

```bash
git clone https://github.com/your-username/sppb-infection-scanner.git
````

### ⭐ Support the Project

If this tool helps you:
👉 Please **star the repository** on GitHub to support continued updates and security research.

---

## 🚀 Features

* 🔍 Detects malware files and PHP shells
* 🧩 Scans both SP Page Builder **and** JCE editor directories
* 👤 Finds rogue Joomla admin accounts
* 🧠 Pattern-based exploit detection
* 🗄️ Database injection scanning
* ⚡ Lightweight PHP execution (no dependencies)
* 🧹 Self-destruct cleanup system

---

## 📦 Installation

### 1. Generate security key

Run:

```bash
php -r "echo bin2hex(random_bytes(32));"
```

Example:

```
47f475d52f1edaf1607159aaafdf9581fb524ac2a16c0059d9353da96c1b3df4
```

---

### 2. Configure scanner

Edit:

```
security-scanner.php
```

Set your key:

```php
$ACCESS_KEY = 'YOUR_GENERATED_KEY_HERE';
```

---

### 3. Upload to Joomla root

Upload to:

```
/public_html/
```

Same folder as:

* index.php
* configuration.php

---

### 4. Run scanner

Open in browser:

```
https://your-site.com/security-scanner.php
```

Login using your secret key.

---

## 🧪 What It Detects

### 🗂 File System Scan

* PHP shells in `/media/`
* `eval(base64_decode())`
* `codex-sppb-*.php`
* Unexpected executables in upload folders
* Malicious files inside JCE's editor and file-browser upload paths (`media/com_jce`, `administrator/components/com_jce`, `components/com_jce`, `plugins/editors/jce`)

---

### 👤 User Scan

* Fake Super Users
* Suspicious accounts:

  * `webmanager83`
  * `*@secure.local`

---

### 🗄 Database Scan

* Joomla menu XSS payloads
* `#__sppagebuilder_assets` injections
* Obfuscated SQL payloads

---

## 🧹 Cleanup Guide

If malware is found:

1. Delete all **high-confidence files**
2. Remove rogue admin accounts
3. Update or remove the **JCE editor** if flagged or unused
4. Change all passwords:

   * Joomla admin
   * Database
   * SMTP/API keys
5. Clear sessions (`#__session`)
6. Check cron jobs
7. Re-scan after cleanup

---

## 🔐 Hardening (Important)

Add to `.htaccess`:

```apache
<DirectoryMatch "/(media|images|uploads|tmp|cache|assets|icons|fonts)(/|$)">
  AllowOverride None
  <FilesMatch "(?i)\.(php|phtml|phar|php[0-9]?|php\..*|shtml)$">
    Require all denied
  </FilesMatch>
</DirectoryMatch>
```

---

## 🧨 Self-Destruct Feature

After scanning, use the built-in cleanup:

> The **Self-destruct button** permanently deletes the scanner and logs from your server.

⚠️ Never leave security tools on production servers.

---

## 📊 Recommended Workflow

1. Backup full website
2. Update SP Page Builder to 6.6.2+
3. Update or remove JCE if it's installed
4. Upload scanner
5. Run full scan
6. Remove threats
7. Rotate credentials
8. Delete scanner (self-destruct)

---

## 🧠 Best Practices

* Always test on staging first
* Scan all websites under same hosting account
* Monitor server logs for exploit attempts
* Use firewall (Admin Tools / RSFirewall)
* Audit every editor/extension with file-upload capability (not just SPPB and JCE) for the same upload-path weaknesses

---

## 👨‍💻 Author

**ZKRANA**

Building secure, scalable digital systems for modern web applications.

---

## 📄 License

MIT / Internal Security Tool (update as needed)

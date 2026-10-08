# JED Submission — MuRu Guard (fill guide)

Fill the "Add extension" form on extensions.joomla.org with exactly these
values. The bundle's install name is **MuRu Guard** — the listing name
must match it exactly, including case.

## File and version

- **Extensions File:** `dist/pkg_muruguard-3.6.3.zip` (the bundle: scanner
  component + Shield plugin in one install).
- **Version:** `4.0.0` — must match the `<version>` inside the uploaded
  zip. If you cut a newer release first (`scripts/release.sh X.Y.Z`),
  enter that number instead and upload the matching zip.
- **Extension Name:** `MuRu Guard`
- **"My extension includes external libraries":** leave unchecked. Every
  asset ships inside the zip; the admin stylesheet is precompiled,
  not a CDN or external library.

## Description (paste-ready)

> MuRu Guard is a free Joomla security suite: a malware scanner component
> plus a real-time Shield plugin, installed together in one package.
>
> Built for the aftermath of the SP Page Builder `uploadCustomIcon`
> unauthenticated RCE, the scanner detects webshells and backdoors hidden
> in media, images, templates and core entry points, verifies core files
> byte-for-byte against official Joomla release hashes, and finds rogue
> Super User accounts, Helix mega-menu XSS injections and defaced template
> styles. Every finding is confidence-scored and ships with a guided,
> backup-first cleanup. Chunked, resumable scans with a progress bar never
> hit host execution-time limits.
>
> The bundled Shield plugin adds real-time Protection Mode: webshell, RCE
> and brute-force blocking with an audit log, Admin Lockdown, Protected
> User auto-revert, and a self-testing Backend Access gate.
>
> No account, no API key, no upsells or nag screens. The admin UI loads
> zero third-party assets, all scanning runs on your own server, and
> updates arrive through Joomla's own updater. Requires Joomla 3.10+
> (PHP 7.4+) through 6.x (PHP 8.1+ on Joomla 4+).

## Category and tags

- **Category:** Security Tools
- **Tags:** `security`, `malware`, `scanner`, `firewall`

## Links (all must differ, except homepage may equal download)

- **Project homepage:**
  `https://store.lyzerslab.com/joomla-products/muru-guard-security-scanner`
- **Download:** same URL as the homepage (explicitly allowed).
- **Demo:** leave blank — no demo applies to a security tool.
- **Support:** `https://www.linkedin.com/in/zkranadevs/`
  (the "Need Help? Reach Me" contact from the README).
- **Documentation:** `https://github.com/zkrana/joomla-security-scanner`
  (the README is the full documentation: install, features, FAQ).
- **License page:** `https://www.gnu.org/licenses/gpl-2.0.html`
  (GPLv2-or-later text; `LICENSE.txt` also ships inside every zip.
  Replace with a license page on your own store if you add one.)

## Integration, license, compatibility

- **Download type:** Free. Leave "Related Free/Paid JED ID" blank
  (only needed if/when the Pro edition gets its own listing).
- **License:** GNU General Public License v2 or later.
- **Compatibility:** tick Joomla **3**, **4**, **5.x compatible** and
  **6.x compatible**, and do NOT tick any "only with B/C plugin"
  option — the code is native `Joomla\CMS\*` API with its own
  small Joomla 3 compatibility layer (`admin/helpers/compat.php`),
  no Joomla B/C plugin involved.
- **"Integrates the Joomla! Update System":** yes. The component feed
  is live; the Shield feed and the bundle entry are dashboard TODOs
  below (Joomla degrades gracefully until they are served).
- **"Verified with JED Checker":** yes (run and clean).
- **"Install name matches the entry name":** yes — both `MuRu Guard`.
- **Extension includes:** tick **C** (Component) and **P** (Plugin) —
  exactly what the bundle installs. Nothing else.

## Logo and images

- **Logo (required):** PNG/JPG, 1200x525 or larger (16:7).
- **Images (recommended):** screenshots of the scanner dashboard and a
  scan report at the same size.
- Nothing in this repo fits (the only banner is Pro artwork), so these
  need creating before submitting.

## Dashboard TODOs (outside this repo)

Until each is served, Joomla simply reports "no update available" for
that extension — nothing breaks.

1. **Shield plugin feed (new endpoint):**
   `https://store.lyzerslab.com/api/joomla-update/free-shield`
   (currently 404). Serve the same update-XML shape as the existing
   `free` feed with `<element>plg_system_muruguardshield</element>`,
   `<type>plugin</type>`, `<folder>system</folder>`,
   `<version>` matching the plugin manifest, and a `<downloadurl>`
   serving the plugin zip.
2. **Bundle entry (extend the existing live feed):**
   `https://store.lyzerslab.com/api/joomla-update/free`. Add a second
   `<update>` block mirroring the component entry's shape with
   `<name>MuRu Guard</name>`, `<element>pkg_muruguard</element>`,
   `<type>package</type>`, `<version>` matching the package manifest,
   and a `<downloadurl>` serving the bundle zip.

## After approval

1. Keep `dist/` zips and the dashboard downloads in sync on every
   release (`scripts/release.sh X.Y.Z` → tag → CI attaches all three
   zips to the GitHub Release).
2. JED shows the changelog — `CHANGELOG.md` already follows
   Keep-a-Changelog and feeds the GitHub Release notes verbatim.

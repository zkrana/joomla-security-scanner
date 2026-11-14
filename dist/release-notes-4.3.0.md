## [4.3.0] - 2026-11-13

A feature release for every supported Joomla version (3.10 to 6): protection levels in one click, SP Page Builder Guard, a review list of old and unused extensions, and the same look as MuRu Guard Pro. Update the Shield plugin to 1.7.0 together with the component (the package installs both). The SP Page Builder attack-route rules are on by default; nothing else changes until you choose a level.

### Added

* **Security presets.** Settings > Site Protection offers four protection levels (Basic, Standard, Advanced and Maximum), each listing exactly which settings it changes, with one-click Undo and "Custom" shown once you change a setting by hand.
* **SP Page Builder Guard.** Requests to SP Page Builder's unused "get-page-data" action, and file or addon parameters holding a traversal, a stream wrapper or a server path, are refused and logged, even before SP Page Builder is patched; the editor never sends these.
* **Scripts planted in SP Page Builder pages are found.** The scan checks pages, drafts, saved versions, collection items, saved sections and saved addons and lists scripts with attack signs, such as reading cookies, hidden code or onerror handlers, in a new SPPB Pages tab.
* **Extensions to review.** The Dashboard lists extensions that look abandoned (no update in two years) or unused (disabled, unpublished or on no page), with advice to uninstall what you no longer need.
* **Protection level suggestion on the Dashboard.** While no level was ever applied and Protection Mode is off, the Dashboard links to the presets.

### Changed

* **Same look as MuRu Guard Pro.** Buttons and tabs use one flat style with more space between them, and text uses the Inter font, bundled so nothing is loaded from other servers.

### Fixed

* **No more false alerts in Vulnerable Extensions.** An extension is listed only when its installed version is one an advisory names as affected. Advisories that name no version are no longer shown, a version given only in the advisory title ("2.9.79", "1.5 and previous") is used as the limit, and Joomla's own extensions, such as its built-in "content" plugins, are never matched. The table now shows the extension's installed name.
* **JCE's editor layout is no longer reported as a possible webshell.** An index.php that starts with Joomla's "no direct access" line stops when opened directly, so it is an extension's own layout (JCE 2.9.80 and later keep one in plugins/editors/jce/Wfe/views/plugin), not a hidden entry point. Every other unusual index.php is still flagged, and the full malware scan still runs on every file.
* **No false "can't check for updates" warning for JCE.** An extension installed as part of a package is updated through the package's update site (JCE's sits on its "JCE Editor Package"), so it is no longer reported as having no update site.

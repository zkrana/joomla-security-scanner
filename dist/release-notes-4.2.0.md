
### Added

* **Admin Lockdown.** New Settings > Site Protection toggle that blocks the Joomla extension installer and creating new backend users while on -- stops a compromised admin session from installing a malicious extension or planting a fresh Super User account. Never touches Joomla's own core updates or editing an existing user (including your own profile). Off by default.
* **Protected User Snapshot & Auto-Revert.** Snapshots every current Super User and watches for tampering on every scheduled check. A protected account getting blocked or removed from the Super Users group is reverted automatically; an email/password change or account deletion is alerted immediately but never auto-reverted, since either can just as easily be something you did yourself. A "Take/refresh snapshot now" button lets you accept a legitimate change as the new baseline.
* **Test a Request.** A read-only preview tool under Settings > Site Protection: paste a URL, IP, User-Agent, or Referer and see exactly what Shield would do with it -- blocked, flagged, or allowed, and why -- before you turn any blocking switch on. Runs through the exact same checks the live gate uses; never writes to the attack log or affects real traffic.


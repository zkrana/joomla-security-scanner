
### Fixed

* **Possible cause of "license key/settings look empty after updating."** Every settings read goes through Joomla's `ComponentHelper::getParams()`, which caches the component registry in the `_system` cache group -- every save method in this codebase already knows to invalidate that cache afterward, but Joomla's own installer writes the extension's row back during an update without ever doing so itself. If the registry got cached at any point during install, the Settings panel could go on serving a stale snapshot indefinitely afterward, reading exactly like data loss even though the database row itself was untouched. `postflight()` now unconditionally clears the `_system` cache after every install/update.


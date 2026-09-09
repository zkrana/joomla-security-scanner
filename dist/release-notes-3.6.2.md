
### Changed

* **Outbound dashboard calls now go to `store.lyzerslab.com`** (the dedicated product/storefront subdomain) instead of the main marketing domain -- the vulnerability feed, the newsletter opt-in banner, and the extension's own Joomla update-check (`<updateservers>`) all switched. No behavior change for users; `lyzerslab.com` keeps serving the same routes for anyone still on an older build, so this update is not required for updates themselves to keep working.


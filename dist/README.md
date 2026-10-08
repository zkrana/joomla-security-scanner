# MuRu Guard: Distribution Zips

**Your Joomla site deserves a guard that never sleeps.** 🛡️

MuRu Guard is a free, open-source Joomla security suite. It finds the malware you can't see, helps you clean it up safely, and blocks the next attack before it lands. The free version supports **Joomla 3 through the latest Joomla release**, so whether you run a long-standing legacy site or a brand-new Joomla 5 or 6 build, you are covered.

It is built for the moment every site owner dreads: the hack, the defaced homepage, the warning from your host. It also has extra, purpose-built detection for sites that run **SP Page Builder** and **Helix Ultimate**.

## What's in the box

One package installs everything. No account, no license key, no API key.

- **Malware scanner component:** finds webshells, backdoors, rogue Super Users, Helix mega-menu XSS injections and defaced template styles. Every finding has a confidence score and shows why it was flagged.
- **Shield plugin (real-time protection):** blocks webshell, RCE and brute-force attempts, with Admin Lockdown, Protected User auto-revert and an audit log.
- **Guided, backup-first cleanup:** so one wrong click never turns a bad day into a worse one.

## Download and install

Installable release zips are built from the current source tree by `scripts/build.sh`.

> **Install the bundle package.** It contains both the component and the plugin:
>
> - `pkg_muruguard-<version>.zip`: the full bundle (component + Shield plugin)

Notes:

- Filenames track the manifest versions, so **never rename these zips by hand**. Rebuild with `scripts/build.sh` instead.
- Older zips are kept for history. **Always install the highest version available.**
- Install it like any Joomla extension: **System → Install Extensions → Upload Package File**. It takes about two minutes.

## Get it on the Joomla Extensions Directory

MuRu Guard is now listed on the official Joomla Extensions Directory, and every release is available there too:

👉 <https://extensions.joomla.org/extension/muru-guard/>

## Why you can trust it

- 💯 Free and open-source
- 🔒 All scanning runs on your own server
- 👀 Read-only scanning: nothing is executed
- 🚫 No account, no API key, no third-party assets in the admin UI
- 🔄 Updates arrive through Joomla's own updater

*Install it once, switch on protection, and get back to running your site. MuRu Guard keeps watch from there.*
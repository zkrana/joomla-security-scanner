
### Added

* **New malware detections**, confirmed against real dropped samples reported from a live incident: exact SHA-256 matches for a 421-byte "X9 Tools" bare file-upload webshell and a 6.5MB heavily-obfuscated PHP backdoor, plus a content-pattern signature for the "X9 Tools" webshell's self-branding and Telegram contact handle (catches re-obfuscated variants of it, not just the exact sample). The known-hash check runs independently of `max_file_scan_size` -- an oversized sample like the 6.5MB one no longer silently skips scanning just for being bigger than the usual scan window. Applies to the ZIP-archive content scan too, not just plain files.


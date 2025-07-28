# Ruby2FA TOTP Desktop App

## Summary

This is a simple, functional security-minded TOTP 2FA app for desktop. Currently you can run it via python, but in the near future I want to release an exe as well for non-power users.

This includes:

## Features

* Add via secret key, or click a button to capture a QR code to automatically add it

*



## Security options

* keeps your 2FA secrets safe with strong encryption and a master password—your codes are protected even if your files are stolen!
    * ###### Ruby2FA encrypts all TOTP secrets using AES (Fernet) with a key derived from your master password via PBKDF2-HMAC-SHA256 and a unique salt. The master password hash is never stored in plaintext. Secrets are never written to disk unencrypted. Exported backups are encrypted in the same way, and a backup can only be imported when the same login password is used.  
    * ###### WARNING: This means if you lose or forget your password, you CANNOT recover your files! 

* Sensitive UI elements are hidden when locked

* Optional third-factor authentication (SMTP email (server/port required) or SSH agent) can be enabled.

* When copied, clears clipboard after a configurable (default 10s) amount of time

* Auto-locks the app and requires password re-submission after a configurable (default 60s) amount of time - and clears the window




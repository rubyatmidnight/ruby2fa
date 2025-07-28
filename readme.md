# Ruby2FA TOTP Desktop App

## Summary

This is a simple, functional security-minded TOTP 2FA app for desktop. Currently you can run it via python, but in the near future I want to release an exe as well for non-power users. This came about because I got tired of how bad google authenticator is, and how authy wants me to give them money

This includes:

## Features

* Add via secret key, or click a button to capture a QR code on the current monitor to automatically add it

* Copy to clipboard, and auto-clears clipboard afterwards

* Recoverable so long as you have the rubykey.json.env file, please back it up if it's important

* Open source and offline, only connects to an email server for optional 3fa



## Security options

* keeps your 2FA secrets safe with strong encryption and a master password—your codes are protected even if your files are stolen!
    * ###### Ruby2FA encrypts all TOTP secrets using AES (Fernet) with a key derived from your master password via PBKDF2-HMAC-SHA256 and a unique salt. The master password hash is never stored in plaintext. Secrets are never written to disk unencrypted. Exported backups are encrypted in the same way, and a backup can only be imported when the same login password is used.  
    * ###### WARNING: This means if you lose or forget your password, you CANNOT recover your files! 

* Sensitive UI elements are hidden when locked

* Optional third-factor authentication (SMTP email (server/port required) or SSH agent 3fa) can be enabled.

* When copied, clears clipboard after a configurable (default 10s) amount of time

* Auto-locks the app and requires password re-submission after a configurable (default 60s) amount of time - and clears the window


## Usage Instructions

1. **Install Python**  
   - Download and install Python 3.8 or newer from [python.org/downloads](https://www.python.org/downloads/).  
   - During installation, make sure to check "Add Python to PATH".

2. **Download Ruby2FA**  
   - Download or extract the Ruby2FA files to a folder on your computer.

3. **Install dependencies**  
   - Open a terminal (Command Prompt/Powershell on Windows, Terminal on Mac/Linux).
   - Navigate to the folder where you saved Ruby2FA.
    - Example: (cd: change directory)
      ```
      cd path/to/Ruby2FA
      ```
   - Run:  
     ```
     pip install -r requirements.txt
     ```

4. **Start the app**  
   - In the same terminal, run:  
     ```
     python ruby2fa.py
     ```
   - The Ruby2FA window will open.

5. **Add an account**  
   - Click "Add" to enter a label and your TOTP secret, or  
   - Click "Scan QR" to capture a QR code from your screen.

6. **Copy a code**  
   - Select an account and click "Copy Code" to copy the current code to your clipboard.  
   - The clipboard will auto-clear after a few seconds.

7. **Backup your secrets**  
   - Backup your `rubykey.json.enc` file to keep your accounts safe.

8. **Enable 3FA (optional)**  
   - Open "Settings" in the app to configure email or SSH 3FA for extra security.

9. **Lock/Unlock**  
   - The app auto-locks after inactivity. Enter your master password to unlock.

**Important:**  
If you forget your master password, your secrets cannot be recovered!  
Keep your backup and password safe.


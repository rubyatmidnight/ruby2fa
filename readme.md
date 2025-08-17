# Ruby2FA TOTP Desktop App

## Summary

This is a simple, functional security-minded TOTP 2FA app for desktop. Currently you can run it via python, but in the near future I want to release an exe as well for non-power users. This came about because I got tired of how bad google authenticator is, and how authy and other apps want me to give them money

This includes:

## Features

* Add directly via secret key, or click a button to capture a QR code on the current monitor to automatically add it (only works on primary monitor; will not capture secondary monitors! Only captures on using the button; not always-on!)

* Copy to clipboard, and auto-clears clipboard afterwards on a configured timer

* Recoverable so long as you have the rubykey.json.env file, please back it up if it's very important

* Open source and offline

* Import from google auth export  (not by qr code for safety reasons; you need the uri from the qr code, use any other qr code app to get it, and then import)

* Folder system; including padded numbers of accounts in the database for obfuscation and security so folder lengths can't be used as a cryptographic hint

## Security options

* keeps your 2FA secrets safe with strong encryption and a master password—your codes are protected even if your files are stolen!
    * ###### Ruby2FA encrypts all TOTP secrets using AES (Fernet) with a key derived from your master password via PBKDF2-HMAC-SHA256 and a unique salt. The master password hash is never stored in plaintext. Secrets are never written to disk unencrypted. Exported backups are encrypted in the same way, and a backup can only be imported when the same login password is used.  
    * ###### WARNING: This means if you lose or forget your password, you CANNOT recover your files! Hashcat is unlikely to help you unless your password was very weak!

* Sensitive UI elements are hidden when locked

* When copied, clears clipboard after a configurable (default 10s) amount of time

* Auto-locks the app and requires password re-submission after a configurable (default 60s) amount of time - and clears the window


## Usage Instructions

0. **Optional: Use quickstart.sh or quickstart.bat**
   - You can run the quickstart script to automatically set up Ruby2FA and its dependencies:
     ```
     bash quickstart.sh
     ```
   - On Windows, you can also double click the quickstart.bat file. 

1. **Install Python**  
   - Download and install Python 3.8 or newer from [python.org/downloads](https://www.python.org/downloads/).  
   - During installation, make sure to check "Add Python to PATH".

2. **Download Ruby2FA**  
   - Download or extract the Ruby2FA files to a folder on your computer.

3. **Install dependencies**  
   - Open a terminal (Command Prompt/Powershell on Windows, Terminal on Mac/Linux). (Search -> cmd. OR Win + R -> cmd)
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
   - The Ruby2FA window will open. Alternatively, use the shortcut options provided with the quickstart files.

5. **Add an account**  
   - The add/remove buttons are in the menu.
   - Click "Add" to enter a label and your TOTP secret, or  
   - Click "Scan QR" to capture a QR code from your screen.
    - ###### Note: This only works on your primary monitor, if the code is on a secondary monitor, it will not capture. Move the QR code to your main screen to use this function, and make sure the QR code isn't obscured.  

6. **Copy a code**  
   - Select an account and click "Copy Code" to copy the current code to your clipboard.  
   - The clipboard will auto-clear after a configured number of seconds.

7. **Backup your secrets**  
   - Backup your `rubykey.json.enc` file to keep your accounts safe.

8. **Lock/Unlock**  
   - The app auto-locks after inactivity. Enter your master password to unlock.

9. **Adjust settings**
   - Write in folder names per key, and put different keys in different folders. Currently not super modular; cannot move folder names around freely, partially because of how the encryption is done. 

**Important:**  
If you forget your master password, your secrets cannot be recovered!  
Keep your backup and password safe.



## Legacy Features/TBD Features

* Optional third-factor authentication (SMTP email (server/port required) or SSH agent 3fa)
* Always on top mode?
* Neko mode


## Common concerns

Q. Can I rename my entries?

   A. No, for security reasons, it's best to not have the names be changeable. Set up a new key if you need to change the name. 

Q. Can I move folder order?

   A. Same answer as above; you will have to delete the folder and remake it. The location and order of the folders is relevant to its security.

Q. It keeps locking on me

   A. In Settings, change the timer. It should have asked you for a default on first run, if it's not broken

Q. It's not capturing the QR code on my second monitor

   A. Primary monitor only. Drag it over

Q. It can't find the QR code and it's right on my desktop

   A. Make sure your mouse pointer is not covering part of it

Q. Why is markdown so annoying sometimes
   A. because it is
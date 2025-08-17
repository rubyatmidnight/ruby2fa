import sys
import pyotp
import time
import cv2
import numpy as np
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QInputDialog, QLineEdit, QComboBox, QListWidget, QMainWindow,
    QListWidgetItem, QMessageBox, QDialog, QFormLayout, QCheckBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QAbstractItemView
)
from PyQt5.QtCore import QTimer, QEvent, Qt
from pyzbar.pyzbar import decode
from PIL import ImageGrab
from cryptography.fernet import Fernet, InvalidToken
import base64
import os
import json
import hashlib
import secrets
import subprocess
import smtplib
from email.mime.text import MIMEText
import addtl.OtpMigration_pb2 as OtpMigration_pb2
import urllib.parse


# --- Directories ---

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECRETS_FILE = os.path.join(BASE_DIR, 'rubykeys', 'rubykey.json.enc')
MASTER_HASH_FILE = os.path.join(BASE_DIR, 'rubykeys', 'master.hash')
PBKDF2_ITER = 200_000
iconPath = os.path.join(BASE_DIR, 'rubykey.ico')

# --- Encryption helpers ---

def deriveKey(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encryptData(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decryptData(token, key):
    f = Fernet(key)
    return f.decrypt(token).decode()

def pbkdf2Hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITER)

import random
import string

MIN_FOLDER_SIZE = 5

def genDummyLabel():
    return 'dummy_' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def genDummySecret():
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))

def isDummyEntry(entry):
    return isinstance(entry, dict) and entry.get('dummy', False)

# Remove EmailConfigDialog and SSHConfigDialog classes and all their usages in SettingsDialog

class SettingsDialog(QDialog):
    def __init__(self, parent=None, lockTimeout=300, clipboardTimeout=20):
        super().__init__(parent)
        self.setWindowTitle('Settings')
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        # Remove emailTab, sshTab, and their tabs
        self.lockTimeoutBox = QComboBox()
        self.lockTimeoutBox.addItems([str(x) for x in [30, 60, 120, 300, 600, 900, 1800]])
        self.lockTimeoutBox.setCurrentText(str(lockTimeout))
        layout.addWidget(QLabel('Auto-lock timeout (seconds):'))
        layout.addWidget(self.lockTimeoutBox)
        self.clipboardTimeoutBox = QComboBox()
        self.clipboardTimeoutBox.addItems([str(x) for x in [10, 15, 20, 25, 30]])
        self.clipboardTimeoutBox.setCurrentText(str(clipboardTimeout))
        layout.addWidget(QLabel('Clipboard clear timeout (seconds):'))
        layout.addWidget(self.clipboardTimeoutBox)
        backupLayout = QHBoxLayout()
        self.exportBtn = QPushButton('Export Encrypted Backup')
        self.exportBtn.clicked.connect(self.exportBackup)
        self.importBtn = QPushButton('Import Encrypted Backup')
        self.importBtn.clicked.connect(self.importBackup)
        backupLayout.addWidget(self.exportBtn)
        backupLayout.addWidget(self.importBtn)
        layout.addLayout(backupLayout)
        self.importGoogleBtn = QPushButton('Import Google Auth Export')
        self.importGoogleBtn.clicked.connect(self.importGoogleAuth)
        layout.addWidget(self.importGoogleBtn)
        btnLayout = QHBoxLayout()
        self.okBtn = QPushButton('OK')
        self.okBtn.clicked.connect(self.accept)
        self.cancelBtn = QPushButton('Cancel')
        self.cancelBtn.clicked.connect(self.reject)
        btnLayout.addWidget(self.okBtn)
        btnLayout.addWidget(self.cancelBtn)
        layout.addLayout(btnLayout)
        self.parentWidget = parent

    def importGoogleAuth(self):
        if self.parentWidget:
            self.parentWidget.importGoogleAuthExport()

    def getConfigs(self):
        return (int(self.lockTimeoutBox.currentText()), int(self.clipboardTimeoutBox.currentText()))
    def exportBackup(self):
        if not self.parentWidget or not hasattr(self.parentWidget, 'secrets') or not hasattr(self.parentWidget, 'key'):
            QMessageBox.warning(self, 'Export Error', 'No secrets to export!')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export Encrypted Backup', '', 'Encrypted Files (*.enc)')
        if not path:
            return
        data = json.dumps(self.parentWidget.secrets)
        enc = encryptData(data, self.parentWidget.key)
        with open(path, 'wb') as f:
            f.write(enc)
        QMessageBox.information(self, 'Export Complete', 'Encrypted backup exported successfully!')
    def importBackup(self):
        if not self.parentWidget or not hasattr(self.parentWidget, 'key'):
            QMessageBox.warning(self, 'Import Error', 'No key available!')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import Encrypted Backup', '', 'Encrypted Files (*.enc)')
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                enc = f.read()
            data = decryptData(enc, self.parentWidget.key)
            secretsDict = json.loads(data)
            self.parentWidget.secrets = secretsDict
            self.parentWidget.saveSecrets()
            self.parentWidget.refreshAccounts()
            QMessageBox.information(self, 'Import Complete', 'Encrypted backup imported successfully!')
        except Exception as e:
            QMessageBox.warning(self, 'Import Error', f'Failed to import backup: {e}')

class LockDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Session Locked')
        layout = QVBoxLayout(self)
        self.infoLbl = QLabel('Session locked due to inactivity. Please re-enter your master password.')
        self.pwdEdit = QLineEdit()
        self.pwdEdit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.infoLbl)
        layout.addWidget(self.pwdEdit)
        btnLayout = QHBoxLayout()
        self.okBtn = QPushButton('Unlock')
        self.okBtn.clicked.connect(self.accept)
        btnLayout.addWidget(self.okBtn)
        layout.addLayout(btnLayout)
    def getPassword(self):
        return self.pwdEdit.text()

class Ruby2FA(QWidget):
    def __init__(self):
        super().__init__()
        self.secrets = {}  # Always foldered: {folder: [accountDict, ...]}
        self.accountTree = None
        self.totp = None
        self.currentLabel = None
        self.key = None
        self.gitWarning = self.checkGitTracked()
        self.lockTimeout = 180  # Default to 3 minutes
        self.clipboardTimeout = 10
        self.lastActivity = time.time()
        self.installEventFilter(self)
        self.initPassword()
        self.initUi()
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateTotp)
        self.timer.start(1000)
        self.lockTimer = QTimer()
        self.lockTimer.timeout.connect(self.checkAutoLock)
        self.lockTimer.start(10000)
        self.clipboardTimer = QTimer()
        self.clipboardTimer.setSingleShot(True)
        self.clipboardTimer.timeout.connect(self.clearClipboard)
        self.clipboardCountdownTimer = QTimer()
        self.clipboardCountdownTimer.timeout.connect(self.updateClipboardCountdown)
        self.clipboardCountdown = 0
        # Remove self.emailConfig, self.loadEmailConfig(), self.sshConfig, self.loadSSHConfig() from Ruby2FA.__init__

    def eventFilter(self, obj, event):
        if event.type() in [QEvent.MouseMove, QEvent.KeyPress, QEvent.MouseButtonPress]:
            self.lastActivity = time.time()
        return super().eventFilter(obj, event)

    def checkAutoLock(self):
        if time.time() - self.lastActivity > self.lockTimeout:
            self.lockApp()

    def lockApp(self):
        self.setSensitiveUiVisible(False)
        dlg = LockDialog(self)
        while True:
            if dlg.exec_():
                pwd = dlg.getPassword()
                pwdHash = pbkdf2Hash(pwd, base64.b64decode(self.getStoredSalt()))
                if self.verifyPassword(pwd, pwdHash):
                    self.lastActivity = time.time()
                    break
            else:
                sys.exit(0)
        self.setSensitiveUiVisible(True)

    def getStoredSalt(self):
        with open(MASTER_HASH_FILE, 'r') as f:
            data = json.load(f)
        return data['salt']

    def verifyPassword(self, pwd, pwdHash):
        with open(MASTER_HASH_FILE, 'r') as f:
            data = json.load(f)
        storedHash = base64.b64decode(data['hash'])
        return secrets.compare_digest(pbkdf2Hash(pwd, base64.b64decode(data['salt'])), storedHash)

    def checkGitTracked(self):
        tracked = []
        try:
            out = subprocess.check_output(['git', 'ls-files'], encoding='utf-8')
            files = out.splitlines()
            for fname in [SECRETS_FILE, MASTER_HASH_FILE]:
                if fname in files:
                    tracked.append(fname)
        except Exception:
            pass
        return tracked

    def initPassword(self):
        while True:
            pwd, ok = QInputDialog.getText(self, 'Master Password', 'Enter master password:', QLineEdit.Password)
            if not ok:
                sys.exit(0)
            if os.path.exists(MASTER_HASH_FILE):
                with open(MASTER_HASH_FILE, 'r') as f:
                    data = json.load(f)
                salt = base64.b64decode(data['salt'])
                storedHash = base64.b64decode(data['hash'])
                pwdHash = pbkdf2Hash(pwd, salt)
                if not secrets.compare_digest(pwdHash, storedHash):
                    continue
            else:
                salt = secrets.token_bytes(16)
                pwdHash = pbkdf2Hash(pwd, salt)
                with open(MASTER_HASH_FILE, 'w') as f:
                    json.dump({'salt': base64.b64encode(salt).decode(), 'hash': base64.b64encode(pwdHash).decode()}, f)
            key = deriveKey(pwd)
            if os.path.exists(SECRETS_FILE):
                try:
                    with open(SECRETS_FILE, 'rb') as f:
                        enc = f.read()
                    data = decryptData(enc, key)
                    self.secrets = json.loads(data)
                    self.key = key
                    break
                except (InvalidToken, json.JSONDecodeError):
                    continue
            else:
                self.secrets = {}
                self.key = key
                break

    def saveSecrets(self):
        secretsCopy = {}
        for folder, entries in self.secrets.items():
            realEntries = [e for e in entries if not isDummyEntry(e)]
            while len(realEntries) < MIN_FOLDER_SIZE:
                realEntries.append({
                    "label": genDummyLabel(),
                    "secret": genDummySecret(),
                    "dummy": True
                })
            secretsCopy[folder] = realEntries
        data = encryptData(json.dumps(secretsCopy), self.key)
        with open(SECRETS_FILE, 'wb') as f:
            f.write(data)

    def loadSecrets(self):
        with open(SECRETS_FILE, 'rb') as f:
            data = f.read()
        secretsDict = json.loads(decryptData(data, self.key))
        # MIGRATION: If flat dict, convert to foldered
        if secretsDict and all(isinstance(v, str) for v in secretsDict.values()):
            migrated = {'Default': []}
            for label, secret in secretsDict.items():
                migrated['Default'].append({
                    'label': label,
                    'secret': secret,
                    'dummy': False
                })
            self.secrets = migrated
        else:
            migrated = {}
            for folder, entries in secretsDict.items():
                newEntries = []
                for entry in entries:
                    if isinstance(entry, str):
                        newEntries.append({
                            'label': 'MigratedAccount',
                            'secret': entry,
                            'dummy': False
                        })
                    elif isinstance(entry, dict):
                        newEntries.append(entry)
                migrated[folder] = [e for e in newEntries if isinstance(e, dict) and not isDummyEntry(e)]
            self.secrets = migrated

    def initUi(self):
        self.setWindowTitle('Ruby2FA <3')
        mainLayout = QHBoxLayout()
        leftLayout = QVBoxLayout()
        if self.gitWarning:
            warnLbl = QLabel(f'Oh my whiskers! Security warning: {", ".join(self.gitWarning)} is tracked by git!')
            warnLbl.setStyleSheet('color: red; font-weight: bold; font-size: 14pt;')
            leftLayout.addWidget(warnLbl)
        self.accountTree = QTreeWidget()
        self.accountTree.setHeaderLabels(['Folder', 'Account'])
        self.accountTree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.accountTree.itemSelectionChanged.connect(self.accountSelected)
        leftLayout.addWidget(self.accountTree)
        btnLayout = QHBoxLayout()
        self.scanBtn = QPushButton('Scan QR')
        self.scanBtn.setStyleSheet('font-size: 12pt;')
        self.scanBtn.clicked.connect(self.scanQrFromScreen)
        btnLayout.addWidget(self.scanBtn)
        leftLayout.addLayout(btnLayout)
        self.menuBtn = QPushButton('Menu')
        self.menuBtn.setStyleSheet('font-size: 12pt;')
        self.menuBtn.clicked.connect(self.openMenuDialog)
        leftLayout.addWidget(self.menuBtn)
        self.settingsBtn = QPushButton('Settings')
        self.settingsBtn.setStyleSheet('font-size: 12pt;')
        self.settingsBtn.clicked.connect(self.openSettings)
        leftLayout.addWidget(self.settingsBtn)
        mainLayout.addLayout(leftLayout, 1)  # Stretchable left
        rightLayout = QVBoxLayout()
        self.nameLbl = QLabel('Meowdy!')
        self.nameLbl.setStyleSheet('font-size: 12pt; color: #555;')
        self.infoLbl = QLabel('TOTP code:')
        self.infoLbl.setStyleSheet('font-size: 16pt;')
        self.codeLbl = QLabel('------')
        self.codeLbl.setStyleSheet("font-size: 40pt; color: #e75480; font-weight: bold;")
        self.expireLbl = QLabel(' ')
        self.expireLbl.setStyleSheet('font-size: 14pt;')
        self.copyBtn = QPushButton('Copy Code')
        self.copyBtn.setStyleSheet('font-size: 12pt;')
        self.copyBtn.clicked.connect(self.copyCode)
        self.clipboardCountdownLbl = QLabel()
        self.clipboardCountdownLbl.setStyleSheet('font-size: 12pt; color: #888;')
        self.clipboardClearedLbl = QLabel()
        self.clipboardClearedLbl.setStyleSheet('font-size: 12pt; color: #4caf50;')
        self.clipboardClearedLbl.hide()
        rightLayout.addWidget(self.nameLbl)
        rightLayout.addWidget(self.infoLbl)
        rightLayout.addWidget(self.codeLbl)
        rightLayout.addWidget(self.expireLbl)
        rightLayout.addWidget(self.copyBtn)
        rightLayout.addWidget(self.clipboardCountdownLbl)
        rightLayout.addWidget(self.clipboardClearedLbl)
        rightWidget = QWidget()
        rightWidget.setLayout(rightLayout)
        rightWidget.setMaximumWidth(400)
        mainLayout.addWidget(rightWidget, 0)  # Fixed right
        self.setLayout(mainLayout)
        self.resize(660, 380)  # Set larger default window size
        # Always start with blank placeholder
        self.totp = None
        self.currentLabel = None
        self.nameLbl.setText('Meowdy!')
        self.codeLbl.setText('------')
        self.expireLbl.setText(' ')
        QTimer.singleShot(3000, self.refreshAccounts)
        self.refreshAccounts()

    def refreshAccounts(self):
        if self.accountTree is not None:
            self.accountTree.clear()
        bullet = '●'
        for folder, entries in self.secrets.items():
            folderItem = QTreeWidgetItem([str(folder), ''])
            font = folderItem.font(0)
            font.setBold(True)
            font.setPointSize(12)
            folderItem.setFont(0, font)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if not isDummyEntry(entry):
                    acctItem = QTreeWidgetItem([bullet, str(entry['label'])])
                    acctFont = acctItem.font(0)
                    acctFont.setPointSize(14)
                    acctItem.setFont(0, acctFont)
                    acctItem.setForeground(0, Qt.gray)
                    acctItem.setForeground(1, Qt.darkMagenta)
                    folderItem.addChild(acctItem)
            if self.accountTree is not None:
                self.accountTree.addTopLevelItem(folderItem)
        if self.accountTree is not None:
            self.accountTree.expandAll()
        # Apply custom stylesheet for grey and pink, with borders for separation
        self.accountTree.setStyleSheet('''
            QTreeWidget { background: #f7f7fa; border: none; }
            QTreeWidget::item { height: 28px; border: 1px solid #eee; border-radius: 6px; margin: 2px; }
            QTreeWidget::item:selected { background: #ffe4ef; color: #e75480; border: 1.5px solid #e75480; }
            QTreeWidget::item:!selected { color: #222; }
            QTreeWidget::branch { background: none; border: none; }
            QTreeWidget::item:has-children { border: 2px solid #e75480; background: #f7f7fa; }
            QHeaderView::section { background: #f7f7fa; color: #e75480; font-weight: bold; border-bottom: 2px solid #e75480; }
        ''')
        # Select the first real account if any
        # if self.accountTree is not None:
        #     for i in range(self.accountTree.topLevelItemCount()):
        #         folderItem = self.accountTree.topLevelItem(i)
        #         for j in range(folderItem.childCount()):
        #             acctItem = folderItem.child(j)
        #             if acctItem.text(1):
        #                 self.accountTree.setCurrentItem(acctItem)
        #                 self.switchAccount(folderItem.text(0), acctItem.text(1))
        #                 return

    def accountSelected(self):
        if self.accountTree is not None:
            item = self.accountTree.currentItem()
            if item and item.parent():
                folder = item.parent().text(0)
                label = item.text(1)
                self.switchAccount(folder, label)

    def addAccount(self):
        if self.accountTree is not None:
            label, ok = QInputDialog.getText(self, 'Account Label', 'Enter a name for this account:')
            if not ok or not label:
                return
            secret, ok = QInputDialog.getText(self, 'Secret', 'Enter the TOTP secret:')
            if not ok or not secret:
                return
            folder, ok = QInputDialog.getText(self, 'Folder', 'Enter folder name:')
            if not ok or not folder:
                return
            entry = {"label": label, "secret": secret, "dummy": False}
            if folder not in self.secrets:
                self.secrets[folder] = []
            self.secrets[folder].append(entry)
            self.saveSecrets()
            self.refreshAccounts()

    def deleteAccount(self):
        if self.accountTree is not None:
            item = self.accountTree.currentItem()
            if not item or not item.parent():
                return
            folder = item.parent().text(0)
            label = item.text(1)
            confirm = QMessageBox.question(self, 'Delete Account', f'Delete account "{label}" from folder "{folder}"?', QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                entries = self.secrets[folder]
                idx = next((i for i, e in enumerate(entries) if isinstance(e, dict) and e['label'] == label and not isDummyEntry(e)), None)
                if idx is not None:
                    del entries[idx]
                    self.saveSecrets()
                    self.refreshAccounts()

    def switchAccount(self, folder, label):
        entries = self.secrets[folder]
        entry = next((e for e in entries if isinstance(e, dict) and e['label'] == label and not isDummyEntry(e)), None)
        if entry:
            self.totp = pyotp.TOTP(entry['secret'])
            self.currentLabel = entry['label']
            self.updateTotp()
        else:
            self.totp = None
            self.nameLbl.setText('Meowdy!')
            self.codeLbl.setText('------')
            self.expireLbl.setText(' ')

    def updateTotp(self):
        if not self.totp:
            self.nameLbl.setText('Meowdy!')
            self.codeLbl.setText('------')
            self.expireLbl.setText(' ')
            return
        code = self.totp.now()
        secs = 30 - int(time.time()) % 30
        self.nameLbl.setText(f'{self.currentLabel}')
        self.codeLbl.setText(code)
        self.expireLbl.setText(f'Expires in: {secs}s')

    def scanQrFromScreen(self):
        self.infoLbl.setText('Scanning... mewmews!')
        img = ImageGrab.grab()
        imgNp = np.array(img)
        imgBgr = cv2.cvtColor(imgNp, cv2.COLOR_RGB2BGR)
        qrCodes = decode(imgBgr)
        if qrCodes:
            for qr in qrCodes:
                data = qr.data.decode('utf-8')
                if data.startswith('otpauth://'):
                    try:
                        otp = pyotp.parse_uri(data)
                        label, ok = QInputDialog.getText(self, 'Account Label', 'Enter a name for this account:')
                        if not ok or not label:
                            self.infoLbl.setText('Cancelled!')
                            return
                        folder, ok = QInputDialog.getText(self, 'Folder', 'Enter folder name:')
                        if not ok or not folder:
                            self.infoLbl.setText('Cancelled!')
                            return
                        entry = {"label": label, "secret": otp.secret, "dummy": False}
                        if folder not in self.secrets:
                            self.secrets[folder] = []
                        self.secrets[folder].append(entry)
                        self.saveSecrets()
                        self.refreshAccounts()
                        self.infoLbl.setText("QR scanned & imported! :3")
                        return
                    except Exception:
                        self.infoLbl.setText("Invalid QR code!")
                        return
            self.infoLbl.setText('No valid OTP QR code found!')
            QTimer.singleShot(5000, lambda: self.infoLbl.setText(''))
        else:
            self.infoLbl.setText("Unable to find QR code!")
            QTimer.singleShot(5000, lambda: self.infoLbl.setText(''))

    def copyCode(self):
        if self.totp:
            QApplication.clipboard().setText(self.codeLbl.text())
            self.clipboardCountdown = self.clipboardTimeout
            self.updateClipboardCountdown()
            self.clipboardCountdownLbl.show()
            self.clipboardClearedLbl.hide()
            self.clipboardTimer.start(self.clipboardTimeout * 1000)
            self.clipboardCountdownTimer.start(1000)

    def updateClipboardCountdown(self):
        if self.clipboardCountdown > 0:
            self.clipboardCountdownLbl.setText(f'Clipboard will clear in {self.clipboardCountdown}s')
            self.clipboardCountdown -= 1
        else:
            self.clipboardCountdownLbl.setText('')
            self.clipboardCountdownTimer.stop()

    def clearClipboard(self):
        QApplication.clipboard().clear()
        self.clipboardClearedLbl.setText('Clipboard cleared!')
        self.clipboardClearedLbl.show()
        self.clipboardCountdownLbl.setText('')
        self.clipboardCountdownTimer.stop()
        QTimer.singleShot(3000, self.clipboardClearedLbl.hide)

    def openSettings(self):
        dlg = SettingsDialog(self, self.lockTimeout, self.clipboardTimeout)
        if dlg.exec_():
            lockTimeout, clipboardTimeout = dlg.getConfigs()
            self.lockTimeout = lockTimeout
            self.clipboardTimeout = clipboardTimeout

    # Remove editEmailConfig, saveEmailConfig, loadEmailConfig
    # Remove editSSHConfig, saveSSHConfig, loadSSHConfig

    # Legacy
    def isSSH3faEnabled(self):
        return False # No SSH config, so it's always disabled

    def send3faCode(self, code):
        return False # No email config, so it's always disabled

    def setSensitiveUiVisible(self, visible):
        if self.accountTree is not None:
            self.accountTree.setVisible(visible)
        if self.codeLbl is not None:
            self.codeLbl.setVisible(visible)
        if self.expireLbl is not None:
            self.expireLbl.setVisible(visible)
        if self.copyBtn is not None:
            self.copyBtn.setVisible(visible)
        if self.clipboardCountdownLbl is not None:
            self.clipboardCountdownLbl.setVisible(visible)
        if self.clipboardClearedLbl is not None:
            self.clipboardClearedLbl.setVisible(visible)
        if self.infoLbl is not None:
            self.infoLbl.setVisible(visible)

    def importGoogleAuthExport(self):
        if OtpMigration_pb2 is None:
            QMessageBox.warning(self, 'Missing Dependency', 'addtl/OtpMigration_pb2 not found!')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import Google Auth Export', '', 'Text Files (*.txt);;All Files (*)')
        if not path:
            return
        try:
            with open(path, 'r') as f:
                uri = f.read().strip()
            if not uri.startswith('otpauth-migration://'):
                QMessageBox.warning(self, 'Import Error', 'File does not contain a valid otpauth-migration URI!')
                return
            data = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query).get('data', [None])[0]
            if not data:
                QMessageBox.warning(self, 'Import Error', 'No data param in URI!')
                return
            raw = base64.urlsafe_b64decode(data + '==')
            payload = OtpMigration_pb2.MigrationPayload()
            payload.ParseFromString(raw)
            added = 0
            if 'Imports' not in self.secrets:
                self.secrets['Imports'] = []
            for acc in payload.otp_parameters:
                secret = base64.b32encode(acc.secret).decode('utf-8').replace('=', '')
                label = acc.name if hasattr(acc, 'name') and acc.name else f'Account {added+1}'
                entry = {"label": label, "secret": secret, "dummy": False}
                self.secrets['Imports'].append(entry)
                added += 1
            self.saveSecrets()
            self.refreshAccounts()
            QMessageBox.information(self, 'Import Complete', f'Imported {added} account(s) from Google Auth Export!')
        except Exception as e:
            QMessageBox.warning(self, 'Import Error', f'Failed to import: {e}')

    def openOrganizeDialog(self):
        dlg = OrganizeAccountsDialog(self)
        dlg.exec_()
        self.refreshAccounts()

    def switchAccount(self, folder, label):
        entries = self.secrets[folder]
        entry = next((e for e in entries if isinstance(e, dict) and e['label'] == label and not isDummyEntry(e)), None)
        if entry:
            self.totp = pyotp.TOTP(entry['secret'])
            self.currentLabel = entry['label']
            self.updateTotp()
        else:
            self.totp = None
            self.nameLbl.setText('Meowdy!')
            self.codeLbl.setText('------')
            self.expireLbl.setText('')

    def saveSecretsFlat(self):
        # Save flat secrets for backwards compatibility
        data = encryptData(json.dumps({e['label']: e['secret'] for e in self.flatSecrets}), self.key)
        with open(SECRETS_FILE, 'wb') as f:
            f.write(data)

    def openMenuDialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle('Menu')
        layout = QVBoxLayout(dlg)
        addBtn = QPushButton('Add Account')
        addBtn.clicked.connect(lambda: [dlg.accept(), self.addAccount()])
        delBtn = QPushButton('Delete Account')
        delBtn.clicked.connect(lambda: [dlg.accept(), self.deleteAccount()])
        importBtn = QPushButton('Import Google Auth Export')
        importBtn.clicked.connect(lambda: [dlg.accept(), self.showGoogleAuthHelp()])
        organizeBtn = QPushButton('Organize Accounts')
        organizeBtn.clicked.connect(lambda: [dlg.accept(), self.openOrganizeDialog()])
        backupExportBtn = QPushButton('Export Encrypted Backup')
        backupExportBtn.clicked.connect(lambda: [dlg.accept(), self.exportBackup()])
        backupImportBtn = QPushButton('Import Encrypted Backup')
        backupImportBtn.clicked.connect(lambda: [dlg.accept(), self.importBackup()])
        layout.addWidget(addBtn)
        layout.addWidget(delBtn)
        layout.addWidget(importBtn)
        layout.addWidget(organizeBtn)
        layout.addWidget(backupExportBtn)
        layout.addWidget(backupImportBtn)
        dlg.setLayout(layout)
        dlg.exec_()

    def showGoogleAuthHelp(self):
        msg = QMessageBox(self)
        msg.setWindowTitle('Import Google Auth Export')
        msg.setText('To import from Google Authenticator:\n1. Export your accounts from Google Auth as a .txt file.\n2. Click OK and select the file to import.\nYour accounts will be added automatically!')
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        if msg.exec_() == QMessageBox.Ok:
            self.importGoogleAuthExport()

    def exportBackup(self):
        if not hasattr(self, 'secrets') or not hasattr(self, 'key'):
            QMessageBox.warning(self, 'Export Error', 'No secrets to export!')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export Encrypted Backup', '', 'Encrypted Files (*.enc)')
        if not path:
            return
        data = json.dumps(self.secrets)
        enc = encryptData(data, self.key)
        with open(path, 'wb') as f:
            f.write(enc)
        QMessageBox.information(self, 'Export Complete', 'Encrypted backup exported successfully!')

    def importBackup(self):
        if not hasattr(self, 'key'):
            QMessageBox.warning(self, 'Import Error', 'No key available!')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import Encrypted Backup', '', 'Encrypted Files (*.enc)')
        if not path:
            return
        with open(path, 'rb') as f:
            enc = f.read()
        try:
            data = decryptData(enc, self.key)
            self.secrets = json.loads(data)
            self.refreshAccounts()
            QMessageBox.information(self, 'Import Complete', 'Backup imported successfully!')
        except Exception:
            QMessageBox.warning(self, 'Import Error', 'Failed to import backup!')

# --- Organize Accounts Dialog ---
from PyQt5.QtWidgets import QDialog, QListWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QInputDialog
class OrganizeAccountsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle('Organize Accounts')
        self.parentWidget = parent
        layout = QVBoxLayout(self)
        self.folderList = QListWidget()
        self.accountList = QListWidget()
        layout.addWidget(QLabel('Folders:'))
        layout.addWidget(self.folderList)
        layout.addWidget(QLabel('Accounts in selected folder:'))
        layout.addWidget(self.accountList)
        btnLayout = QHBoxLayout()
        self.moveBtn = QPushButton('Move to Folder...')
        self.moveBtn.clicked.connect(self.moveAccount)
        btnLayout.addWidget(self.moveBtn)
        self.newFolderBtn = QPushButton('New Folder')
        self.newFolderBtn.clicked.connect(self.newFolder)
        btnLayout.addWidget(self.newFolderBtn)
        layout.addLayout(btnLayout)
        self.setLayout(layout)
        self.folderList.currentItemChanged.connect(self.updateAccountList)
        self.loadFolders()
    def loadFolders(self):
        self.folderList.clear()
        self.folders = list(self.parentWidget.secrets.keys()) if self.parentWidget.secrets else ['Default']
        for folder in self.folders:
            self.folderList.addItem(folder)
        if self.folders:
            self.folderList.setCurrentRow(0)
    def updateAccountList(self):
        self.accountList.clear()
        folder = self.folderList.currentItem().text() if self.folderList.currentItem() else None
        if not folder:
            return
        entries = self.parentWidget.secrets.get(folder, [])
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if not isDummyEntry(entry):
                self.accountList.addItem(entry['label'])
    def moveAccount(self):
        folder = self.folderList.currentItem().text() if self.folderList.currentItem() else None
        idx = self.accountList.currentRow()
        if not folder or idx < 0:
            return
        label = self.accountList.item(idx).text()
        # Find and remove from current folder
        for f in (self.parentWidget.secrets if self.parentWidget.secrets else ['Default']):
            entries = self.parentWidget.secrets.get(f, [])
            for i, entry in enumerate(entries):
                if entry['label'] == label:
                    entryToMove = entries.pop(i)
                    break
        # Ask for new folder
        newFolder, ok = QInputDialog.getText(self, 'Move to Folder', 'Enter folder name:')
        if not ok or not newFolder:
            return
        if newFolder not in self.parentWidget.secrets:
            self.parentWidget.secrets[newFolder] = []
        self.parentWidget.secrets[newFolder].append(entryToMove)
        self.parentWidget.saveSecrets()
        self.loadFolders()
        self.updateAccountList()
    def newFolder(self):
        folder, ok = QInputDialog.getText(self, 'New Folder', 'Enter new folder name:')
        if not ok or not folder:
            return
        if folder not in self.parentWidget.secrets:
            self.parentWidget.secrets[folder] = []
        self.loadFolders()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(iconPath))

    # First launch timeout prompt
    firstLaunch = not os.path.exists(MASTER_HASH_FILE)
    lockTimeout, clipboardTimeout = 60, 10
    if firstLaunch:
        dlg = QDialog()
        dlg.setWindowTitle('First Launch Setup')
        layout = QFormLayout(dlg)
        lockBox = QComboBox()
        lockBox.addItems([str(x) for x in [30, 60, 120, 300, 600, 900, 1800]])
        lockBox.setCurrentText('60')
        clipboardBox = QComboBox()
        clipboardBox.addItems([str(x) for x in [5, 10, 20, 30, 60]])
        clipboardBox.setCurrentText('10')
        layout.addRow('Auto-lock timeout (seconds):', lockBox)
        layout.addRow('Clipboard clear timeout (seconds):', clipboardBox)
        okBtn = QPushButton('OK')
        okBtn.clicked.connect(dlg.accept)
        layout.addWidget(okBtn)
        dlg.setLayout(layout)
        if dlg.exec_() == QDialog.Accepted:
            lockTimeout = int(lockBox.currentText())
            clipboardTimeout = int(clipboardBox.currentText())

    win = Ruby2FA()
    win.setWindowIcon(QIcon(iconPath))
    if firstLaunch:
        win.lockTimeout = lockTimeout
        win.clipboardTimeout = clipboardTimeout
    win.show()

    sys.exit(app.exec_())

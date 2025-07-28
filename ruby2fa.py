import sys
import pyotp
import time
import cv2
import numpy as np
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QInputDialog, QLineEdit, QComboBox, QListWidget, QListWidgetItem, QMessageBox, QDialog, QFormLayout, QCheckBox, QTabWidget
from PyQt5.QtCore import QTimer, QEvent
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

SECRETS_FILE = 'secrets.json.enc'
MASTER_HASH_FILE = 'master.hash'
PBKDF2_ITER = 200_000

# --- Encryption helpers ---
def deriveKey(password):
    # derive 32-byte key from password
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encryptData(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decryptData(token, key):
    f = Fernet(key)
    return f.decrypt(token).decode()

def pbkdf2Hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITER)

# --- Main App ---
class EmailConfigDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle('Email 3FA Settings')
        layout = QFormLayout(self)
        self.smtpServer = QLineEdit(config.get('smtpServer', '') if config else '')
        self.smtpPort = QLineEdit(str(config.get('smtpPort', 587)) if config else '587')
        self.email = QLineEdit(config.get('email', '') if config else '')
        self.emailPass = QLineEdit(config.get('emailPass', '') if config else '')
        self.emailPass.setEchoMode(QLineEdit.Password)
        self.enable3fa = QComboBox()
        self.enable3fa.addItems(['Disabled', 'Enabled'])
        if config and config.get('enabled', False):
            self.enable3fa.setCurrentIndex(1)
        layout.addRow('Enable Email 3FA:', self.enable3fa)
        layout.addRow('SMTP Server:', self.smtpServer)
        layout.addRow('SMTP Port:', self.smtpPort)
        layout.addRow('Email Address:', self.email)
        layout.addRow('Email Password:', self.emailPass)
        btns = QHBoxLayout()
        self.okBtn = QPushButton('OK')
        self.okBtn.clicked.connect(self.accept)
        self.cancelBtn = QPushButton('Cancel')
        self.cancelBtn.clicked.connect(self.reject)
        btns.addWidget(self.okBtn)
        btns.addWidget(self.cancelBtn)
        layout.addRow(btns)
    def getConfig(self):
        return {
            'enabled': self.enable3fa.currentIndex() == 1,
            'smtpServer': self.smtpServer.text(),
            'smtpPort': int(self.smtpPort.text()),
            'email': self.email.text(),
            'emailPass': self.emailPass.text()
        }

class SSHConfigDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle('SSH Agent 3FA Settings')
        layout = QFormLayout(self)
        self.enable3fa = QComboBox()
        self.enable3fa.addItems(['Disabled', 'Enabled'])
        if config and config.get('enabled', False):
            self.enable3fa.setCurrentIndex(1)
        layout.addRow('Enable SSH Agent 3FA:', self.enable3fa)
        # Placeholder for future SSH key selection
        btns = QHBoxLayout()
        self.okBtn = QPushButton('OK')
        self.okBtn.clicked.connect(self.accept)
        self.cancelBtn = QPushButton('Cancel')
        self.cancelBtn.clicked.connect(self.reject)
        btns.addWidget(self.okBtn)
        btns.addWidget(self.cancelBtn)
        layout.addRow(btns)
    def getConfig(self):
        return {
            'enabled': self.enable3fa.currentIndex() == 1
        }

class SettingsDialog(QDialog):
    def __init__(self, parent=None, emailConfig=None, sshConfig=None, lockTimeout=60, clipboardTimeout=10):
        super().__init__(parent)
        self.setWindowTitle('Settings')
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.emailTab = EmailConfigDialog(self, emailConfig)
        self.sshTab = SSHConfigDialog(self, sshConfig)
        self.tabs.addTab(self.emailTab, 'Email 3FA')
        self.tabs.addTab(self.sshTab, 'SSH Agent 3FA')
        layout.addWidget(self.tabs)
        self.lockTimeoutBox = QComboBox()
        self.lockTimeoutBox.addItems([str(x) for x in [60, 120, 300, 600, 900, 1800]])
        self.lockTimeoutBox.setCurrentText(str(lockTimeout))
        layout.addWidget(QLabel('Auto-lock timeout (seconds):'))
        layout.addWidget(self.lockTimeoutBox)
        self.clipboardTimeoutBox = QComboBox()
        self.clipboardTimeoutBox.addItems([str(x) for x in [10, 15, 20, 25, 30]])
        self.clipboardTimeoutBox.setCurrentText(str(clipboardTimeout))
        layout.addWidget(QLabel('Clipboard clear timeout (seconds):'))
        layout.addWidget(self.clipboardTimeoutBox)
        # Backup/restore buttons
        backupLayout = QHBoxLayout()
        self.exportBtn = QPushButton('Export Encrypted Backup')
        self.exportBtn.clicked.connect(self.exportBackup)
        self.importBtn = QPushButton('Import Encrypted Backup')
        self.importBtn.clicked.connect(self.importBackup)
        backupLayout.addWidget(self.exportBtn)
        backupLayout.addWidget(self.importBtn)
        layout.addLayout(backupLayout)
        btnLayout = QHBoxLayout()
        self.okBtn = QPushButton('OK')
        self.okBtn.clicked.connect(self.accept)
        self.cancelBtn = QPushButton('Cancel')
        self.cancelBtn.clicked.connect(self.reject)
        btnLayout.addWidget(self.okBtn)
        btnLayout.addWidget(self.cancelBtn)
        layout.addLayout(btnLayout)
        self.parentWidget = parent
    def getConfigs(self):
        return (self.emailTab.getConfig(), self.sshTab.getConfig(), int(self.lockTimeoutBox.currentText()), int(self.clipboardTimeoutBox.currentText()))
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
        self.secrets = {}
        self.totp = None
        self.currentLabel = None
        self.key = None
        self.gitWarning = self.checkGitTracked()
        self.lockTimeout = 60
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
        self.emailConfig = None
        self.loadEmailConfig()
        self.sshConfig = None
        self.loadSSHConfig()

    def eventFilter(self, obj, event):
        if event.type() in [QEvent.MouseMove, QEvent.KeyPress, QEvent.MouseButtonPress]:
            self.lastActivity = time.time()
        return super().eventFilter(obj, event)

    def checkAutoLock(self):
        if time.time() - self.lastActivity > self.lockTimeout:
            self.lockApp()

    def lockApp(self):
        # Hide sensitive info
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
        # Restore sensitive info
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
                    continue  # wrong password, ask again
            else:
                # first time setup, store salt+hash
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
        data = json.dumps(self.secrets)
        enc = encryptData(data, self.key)
        with open(SECRETS_FILE, 'wb') as f:
            f.write(enc)

    def initUi(self):
        self.setWindowTitle('Ruby2FA :3')
        mainLayout = QHBoxLayout()
        # Left: Account list and actions
        leftLayout = QVBoxLayout()
        if self.gitWarning:
            warnLbl = QLabel(f'Oh my whiskers! Security warning: {", ".join(self.gitWarning)} is tracked by git!')
            warnLbl.setStyleSheet('color: red; font-weight: bold; font-size: 14pt;')
            leftLayout.addWidget(warnLbl)
        self.accountList = QListWidget()
        self.accountList.setStyleSheet('font-size: 14pt;')
        self.accountList.itemSelectionChanged.connect(self.accountSelected)
        leftLayout.addWidget(self.accountList)
        btnLayout = QHBoxLayout()
        self.addBtn = QPushButton('Add')
        self.addBtn.setStyleSheet('font-size: 12pt;')
        self.addBtn.clicked.connect(self.addAccount)
        self.delBtn = QPushButton('Delete')
        self.delBtn.setStyleSheet('font-size: 12pt;')
        self.delBtn.clicked.connect(self.deleteAccount)
        self.scanBtn = QPushButton('Scan QR')
        self.scanBtn.setStyleSheet('font-size: 12pt;')
        self.scanBtn.clicked.connect(self.scanQrFromScreen)
        btnLayout.addWidget(self.addBtn)
        btnLayout.addWidget(self.delBtn)
        btnLayout.addWidget(self.scanBtn)
        leftLayout.addLayout(btnLayout)
        self.settingsBtn = QPushButton('Settings')
        self.settingsBtn.setStyleSheet('font-size: 12pt;')
        self.settingsBtn.clicked.connect(self.openSettings)
        leftLayout.addWidget(self.settingsBtn)
        mainLayout.addLayout(leftLayout, 1)
        # Right: Code display and details
        rightLayout = QVBoxLayout()
        self.infoLbl = QLabel('2FA code:')
        self.infoLbl.setStyleSheet('font-size: 16pt;')
        self.codeLbl = QLabel('------')
        self.codeLbl.setStyleSheet("font-size: 40pt; color: #e75480; font-weight: bold;")
        self.expireLbl = QLabel('Expires in: 30s')
        self.expireLbl.setStyleSheet('font-size: 14pt;')
        self.copyBtn = QPushButton('Copy Code')
        self.copyBtn.setStyleSheet('font-size: 12pt;')
        self.copyBtn.clicked.connect(self.copyCode)
        self.clipboardCountdownLbl = QLabel()
        self.clipboardCountdownLbl.setStyleSheet('font-size: 12pt; color: #888;')
        self.clipboardClearedLbl = QLabel()
        self.clipboardClearedLbl.setStyleSheet('font-size: 12pt; color: #4caf50;')
        self.clipboardClearedLbl.hide()
        rightLayout.addWidget(self.infoLbl)
        rightLayout.addWidget(self.codeLbl)
        rightLayout.addWidget(self.expireLbl)
        rightLayout.addWidget(self.copyBtn)
        rightLayout.addWidget(self.clipboardCountdownLbl)
        rightLayout.addWidget(self.clipboardClearedLbl)
        rightLayout.addStretch(1)
        mainLayout.addLayout(rightLayout, 2)
        self.setLayout(mainLayout)
        self.refreshAccounts()

    def refreshAccounts(self):
        self.accountList.clear()
        for label in self.secrets:
            self.accountList.addItem(label)
        if self.secrets:
            self.accountList.setCurrentRow(0)
            self.switchAccount(0)
        else:
            self.totp = None
            self.codeLbl.setText('------')
            self.expireLbl.setText('No accounts!')

    def accountSelected(self):
        idx = self.accountList.currentRow()
        self.switchAccount(idx)

    def addAccount(self):
        label, ok = QInputDialog.getText(self, 'Account Label', 'Enter a name for this account:')
        if not ok or not label:
            return
        secret, ok = QInputDialog.getText(self, 'Secret', 'Enter the TOTP secret:')
        if not ok or not secret:
            return
        self.secrets[label] = secret
        self.saveSecrets()
        self.refreshAccounts()

    def deleteAccount(self):
        idx = self.accountList.currentRow()
        if idx < 0:
            return
        label = self.accountList.item(idx).text()
        confirm = QMessageBox.question(self, 'Delete Account', f'Delete account "{label}"?', QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            del self.secrets[label]
            self.saveSecrets()
            self.refreshAccounts()

    def switchAccount(self, idx):
        if idx < 0 or not self.secrets:
            self.totp = None
            self.codeLbl.setText('------')
            self.expireLbl.setText('No accounts!')
            return
        label = self.accountList.item(idx).text()
        secret = self.secrets[label]
        self.totp = pyotp.TOTP(secret)
        self.currentLabel = label
        self.updateTotp()

    def updateTotp(self):
        if not self.totp:
            self.codeLbl.setText('------')
            self.expireLbl.setText('No accounts!')
            return
        code = self.totp.now()
        secs = 30 - int(time.time()) % 30
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
                        self.secrets[label] = otp.secret
                        self.saveSecrets()
                        self.refreshAccounts()
                        self.infoLbl.setText('QR scanned & saved! :3')
                        return
                    except Exception:
                        self.infoLbl.setText('Invalid QR! mewmews')
                        return
            self.infoLbl.setText('No valid OTP QR found!')
        else:
            self.infoLbl.setText('No QR found! mewmews')

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
        dlg = SettingsDialog(self, getattr(self, 'emailConfig', None), getattr(self, 'sshConfig', None), self.lockTimeout, self.clipboardTimeout)
        if dlg.exec_():
            emailCfg, sshCfg, lockTimeout, clipboardTimeout = dlg.getConfigs()
            self.emailConfig = emailCfg
            self.saveEmailConfig()
            self.sshConfig = sshCfg
            self.saveSSHConfig()
            self.lockTimeout = lockTimeout
            self.clipboardTimeout = clipboardTimeout

    def editEmailConfig(self):
        cfg = getattr(self, 'emailConfig', None)
        dlg = EmailConfigDialog(self, cfg)
        if dlg.exec_():
            self.emailConfig = dlg.getConfig()
            self.saveEmailConfig()

    def saveEmailConfig(self):
        # Save email config encrypted with master key
        if not hasattr(self, 'emailConfig') or not self.key:
            return
        data = encryptData(json.dumps(self.emailConfig), self.key)
        with open('email3fa.enc', 'wb') as f:
            f.write(data)

    def loadEmailConfig(self):
        try:
            with open('email3fa.enc', 'rb') as f:
                data = f.read()
            self.emailConfig = json.loads(decryptData(data, self.key))
        except Exception:
            self.emailConfig = None

    def editSSHConfig(self):
        cfg = getattr(self, 'sshConfig', None)
        dlg = SSHConfigDialog(self, cfg)
        if dlg.exec_():
            self.sshConfig = dlg.getConfig()
            self.saveSSHConfig()

    def saveSSHConfig(self):
        if not hasattr(self, 'sshConfig') or not self.key:
            return
        data = encryptData(json.dumps(self.sshConfig), self.key)
        with open('ssh3fa.enc', 'wb') as f:
            f.write(data)

    def loadSSHConfig(self):
        try:
            with open('ssh3fa.enc', 'rb') as f:
                data = f.read()
            self.sshConfig = json.loads(decryptData(data, self.key))
        except Exception:
            self.sshConfig = None

    def isSSH3faEnabled(self):
        return hasattr(self, 'sshConfig') and self.sshConfig and self.sshConfig.get('enabled', False)

    def send3faCode(self, code):
        if not hasattr(self, 'emailConfig') or not self.emailConfig:
            return False
        cfg = self.emailConfig
        if not cfg.get('enabled', False):
            return False # Email 3FA is disabled
        msg = MIMEText(f'Your Ruby2FA 3FA code is: {code}')
        msg['Subject'] = 'Your Ruby2FA 3FA Code'
        msg['From'] = cfg['email']
        msg['To'] = cfg['email']
        try:
            with smtplib.SMTP(cfg['smtpServer'], cfg['smtpPort']) as server:
                server.starttls()
                server.login(cfg['email'], cfg['emailPass'])
                server.sendmail(cfg['email'], [cfg['email']], msg.as_string())
            return True
        except Exception as e:
            QMessageBox.warning(self, 'Email Error', f'Failed to send 3FA code: {e}')
            return False

    def setSensitiveUiVisible(self, visible):
        # Hide or show sensitive widgets
        if hasattr(self, 'accountList'):
            self.accountList.setVisible(visible)
        if hasattr(self, 'codeLbl'):
            self.codeLbl.setVisible(visible)
        if hasattr(self, 'expireLbl'):
            self.expireLbl.setVisible(visible)
        if hasattr(self, 'copyBtn'):
            self.copyBtn.setVisible(visible)
        if hasattr(self, 'clipboardCountdownLbl'):
            self.clipboardCountdownLbl.setVisible(visible)
        if hasattr(self, 'clipboardClearedLbl'):
            self.clipboardClearedLbl.setVisible(visible)
        if hasattr(self, 'infoLbl'):
            self.infoLbl.setVisible(visible)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = Ruby2FA()
    win.show()
    sys.exit(app.exec_())

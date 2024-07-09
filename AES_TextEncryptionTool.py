import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QLineEdit, QMessageBox


class AESCipher:
    def __init__(self, password):
        # Derive a 256-bit key using Scrypt
        self.key = scrypt(password, salt=b'saltysalt', key_len=32, N=2**14, r=8, p=1)

    def encrypt(self, message):
        # Generate a random initialization vector
        iv = get_random_bytes(AES.block_size)

        # Create AES cipher with CBC mode and PKCS7 padding
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Encrypt the message
        ciphertext = cipher.encrypt(self._pad(message))

        # Return base64 encoded cipher text and IV
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_message):
        # Decode base64 and extract IV
        ciphertext = base64.b64decode(encrypted_message)
        iv = ciphertext[:AES.block_size]

        # Create AES cipher with CBC mode and PKCS7 padding
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Decrypt the message and strip PKCS7 padding
        decrypted_message = self._unpad(cipher.decrypt(ciphertext[AES.block_size:])).decode('utf-8')

        return decrypted_message

    def _pad(self, s):
        # PKCS7 padding
        block_size = AES.block_size
        padding = block_size - len(s) % block_size
        return s + bytes([padding]) * padding

    def _unpad(self, s):
        # Remove PKCS7 padding
        return s[:-s[-1]]


class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('AES Encryption Tool')
        self.setGeometry(100, 100, 500, 300)

        layout = QVBoxLayout()

        # Password input
        password_label = QLabel('Enter Encryption Password:')
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_label)
        layout.addWidget(self.password_entry)

        # Text input area
        text_label = QLabel('Enter Text to Encrypt/Decrypt:')
        self.text_input = QTextEdit()
        layout.addWidget(text_label)
        layout.addWidget(self.text_input)

        # Buttons
        button_layout = QHBoxLayout()
        encrypt_button = QPushButton('Encrypt', self)
        encrypt_button.clicked.connect(self.encrypt_text)
        button_layout.addWidget(encrypt_button)

        decrypt_button = QPushButton('Decrypt', self)
        decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(decrypt_button)

        layout.addLayout(button_layout)

        # Output area (using QTextEdit for copy functionality)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)  # Set to read-only to prevent editing
        layout.addWidget(self.output_text)

        self.setLayout(layout)
        self.show()

    def encrypt_text(self):
        password = self.password_entry.text().encode('utf-8')
        aes_cipher = AESCipher(password)
        plaintext = self.text_input.toPlainText().encode('utf-8')  # Convert to bytes
        encrypted_message = aes_cipher.encrypt(plaintext)
        self.output_text.setPlainText(encrypted_message)  # Set encrypted message in QTextEdit

    def decrypt_text(self):
        password = self.password_entry.text().encode('utf-8')
        aes_cipher = AESCipher(password)
        encrypted_message = self.output_text.toPlainText().strip()  # Get encrypted message from QTextEdit
        decrypted_message = aes_cipher.decrypt(encrypted_message)
        self.output_text.setPlainText(decrypted_message)  # Display decrypted message in QTextEdit


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptionApp()
    sys.exit(app.exec_())

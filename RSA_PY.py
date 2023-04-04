import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QMessageBox, QFileDialog, QAction
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import qdarkstyle

class CryptoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Crittografia RSA")
        self.setWindowIcon(QIcon("cifratura.png"))

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        input_label = QLabel("Inserisci il testo da cifrare:")
        layout.addWidget(input_label)

        self.input_text = QTextEdit()
        layout.addWidget(self.input_text)

        button_layout = QHBoxLayout()
        cifra_button = QPushButton("Cifra")
        cifra_button.clicked.connect(self.cifra)
        button_layout.addWidget(cifra_button)

        decifra_button = QPushButton("Decifra")
        decifra_button.clicked.connect(self.decifra)
        button_layout.addWidget(decifra_button)

        layout.addLayout(button_layout)

        output_label = QLabel("Output:")
        layout.addWidget(output_label)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        self.private_key = None

        # File menu
        file_menu = self.menuBar().addMenu("File")

        save_key_action = QAction("Salva chiave privata", self)
        save_key_action.setShortcut("Ctrl+S")
        save_key_action.triggered.connect(self.salva_chiave)
        file_menu.addAction(save_key_action)

        # Style menu
        style_menu = self.menuBar().addMenu("Stile")

        default_style_action = QAction("Default", self)
        default_style_action.triggered.connect(self.default_style)
        style_menu.addAction(default_style_action)

        dark_style_action = QAction("Scuro", self)
        dark_style_action.triggered.connect(self.dark_style)
        style_menu.addAction(dark_style_action)

        # Set default style
        self.default_style()

    def cifra(self):
        message = self.input_text.toPlainText().encode()
        public_key, self.private_key = self.generate_keys()

        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.output_text.clear()
        self.output_text.insertPlainText(f"Il testo cifrato è:\n{ciphertext.hex()}\n")
        self.output_text.insertPlainText(f"La chiave privata per decifrare è salvata nel menu File.\n")

    def decifra(self):
        ciphertext_hex = self.output_text.toPlainText().split("\n")[1].strip()
        ciphertext = bytes.fromhex(ciphertext_hex)

        if self.private_key is None:
            self.show_error_message("Devi prima cifrare il testo!")
            return

        private_key = serialization.load_pem_private_key(
            self.private_key.encode(),
            password=None
        )

        try:
            message = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.output_text.clear()
            self.output_text.insertPlainText(f"Il testo decifrato è:\n{message.decode()}\n")
        except Exception as e:
            self.show_error_message(f"Errore nella decifratura: {e}")
    def decifra(self):
        ciphertext_hex = self.output_text.toPlainText().split("\n")[1].strip()
        ciphertext = bytes.fromhex(ciphertext_hex)

        if self.private_key is None:
            self.show_error_message("Devi prima cifrare il testo!")
            return

        private_key = serialization.load_pem_private_key(
        self.private_key.encode(),
        password=None
        )

        try:
            message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
            self.input_text.clear()
            self.input_text.insertPlainText(message.decode())
        except Exception as e:
            self.show_error_message(f"Impossibile decifrare il testo con la chiave privata corrente.\n{str(e)}")

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return public_key, private_key_pem.decode()

    def salva_chiave(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Salva chiave privata", "", "PEM Files (*.pem)")
        if file_path:
            if self.private_key is None:
                self.show_error_message("Non è stata generata alcuna chiave privata!")
                return

            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
                )

            with open(file_path, 'wb') as f:
                f.write(pem)
    def show_error_message(self, message):
        error_box = QMessageBox(self)
        error_box.setIcon(QMessageBox.Critical)
        error_box.setWindowTitle("Errore")
        error_box.setText(message)
        error_box.exec_()

    def default_style(self):
        self.setStyleSheet("")
        self.setPalette(QMainWindow().palette())

    def dark_style(self):
        self.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5'))
        self.setPalette(QMainWindow().palette())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    crypto_gui = CryptoGUI()
    crypto_gui.show()
    sys.exit(app.exec_())

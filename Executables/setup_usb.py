import sys
import os
import json
import uuid
import psutil
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QListWidget, QLabel, QMessageBox
)
from PySide6.QtCore import QThread, QObject, Signal, Slot
from PySide6.QtGui import QIcon

# --- Konfigurasi dari skrip asli ---
KEY_FILE_NAME = ".my_crypto_app_key"

# --- Path Konfigurasi Baru ---
# Dapatkan path absolut dari skrip ini
script_path = os.path.abspath(__file__)
# Dapatkan direktori tempat skrip ini berada
script_dir = os.path.dirname(script_path)
# Dapatkan direktori parent dari direktori skrip
parent_dir = os.path.dirname(script_dir)
# Tentukan path file konfigurasi di direktori parent
LOCAL_CONFIG_FILE = os.path.join(parent_dir, "auth/auth.config")

HARDCODED_SECRET = "ini-adalah-kunci-rahasia-saya-yang-sangat-panjang-12345"

# Konfigurasi PBKDF2 (key derivation)
SALT_SIZE = 16
KEY_SIZE = 32  # 256-bit key
ITERATIONS = 100000
HASH_ALG = "sha256"

# --- Fungsi Enkripsi/Dekripsi (Tidak berubah) ---
def encrypt_config(plain_text_key, password):
    """Mengenkripsi teks (kunci USB) menggunakan AES-GCM."""
    salt = get_random_bytes(SALT_SIZE)
    key = pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, ITERATIONS, KEY_SIZE)

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text_key.encode("utf-8"))

    encrypted_data = {
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }
    return json.dumps(encrypted_data).encode("utf-8")


def decrypt_config(encrypted_data_bytes, password):
    """Mendekripsi file config terenkripsi dan memverifikasi integritasnya."""
    try:
        encrypted_data = json.loads(encrypted_data_bytes.decode("utf-8"))
        salt = bytes.fromhex(encrypted_data["salt"])
        nonce = bytes.fromhex(encrypted_data["nonce"])
        tag = bytes.fromhex(encrypted_data["tag"])
        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])

        key = pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, ITERATIONS, KEY_SIZE)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain_text_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plain_text_bytes.decode("utf-8")

    except Exception as e:
        print(f"❌ Dekripsi gagal: {e}")
        return None


# --- Utilitas USB (Tidak berubah) ---
def find_removable_drives():
    """Mendeteksi semua removable drive (USB)."""
    drives = []
    try:
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts or (sys.platform == "linux" and "fixed" not in partition.opts):
                 # Logika deteksi sedikit disesuaikan untuk keandalan lintas platform
                drives.append(partition.mountpoint)
    except Exception as e:
        print(f"Error saat mencari drive: {e}")
    return drives

# --- Worker untuk Threading ---

class DriveScanner(QObject):
    """Worker untuk memindai drive di thread terpisah."""
    drives_found = Signal(list)
    finished = Signal()

    @Slot()
    def run(self):
        drives = find_removable_drives()
        self.drives_found.emit(drives)
        self.finished.emit()

class DriveSetter(QObject):
    """Worker untuk menulis key ke USB dan file config di thread terpisah."""
    setup_success = Signal(str, str)
    setup_error = Signal(str)
    finished = Signal()

    def __init__(self, drive_path):
        super().__init__()
        self.target_drive_path = drive_path

    @Slot()
    def run(self):
        try:
            # Generate key unik untuk USB
            secret_key = str(uuid.uuid4())
            key_file_path = os.path.join(self.target_drive_path, KEY_FILE_NAME)

            # 1. Simpan key ke USB
            with open(key_file_path, "w") as f:
                f.write(secret_key)

            # 2. Enkripsi key ke file lokal
            encrypted_config_data = encrypt_config(secret_key, HARDCODED_SECRET)
            
            with open(LOCAL_CONFIG_FILE, "wb") as f:
                f.write(encrypted_config_data)

            self.setup_success.emit(key_file_path, LOCAL_CONFIG_FILE)

        except Exception as e:
            self.setup_error.emit(f"Gagal: {e}. Periksa izin akses.")
        
        self.finished.emit()


# --- UI Utama ---

class AppWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Key Provisioning Tool")
        self.setGeometry(300, 300, 500, 350)
        
        # Simpan referensi ke thread dan worker
        self.thread = None
        self.worker = None

        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        self.layout = QVBoxLayout(self)

        # 1. Tombol Scan
        self.scan_button = QPushButton("Pindai Drive USB")
        self.scan_button.clicked.connect(self.start_drive_scan)

        # 2. Daftar Drive
        self.drive_list_label = QLabel("Drive yang Terdeteksi:")
        self.drive_list = QListWidget()
        self.drive_list.itemSelectionChanged.connect(self.on_selection_change)

        # 3. Tombol Setup
        self.setup_button = QPushButton("Setup Drive yang Dipilih")
        self.setup_button.clicked.connect(self.start_drive_setup)
        self.setup_button.setEnabled(False) # Nonaktifkan sampai ada yang dipilih

        # 4. Label Status
        self.status_label = QLabel("Klik 'Pindai' untuk memulai.")
        self.status_label.setWordWrap(True)

        # Tambahkan widget ke layout
        self.layout.addWidget(self.scan_button)
        self.layout.addWidget(self.drive_list_label)
        self.layout.addWidget(self.drive_list)
        self.layout.addWidget(self.setup_button)
        self.layout.addWidget(self.status_label)

    def apply_styles(self):
        """Menambahkan sedikit styling agar terlihat lebih baik."""
        self.setStyleSheet("""
            QWidget {
                font-family: Segoe UI, sans-serif;
                font-size: 11pt;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #aac8e2;
            }
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 5px;
            }
            QLabel#status_label {
                font-size: 10pt;
                padding-top: 10px;
            }
        """)
        self.status_label.setObjectName("status_label")

    def on_selection_change(self):
        """Mengaktifkan tombol setup jika ada drive yang dipilih."""
        if self.drive_list.selectedItems():
            self.setup_button.setEnabled(True)
        else:
            self.setup_button.setEnabled(False)

    def set_ui_busy(self, busy):
        """Mengatur status UI saat proses berjalan."""
        self.scan_button.setEnabled(not busy)
        self.setup_button.setEnabled(not busy and bool(self.drive_list.selectedItems()))

    # --- Slot untuk Worker Thread ---

    def start_drive_scan(self):
        self.set_ui_busy(True)
        self.status_label.setText("Memindai drive...")
        self.status_label.setStyleSheet("color: black;")
        self.drive_list.clear()

        self.thread = QThread()
        self.worker = DriveScanner()
        self.worker.moveToThread(self.thread)

        self.worker.drives_found.connect(self.on_drives_found)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.set_ui_busy(False))

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def on_drives_found(self, drives):
        if not drives:
            self.status_label.setText("Tidak ada drive USB yang terdeteksi.")
        else:
            self.drive_list.addItems(drives)
            self.status_label.setText("Pilih drive dan klik 'Setup'.")

    def start_drive_setup(self):
        selected_items = self.drive_list.selectedItems()
        if not selected_items:
            return

        drive_path = selected_items[0].text()
        
        reply = QMessageBox.question(self, "Konfirmasi Setup",
            f"Anda akan menyiapkan drive berikut:\n\n{drive_path}\n\n"
            f"Ini akan membuat file '{KEY_FILE_NAME}' di drive tersebut. Lanjutkan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.No:
            return

        self.set_ui_busy(True)
        self.status_label.setText(f"Menyiapkan {drive_path}...")
        self.status_label.setStyleSheet("color: black;")

        self.thread = QThread()
        self.worker = DriveSetter(drive_path)
        self.worker.moveToThread(self.thread)

        self.worker.setup_success.connect(self.on_setup_success)
        self.worker.setup_error.connect(self.on_setup_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.set_ui_busy(False))
        
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def on_setup_success(self, usb_path, local_path):
        self.status_label.setText(
            f"✅ Sukses!\nFile USB key: {usb_path}\nFile config: {local_path}"
        )
        self.status_label.setStyleSheet("color: green;")
        QMessageBox.information(self, "Sukses", 
            "Drive USB berhasil disiapkan dan file konfigurasi lokal telah dibuat.")

    def on_setup_error(self, error_message):
        self.status_label.setText(f"❌ Error: {error_message}")
        self.status_label.setStyleSheet("color: red;")
        QMessageBox.warning(self, "Error", 
            f"Terjadi kesalahan:\n\n{error_message}")


if __name__ == "__main__":
    # Pastikan Anda telah menginstal dependensi:
    # pip install PySide6 psutil pycryptodome
    
    app = QApplication(sys.argv)
    
    # Coba atur ikon aplikasi (opsional)
    try:
        # Menggunakan ikon standar bawaan Qt jika ada
        app.setWindowIcon(QIcon.fromTheme("drive-removable-media"))
    except Exception:
        pass # Tidak masalah jika gagal

    window = AppWindow()
    window.show()
    sys.exit(app.exec())


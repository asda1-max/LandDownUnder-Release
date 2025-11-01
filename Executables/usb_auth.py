import os
import time
import psutil
from tkinter import messagebox
from setup_usb import decrypt_config
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QMetaObject, Qt, Q_ARG

# --- Konfigurasi ---
# --- Path Konfigurasi Baru ---
# Dapatkan path absolut dari skrip ini
script_path = os.path.abspath(__file__)
# Dapatkan direktori tempat skrip ini berada
script_dir = os.path.dirname(script_path)
# Dapatkan direktori parent dari direktori skrip
parent_dir = os.path.dirname(script_dir)
# Tentukan path file konfigurasi di direktori parent
LOCAL_CONFIG_FILE = os.path.join(parent_dir, "auth/auth.config")
USB_KEY_FILE = ".my_crypto_app_key"
MASTER_SECRET = "ini-adalah-kunci-rahasia-saya-yang-sangat-panjang-12345"  # sama persis dengan setup_usb.py


def get_expected_key():
    """
    Membaca dan mendekripsi file konfigurasi lokal untuk mendapatkan USB key yang diharapkan.
    """
    if not os.path.exists(LOCAL_CONFIG_FILE):
        print(f"⚠️ File {LOCAL_CONFIG_FILE} tidak ditemukan.")
        return None

    try:
        with open(LOCAL_CONFIG_FILE, "rb") as f:
            encrypted_data = f.read()

        expected_key = decrypt_config(encrypted_data, MASTER_SECRET)
        if not expected_key:
            print("⚠️ Gagal mendekripsi config. Pastikan password benar.")
            return None
        return expected_key.strip()
    except Exception as e:
        print(f"❌ Error membaca {LOCAL_CONFIG_FILE}: {e}")
        return None


def find_removable_drives():
    """Mendeteksi semua drive removable (USB)."""
    drives = []
    for partition in psutil.disk_partitions():
        if "removable" in partition.opts or not "fixed" in partition.opts:
            drives.append(partition.mountpoint)
    return drives


def find_usb_key_drive(expected_key):
    """
    Mencari USB drive yang memiliki file .my_crypto_app_key dengan key yang cocok.
    """
    drives = find_removable_drives()
    for drive in drives:
        key_path = os.path.join(drive, USB_KEY_FILE)
        if os.path.exists(key_path):
            try:
                with open(key_path, "r") as f:
                    key_value = f.read().strip()
                if key_value == expected_key:
                    print(f"✅ USB key cocok ditemukan di: {drive}")
                    return drive
            except Exception:
                continue
    return None


def check_usb_key(expected_key):
    """Mengecek apakah USB dengan key yang cocok sedang terpasang."""
    return find_usb_key_drive(expected_key) is not None


def monitor_usb_drive(qt_app, expected_key):
    """
    Memantau keberadaan USB key secara terus-menerus.
    Jika dilepas, aplikasi menampilkan peringatan dan menutup Qt secara aman.
    """
    print("🔍 Memulai pemantauan USB key...")
    while True:
        if not check_usb_key(expected_key):
            print("❌ USB key dilepas! Menutup aplikasi demi keamanan...")
            try:
                messagebox.showwarning(
                    "USB Key Removed",
                    "USB key dilepas! Aplikasi akan ditutup demi keamanan."
                )
            except Exception:
                pass

            # ✅ Kirim perintah quit ke thread utama Qt, bukan kill paksa
            QMetaObject.invokeMethod(
                qt_app,
                "quit",
                Qt.QueuedConnection
            )
            return  # hentikan loop monitoring
        time.sleep(2)
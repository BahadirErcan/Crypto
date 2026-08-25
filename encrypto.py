#!/usr/bin/env python3
import os
import sys
import shutil
import zipfile
import argparse
import io
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

HELP_TEXT = """KULLANIM: python3 encript.py [SEÇENEKLER]

Şifreleme uygulaması. Dosya, dizin veya metin şifreler.

SEÇENEKLER:
  -h, --help            Bu yardım mesajını gösterir.
  -k, --key ANAHTAR     Şifreleme anahtarı (gerekli).
  -f, --file DOSYA      Şifrelenecek dosya veya dizin yolu.
  -t, --text YAZI       Şifrelenecek metin.
  -d, --delete          Şifreleme sonrası orijinali siler.
  -s, --save YOL        Şifrelenmiş çıktıyı belirtilen yola kaydeder.
  -z, --zip             Çıktıyı .zip arşivine alır.

ÖRNEKLER:
  python3 encript.py -k mypassword -f /path/file.txt
  python3 encript.py -k mypassword -f /path/folder
  python3 encript.py -k mypassword -t "merhaba dünya"
  python3 encript.py -k mypassword -f /path/file.txt -d
  python3 encript.py -k mypassword -t "abc" -s /tmp/encrypted.txt
  python3 encript.py -k mypassword -f /path/file.txt -z

NOT: -k parametresi zorunludur. Anahtar olmadan şifreleme yapılamaz."""

HELP_KEY = """-k, --key ANAHTAR
  Şifreleme anahtarı parametresi.
  Bu parametre şifreleme için zorunludur.
  Güvenli bir anahtar kullanın.
  Örnek: -k "guvenliAnhtar123!"

  NOT: Bu parametre olmadan şifreleme yapılamaz.
  Anahtar unutulursa şifrelenmiş veri kurtarılamaz."""

HELP_FILE = """-f, --file DOSYA
  Şifrelenecek dosya veya dizin yolu.
  Dosya belirtilirse: Aynı dizinde "_encrypted" ekli kopya oluşturulur.
  Dizin belirtilirse: Üst dizinde "_encrypted" ekli kopya oluşturulur.
  -z ile birlikte kullanılırsa: ".zip.enc" uzantılı dosya oluşturulur.

  Örnek:
    -f /path/file.txt   -> /path/file_encrypted.txt
    -f /path/folder     -> /path/folder_encrypted/
    -f /path/file.txt -z -> /path/file.txt.zip.enc

  -s ile farklı bir yol belirtilebilir."""

HELP_TEXT_ARG = """-t, --text YAZI
  Metin şifrelemek için kullanılır.
  Şifrelenmiş metin terminale yazdırılır.
  -s ile bir dosyaya kaydedilebilir.

  Örnek:
    -t "merhaba dünya"
    -t "abc" -s /tmp/sifreli.txt"""

HELP_DELETE = """-d, --delete
  Orijinal dosyayı/dizini şifreleme sonrası siler.
  Kullanıldığında silme işlemini onay ister.

  Örnek:
    -d          -> Orijinali siler
    -f /path/a.txt -d -> a.txt şifrelenir, orijinali silinir"""

HELP_SAVE = """-s, --save YOL
  Şifrelenmiş çıktıyı belirtilen yola kaydeder.
  Dosya/dizinde: Varsayılan kaydetme yolunu yoksayar, belirtilen yola kaydeder.
  Metinde: Şifrelenmiş metni dosyaya yazar.

  Örnek:
    -s /tmp/encrypted.txt
    -f /path/file.txt -s /tmp/sifreli.txt"""

HELP_ZIP = """-z, --zip
  Çıktıyı .zip arşivine alır.
  Hem dosya içeriği hem de zip dosyası anahtarla şifrelenir.
  Çıktı ".zip.enc" uzantısı ile kaydedilir.

  Örnek:
    -f /path/file.txt -z -> /path/file.txt.zip.enc
    -f /path/folder -z   -> /path/folder.zip.enc"""


def derive_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_data(data: bytes, password: str) -> bytes:
    key, salt = derive_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(data)
    return salt + encrypted


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    token = encrypted_data[16:]
    key, _ = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token)


def get_encrypted_path(path: str, use_zip: bool = False) -> str:
    p = Path(path)
    if use_zip:
        return p.parent / f"{p.name}.zip.enc"
    return p.parent / f"{p.name}_encrypted"


def get_decrypted_path(path: str, use_zip: bool = False) -> str:
    p = Path(path)
    if use_zip:
        if p.name.endswith(".zip.enc"):
            return p.parent / p.name[:-8]
        return p.parent / f"{p.name}_decrypted"
    if p.name.endswith("_encrypted"):
        return p.parent / p.name[:-10]
    return p.parent / f"{p.name}_decrypted"


def encrypt_file(filepath: str, password: str, delete: bool = False,
                 save_path: str = None, use_zip: bool = False):
    filepath = os.path.abspath(filepath)
    if not os.path.exists(filepath):
        print(f"HATA: Dosya bulunamadı: {filepath}")
        sys.exit(1)

    if os.path.isdir(filepath):
        encrypt_directory(filepath, password, delete, save_path, use_zip)
        return

    with open(filepath, "rb") as f:
        data = f.read()

    if use_zip:
        target = get_encrypted_path(filepath, use_zip=True)
        if save_path:
            target = save_path
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(os.path.basename(filepath), data)
        encrypted = encrypt_data(zip_buf.getvalue(), password)
        with open(target, "wb") as f:
            f.write(encrypted)
        print(f"ZIP şifrelendi: {target}")
    else:
        encrypted = encrypt_data(data, password)
        target = get_encrypted_path(filepath)
        if save_path:
            target = save_path
        with open(target, "wb") as f:
            f.write(encrypted)
        print(f"Şifrelendi: {target}")

    if delete:
        confirm = input(f"Orijinal dosya silinecek: {filepath} (e/h): ").strip().lower()
        if confirm == "e":
            os.remove(filepath)
            print(f"Silindi: {filepath}")
        else:
            print("Silme iptal edildi.")


def encrypt_directory(dirpath: str, password: str, delete: bool = False,
                      save_path: str = None, use_zip: bool = False):
    dirpath = os.path.abspath(dirpath)
    if not os.path.isdir(dirpath):
        print(f"HATA: Dizin bulunamadı: {dirpath}")
        sys.exit(1)

    if use_zip:
        target = get_encrypted_path(dirpath, use_zip=True)
        if save_path:
            target = save_path
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(dirpath):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(dirpath))
                    zf.write(file_path, arcname)
        encrypted = encrypt_data(zip_buf.getvalue(), password)
        with open(target, "wb") as f:
            f.write(encrypted)
        print(f"ZIP şifrelendi: {target}")
    else:
        target_dir = get_encrypted_path(dirpath)
        if save_path:
            target_dir = save_path
        os.makedirs(target_dir, exist_ok=True)
        for root, dirs, files in os.walk(dirpath):
            rel_root = os.path.relpath(root, dirpath)
            dest_root = os.path.join(target_dir, rel_root)
            os.makedirs(dest_root, exist_ok=True)
            for file in files:
                src = os.path.join(root, file)
                dst = os.path.join(dest_root, file)
                with open(src, "rb") as f:
                    data = f.read()
                encrypted = encrypt_data(data, password)
                with open(dst, "wb") as f:
                    f.write(encrypted)
        print(f"Şifrelendi: {target_dir}")

    if delete:
        confirm = input(f"Orijinal dizin silinecek: {dirpath} (e/h): ").strip().lower()
        if confirm == "e":
            shutil.rmtree(dirpath)
            print(f"Silindi: {dirpath}")
        else:
            print("Silme iptal edildi.")


def encrypt_text(text: str, password: str, save_path: str = None):
    encrypted = encrypt_data(text.encode("utf-8"), password)
    encoded = base64.b64encode(encrypted).decode("ascii")
    if save_path:
        with open(save_path, "w") as f:
            f.write(encoded)
        print(f"Şifrelenmiş metin kaydedildi: {save_path}")
    else:
        print(encoded)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        if len(sys.argv) > 2:
            target = sys.argv[2]
            help_map = {
                "-k": HELP_KEY, "--key": HELP_KEY,
                "-f": HELP_FILE, "--file": HELP_FILE,
                "-t": HELP_TEXT_ARG, "--text": HELP_TEXT_ARG,
                "-d": HELP_DELETE, "--delete": HELP_DELETE,
                "-s": HELP_SAVE, "--save": HELP_SAVE,
                "-z": HELP_ZIP, "--zip": HELP_ZIP,
            }
            print(help_map.get(target, HELP_TEXT))
        else:
            print(HELP_TEXT)
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Şifreleme uygulaması", add_help=False)
    parser.add_argument("-k", "--key", default=None)
    parser.add_argument("-f", "--file", default=None)
    parser.add_argument("-t", "--text", default=None)
    parser.add_argument("-d", "--delete", action="store_true")
    parser.add_argument("-s", "--save", default=None)
    parser.add_argument("-z", "--zip", action="store_true")

    args, _ = parser.parse_known_args()

    if args.key is None:
        parser.error("Anahtar gerekli. -k/--key parametresini belirtin.\n"
                     "Yardım için: python3 encript.py -h")

    if args.text is None and args.file is None:
        print("HATA: Dosya (-f) veya metin (-t) parametresi gerekli.")
        print("Yardım için: python3 encript.py -h")
        sys.exit(1)

    if args.text is not None:
        encrypt_text(args.text, args.key, args.save)
    elif args.file is not None:
        encrypt_file(args.file, args.key, args.delete, args.save, args.zip)


if __name__ == "__main__":
    main()

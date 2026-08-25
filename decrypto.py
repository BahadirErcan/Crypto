#!/usr/bin/env python3
import os
import sys
import shutil
import zipfile
import argparse
import io
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HELP_TEXT = """KULLANIM: python3 decript.py [SEÇENEKLER]

Şifre çözme uygulaması. Dosya, dizin veya metin çözer.

SEÇENEKLER:
  -h, --help            Bu yardım mesajını gösterir.
  -k, --key ANAHTAR     Şifre çözme anahtarı (gerekli).
  -f, --file DOSYA      Şifresi çözülecek dosya veya dizin yolu.
  -t, --text YAZI       Şifresi çözülecek metin.
  -d, --delete          Şifre çözme sonrası şifreli dosyayı siler.
  -s, --save YOL        Çözülmüş çıktıyı belirtilen yola kaydeder.
  -z, --zip             .zip arşivinden çıkarır.

ÖRNEKLER:
  python3 decript.py -k mypassword -f /path/file_encrypted.txt
  python3 decript.py -k mypassword -f /path/folder_encrypted
  python3 decript.py -k mypassword -t "sifreliMetin..."
  python3 decript.py -k mypassword -f /path/file_encrypted.txt -d
  python3 decript.py -k mypassword -t "abc" -s /tmp/cozulmus.txt
  python3 decript.py -k mypassword -f /path/file.txt.zip.enc -z

NOT: -k parametresi zorunludur. Yanlış anahtar ile çözümleme başarısız olur."""

HELP_KEY = """-k, --key ANAHTAR
  Şifre çözme anahtarı parametresi.
  Bu parametre şifre çözümü için zorunludur.
  Anahtarın şifreleme sırasında kullanılan ile aynı olması gerekir.

  Örnek: -k "guvenliAnhtar123!"

  NOT: Yanlış anahtar ile çözümleme yapılamaz."""

HELP_FILE = """-f, --file DOSYA
  Şifresi çözülecek dosya veya dizin yolu.
  Dosya belirtilirse: Aynı dizinde "_decrypted" ekli kopya oluşturulur.
  Dizin belirtilirse: Üst dizinde "_decrypted" ekli kopya oluşturulur.
  -z ile birlikte kullanılırsa: Zip'ten çıkarır.

  Örnek:
    -f /path/file_encrypted.txt   -> /path/file_decrypted.txt
    -f /path/folder_encrypted     -> /path/folder_decrypted/
    -f /path/file.txt.zip.enc -z  -> /path/file.txt

  -s ile farklı bir yol belirtilebilir."""

HELP_TEXT_ARG = """-t, --text YAZI
  Metin çözmek için kullanılır.
  Şifrelenmiş base64 metin çözülerek terminale yazdırılır.
  -s ile bir dosyaya kaydedilebilir.

  Örnek:
    -t "c2lmcmxpIG1ldGlu..."
    -t "abc..." -s /tmp/cozulmus.txt"""

HELP_DELETE = """-d, --delete
  Şifreli dosyayı/dizini çözümleme sonrası siler.
  Kullanıldığında silme işlemini onay ister.

  Örnek:
    -d           -> Şifreli dosya silinir
    -f /path/a.txt_encrypted -d -> a.txt_encrypted çözülür, şifreli hali silinir"""

HELP_SAVE = """-s, --save YOL
  Çözülmüş çıktıyı belirtilen yola kaydeder.
  Dosya/dizinde: Varsayılan kaydetme yolunu yoksayar, belirtilen yola kaydeder.
  Metinde: Çözülmüş metni dosyaya yazar.

  Örnek:
    -s /tmp/cozulmus.txt
    -f /path/file_encrypted.txt -s /tmp/original.txt"""

HELP_ZIP = """-z, --zip
  .zip arşivinden çıkarır.
  Şifreli zip dosyası önce çözülür, sonra zip'ten çıkarılır.

  Örnek:
    -f /path/file.txt.zip.enc -z -> /path/file.txt
    -f /path/folder.zip.enc -z   -> /path/folder/"""


def derive_key(password: str, salt: bytes) -> tuple:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    token = encrypted_data[16:]
    key, _ = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token)


def get_decrypted_path(path: str, use_zip: bool = False) -> str:
    p = Path(path)
    if use_zip:
        if p.name.endswith(".zip.enc"):
            return p.parent / p.name[:-8]
        return p.parent / f"{p.name}_decrypted"
    if p.name.endswith("_encrypted"):
        return p.parent / p.name[:-10]
    return p.parent / f"{p.name}_decrypted"


def decrypt_file(filepath: str, password: str, delete: bool = False,
                 save_path: str = None, use_zip: bool = False):
    filepath = os.path.abspath(filepath)
    if not os.path.exists(filepath):
        print(f"HATA: Dosya bulunamadı: {filepath}")
        sys.exit(1)

    if os.path.isdir(filepath):
        decrypt_directory(filepath, password, delete, save_path, use_zip)
        return

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted = decrypt_data(encrypted_data, password)
    except Exception:
        print("HATA: Şifre çözme başarısız. Anahtar yanlış olabilir.")
        sys.exit(1)

    if use_zip or filepath.endswith(".zip.enc"):
        target = str(get_decrypted_path(filepath, use_zip=True))
        if save_path:
            target = save_path
        zip_path = target + ".tmp.zip"
        with open(zip_path, "wb") as f:
            f.write(decrypted)
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(os.path.dirname(target) if os.path.dirname(target) else ".")
            os.remove(zip_path)
            print(f"ZIP çıkarıldı: {target}")
        except zipfile.BadZipFile:
            os.remove(zip_path)
            with open(target, "wb") as f:
                f.write(decrypted)
            print(f"Şifresi çözüldü (geçersiz zip): {target}")
    else:
        target = get_decrypted_path(filepath)
        if save_path:
            target = save_path
        with open(target, "wb") as f:
            f.write(decrypted)
        print(f"Şifresi çözüldü: {target}")

    if delete:
        confirm = input(f"Şifreli dosya silinecek: {filepath} (e/h): ").strip().lower()
        if confirm == "e":
            os.remove(filepath)
            print(f"Silindi: {filepath}")
        else:
            print("Silme iptal edildi.")


def decrypt_directory(dirpath: str, password: str, delete: bool = False,
                      save_path: str = None, use_zip: bool = False):
    dirpath = os.path.abspath(dirpath)
    if not os.path.isdir(dirpath):
        print(f"HATA: Dizin bulunamadı: {dirpath}")
        sys.exit(1)

    if use_zip or dirpath.endswith(".zip.enc"):
        if not os.path.isfile(dirpath):
            print(f"HATA: Dosya bulunamadı: {dirpath}")
            sys.exit(1)
        with open(dirpath, "rb") as f:
            encrypted_data = f.read()
        try:
            decrypted = decrypt_data(encrypted_data, password)
        except Exception:
            print("HATA: Şifre çözme başarısız. Anahtar yanlış olabilir.")
            sys.exit(1)
        target = str(get_decrypted_path(dirpath, use_zip=True))
        if save_path:
            target = save_path
        zip_path = target + ".tmp.zip"
        with open(zip_path, "wb") as f:
            f.write(decrypted)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(os.path.dirname(target) if os.path.dirname(target) else ".")
        os.remove(zip_path)
        print(f"ZIP çıkarıldı: {target}")
    else:
        target_dir = get_decrypted_path(dirpath)
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
                try:
                    decrypted = decrypt_data(data, password)
                except Exception:
                    print(f"HATA: Şifre çözme başarısız: {src}")
                    continue
                with open(dst, "wb") as f:
                    f.write(decrypted)
        print(f"Şifresi çözüldü: {target_dir}")

    if delete:
        confirm = input(f"Şifreli dizin silinecek: {dirpath} (e/h): ").strip().lower()
        if confirm == "e":
            shutil.rmtree(dirpath)
            print(f"Silindi: {dirpath}")
        else:
            print("Silme iptal edildi.")


def decrypt_text(text: str, password: str, save_path: str = None):
    try:
        encrypted = base64.b64decode(text)
        decrypted = decrypt_data(encrypted, password)
        result = decrypted.decode("utf-8")
    except Exception:
        print("HATA: Şifre çözme başarısız. Anahtar veya metin yanlış olabilir.")
        sys.exit(1)

    if save_path:
        with open(save_path, "w") as f:
            f.write(result)
        print(f"Çözülmüş metin kaydedildi: {save_path}")
    else:
        print(result)


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

    parser = argparse.ArgumentParser(description="Şifre çözme uygulaması", add_help=False)
    parser.add_argument("-k", "--key", default=None)
    parser.add_argument("-f", "--file", default=None)
    parser.add_argument("-t", "--text", default=None)
    parser.add_argument("-d", "--delete", action="store_true")
    parser.add_argument("-s", "--save", default=None)
    parser.add_argument("-z", "--zip", action="store_true")

    args, _ = parser.parse_known_args()

    if args.key is None:
        parser.error("Anahtar gerekli. -k/--key parametresini belirtin.\n"
                     "Yardım için: python3 decript.py -h")

    if args.text is None and args.file is None:
        print("HATA: Dosya (-f) veya metin (-t) parametresi gerekli.")
        print("Yardım için: python3 decript.py -h")
        sys.exit(1)

    if args.text is not None:
        decrypt_text(args.text, args.key, args.save)
    elif args.file is not None:
        decrypt_file(args.file, args.key, args.delete, args.save, args.zip)


if __name__ == "__main__":
    main()

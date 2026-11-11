# Encryption - Şifreleme ve Çözme Aracı

Python ile yazılmış, dosya, dizin ve metin şifreleme/çözme uygulaması.

## Özellikler

- Dosya ve dizin şifreleme/çözme
- Metin şifreleme/çözme
- ZIP arşivleme desteği
- PBKDF2 tabanlı anahtar türetme (480.000 iterasyon)
- Fernet simetrik şifreleme
- Orijinal dosyayı silme seçeneği

## Kurulum

```bash
git clone https://github.com/BahadirErcan/Crypto.git
cd Crypto
pip install -r requirements.txt
```

## Kullanım

### Şifreleme (encrypto.py)

```bash
# Dosya şifreleme
python3 encrypto.py -k ANAHTAR -f /yol/dosya.txt

# Dizin şifreleme
python3 encrypto.py -k ANAHTAR -f /yol/dizin

# Metin şifreleme
python3 encrypto.py -k ANAHTAR -t "şifrelenecek metin"

# Şifreleme ve orijinali silme
python3 encrypto.py -k ANAHTAR -f /yol/dosya.txt -d

# ZIP ile şifreleme
python3 encrypto.py -k ANAHTAR -f /yol/dosya.txt -z

# Belirtilen yola kaydetme
python3 encrypto.py -k ANAHTAR -t "metin" -s /yol/cikti.txt
```

### Çözme (decrypto.py)

```bash
# Dosya çözme
python3 decrypto.py -k ANAHTAR -f /yol/dosya_encrypted.txt

# Dizin çözme
python3 decrypto.py -k ANAHTAR -f /yol/dizin_encrypted

# Metin çözme
python3 decrypto.py -k ANAHTAR -t "şifreliMetin..."

# ZIP'ten çıkarma
python3 decrypto.py -k ANAHTAR -f /yol/dosya.txt.zip.enc -z

# Çözme ve şifreli dosyayı silme
python3 decrypto.py -k ANAHTAR -f /yol/dosya_encrypted.txt -d
```

## Parametreler

| Parametre | Açıklama |
|-----------|----------|
| `-k`, `--key` | Şifreleme/çözme anahtarı (zorunlu) |
| `-f`, `--file` | Şifrelenecek/çözülecek dosya veya dizin |
| `-t`, `--text` | Şifrelenecek/çözülecek metin |
| `-d`, `--delete` | İşlem sonrası orijinal dosyayı siler |
| `-s`, `--save` | Çıktıyı belirtilen yola kaydeder |
| `-z`, `--zip` | ZIP arşivleme kullanır |
| `-h`, `--help` | Yardım mesajını gösterir |

## Örnekler

```bash
# Güçlü anahtar ile dosya şifreleme
python3 encrypto.py -k "Guvenli123!@#" -f belgelerim/rapor.pdf

# Şifreli dosyayı çözme
python3 decrypto.py -k "Guvenli123!@#" -f belgelerim/rapor_encrypted.pdf

# Klasörü ZIP ile şifreleme
python3 encrypto.py -k "sifrem" -f proje_klasoru -z

# Şifreli ZIP'ten çıkarma
python3 decrypto.py -k "sifrem" -f proje_klasoru.zip.enc -z
```

## Çıktı Formatları

| Giriş | Çıkış |
|-------|-------|
| `dosya.txt` | `dosya_encrypted.txt` |
| `dosya.txt.zip.enc` | `dosya.txt` |
| `dizin/` | `dizin_encrypted/` |
| `dizin.zip.enc` | `dizin/` |

## Teknik Detaylar

- **Şifreleme:** Fernet (AES-128-CBC)
- **Anahtar Türetme:** PBKDF2-HMAC-SHA256 (480.000 iterasyon)
- **Tuz:** Rastgele 16 byte (her işlem için farklı)
- **Bellek:** 32 byte anahtar uzunluğu

## Uyarılar

- Anahtar unutulursa şifrelenmiş veri kurtarılamaz
- Yanlış anahtar ile çözümleme başarısız olur
- `-d` parametresi kullanırken dikkatli olun, silinen dosyalar geri alınamaz

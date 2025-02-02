# Blockchain Python

[GitHub Address](https://github.com/hamitmizrak/blockchainPython.git)
---

## Git
```sh
git init
git add .
git commit -m "blockchain initialized"
git remote add origin master
git push origin master

git clone https://github.com/hamitmizrak/blockchainPython.git
```
---

## pip version
```sh
pip --version
pip install pycryptodo    # AES kütüphanesi

```
---


## Renkler 
```sh
pip install colorama
form colorama import Fore,Style
```
---


## AES 
```sh
AES, simetrik anahtarlı blok şifreleme algoritmasıdır.
2001 yılında NIST (National Instute of Standards and Technology)
Rijndael algorithm dayanır
128-bit, 192-bit, 256-bit
Günümüz şarlarında DES'e göre daha güvenlidir.
Yükse Hız verimliliği, güçlü, brute force dayanaıklıdır.
Veri şifreleme
WPA2,WPA3
VPN
```
---


## Simetrik Asimetrik
```sh

```
---
### **Simetrik ve Asimetrik Şifreleme Arasındaki Farklar**

| **Özellik**          | **Simetrik Şifreleme** 🔐 | **Asimetrik Şifreleme** 🔑 |
|----------------------|-------------------------|-------------------------|
| **Anahtar Kullanımı** | Aynı anahtar hem şifreleme hem de çözme işlemi için kullanılır. | İki farklı anahtar (genellikle **Genel** ve **Özel**) kullanılır. |
| **Hız**              | Daha hızlıdır çünkü tek bir anahtar ile işlem yapılır. | Daha yavaştır çünkü karmaşık matematiksel işlemler kullanır. |
| **Güvenlik**         | Anahtar paylaşımı risklidir, çalınırsa şifre çözülür. | Daha güvenlidir çünkü özel anahtar paylaşılmaz. |
| **Kullanım Alanı**   | Büyük verilerin şifrelenmesi, disk şifreleme, VPN, AES gibi algoritmalar. | Dijital imza, anahtar değişimi, kimlik doğrulama, RSA gibi algoritmalar. |
| **Örnek Algoritmalar** | AES, DES, 3DES, ChaCha20 | RSA, ECC, Diffie-Hellman, DSA |

---

## **🔹 1. Simetrik Şifreleme Nedir?**
Simetrik şifrelemede, **şifreleme ve çözme işlemi için aynı anahtar kullanılır**. Anahtarın gizli tutulması çok önemlidir, çünkü eğer bir saldırgan anahtarı ele geçirirse tüm şifrelenmiş verileri çözebilir.

### **Örnek: AES ile Simetrik Şifreleme**
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(32)  # 256-bit anahtar
iv = os.urandom(16)   # AES için Initialization Vector
data = "Simetrik Şifreleme".encode()

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("Şifreli Veri:", ciphertext.hex())
print("Çözülmüş Veri:", decrypted.decode())
```

- **Avantajları:**
  - Hızlıdır, büyük verileri şifrelemekte idealdir.
  - Günümüzde AES gibi güçlü algoritmalar kullanılır.

- **Dezavantajları:**
  - **Anahtar paylaşımı güvenli olmalıdır**. Eğer bir saldırgan anahtarı ele geçirirse, tüm verileri çözebilir.

---

## **🔹 2. Asimetrik Şifreleme Nedir?**
Asimetrik şifrelemede **iki farklı anahtar kullanılır**:
1. **Genel Anahtar (Public Key):** Veriyi şifrelemek için kullanılır.
2. **Özel Anahtar (Private Key):** Veriyi çözmek için kullanılır.

Genel anahtar herkesle paylaşılabilir, ancak özel anahtar **gizli tutulmalıdır**.

### **Örnek: RSA ile Asimetrik Şifreleme**
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Anahtar çifti oluştur
key = RSA.generate(2048)
public_key = key.publickey().export_key()
private_key = key.export_key()

# Şifreleme
rsa_public = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(rsa_public)
encrypted = cipher.encrypt(b"Asimetrik Şifreleme")

# Şifre Çözme
rsa_private = RSA.import_key(private_key)
decipher = PKCS1_OAEP.new(rsa_private)
decrypted = decipher.decrypt(encrypted)

print("Şifrelenmiş Veri:", encrypted.hex())
print("Çözülmüş Veri:", decrypted.decode())
```

- **Avantajları:**
  - **Güvenli**: Özel anahtar paylaşılmadığı için saldırganların şifreyi çözmesi zordur.
  - **Dijital İmzalar** ve **kimlik doğrulama** işlemleri için idealdir.

- **Dezavantajları:**
  - Simetrik şifrelemeye göre **daha yavaştır**.
  - Büyük dosyaları doğrudan şifrelemek için uygun değildir (genellikle anahtar değişimi için kullanılır).

---

## **🔹 Simetrik mi, Asimetrik mi Kullanmalı?**
- **Güvenli anahtar değişimi yapacaksanız:** 🔑 **Asimetrik Şifreleme** (Örn: RSA, Diffie-Hellman)
- **Büyük veri şifreleyecekseniz:** 🔐 **Simetrik Şifreleme** (Örn: AES, ChaCha20)
- **Hibrit Kullanım:** Genellikle **asimetrik şifreleme, simetrik anahtarı güvenli şekilde paylaşmak için** kullanılır. Örneğin:
  - **TLS (HTTPS)** protokolü, RSA/DH gibi asimetrik şifrelemeyi kullanarak **AES anahtarını güvenli bir şekilde paylaşır**, sonra AES ile simetrik şifreleme yapar.

---

## **Özet**
- **Simetrik Şifreleme** (AES, DES): Aynı anahtar kullanılır, hızlıdır.
- **Asimetrik Şifreleme** (RSA, ECC): İki farklı anahtar kullanılır, daha güvenlidir ama yavaştır.
- **Modern Sistemlerde:** İkisi birlikte kullanılarak hem güvenlik hem de hız sağlanır.

🚀 🔐





## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


## Blockhain
```sh

```
---


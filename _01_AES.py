# pip --version
# pip install pycryptodo    # AES kütüphanesi

# Eğer paket yüklenmezse
# pip uninstall pycryptodo
# pip install pycryptodo --no-cache-dir

# 8bit=1Bayt

"""
AES, simetrik anahtarlı blok şifreleme algoritmasıdır.
2001 yılında NIST (National Instute of Standards and Technology)
Rijndael algorithm dayanır
128-bit, 192-bit, 256-bit
Günümüz şarlarında DES'e göre daha güvenlidir.
Yükse Hız verimliliği, güçlü, brute force dayanaıklıdır.
Veri şifreleme
WPA2,WPA3
VPN
"""
################################
from Crypto.Cipher import AES    # AES şifreleme kütüphanesi
from Crypto.Util.Padding import pad,unpad # Veri bloklarını tamamlama ve kaldırma fonksiyonu
import os # Rastgelere anahtar üretmek için kullanılan kütüphanes

#  8 bit = 1 byte
# AES için 256-bit(32 byte) uzunluğunda rastgele bir anahtar oluştur
key = os.urandom(32) # 256-bit AES anahtarı güvenli ve rastgele için

# AES için initialization Vector(IV) olarak 16 byte olarak rastgele bir değer oluştur
iv= os.urandom(16)   # AES için Initialization Vector

# Şifrelencek veriyi tamamladık (Örnek: e-posta adresi)
data = "hamitmizrak@gmail.com:123456".encode() # string veriyi byte formanıta çevir

# AES şifreleme (CBC Modu)
cipher = AES.new(key, AES.MODE_CBC,iv) # AES nesnesini oluştur (CBC modu ve IV)

# Veriyi AES şifreleme bloğu boyutuna uygun hale getirmek için pad() kullanılıyoruz.
# AES blok boyutu 16 byte olduğu için eksik kalan kısımları uygun bir şemada dolduralım.
ciphertext= cipher.encrypt(pad(data, AES.block_size))

# Şifrelenmiş verileri hexadecimal formatında ekrana yazdırıyoruz.
print("İlk Veri Veri AES: ", data)
print("Şifrelenmiş Veri AES: ", ciphertext.hex())

# AES şifre çözme (CBC Modu)
# AES şifre çözme işlemi için aynı anahtar ve IV ile yeni bir AES nesnesi oluşturuyoruz.
decipher = AES.new(key, AES.MODE_CBC, iv)

# Şifrelenmiş verileri AES şifre çözme bloğuna uygun hale getirmek için unpad() kullanıyoruz.
decipher_data= unpad(decipher.decrypt(ciphertext), AES.block_size)

# Şifre çözülmüş verileri ekrana yazdırıyoruz.
print("Çözülmüş ilk veri: (AES):", decipher_data.decode())

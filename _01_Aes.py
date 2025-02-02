# pip --version
# pip install pycryptodo    # AES kütüphanesi

# Eğer paket yüklenmezse
# pip uninstall pycryptodo
# pip install pycryptodo --no-cache-dir

# 8bit=1Bayt

"""
"""
################################
from Crypto.Cipher import AES
import os

from Crypto.Util.Padding import pad,unpad

key = os.urandom(32) # 256-bit AES anahtarı
iv= os.urandom(16)   # AES için Initialization Vector

data = "hamitmizrak@gmail.com".encode() #

# AES şifreleme (CBC Modu)
cipher = AES.new(key, AES.MODE_CBC,iv)
ciphertext= cipher.encrypt(pad(data, AES.block_size))
print("İlk Veri Veri AES: ", data)
print("Şifrelenmiş Veri AES: ", ciphertext.hex())

# AES şifre çözme (CBC Modu)
decipher = AES.new(key, AES.MODE_CBC, iv)
decipher_data= unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Çözülmüş ilk veri: (AES):", decipher_data.decode())

##########################################################################################
#### Data Type : Dictionary      ################################################################

#  1. Anahtar ve Değer Çiftleri:
#  - Dictionary, anahtar (key) ve değer (value) çiftlerinden oluşur.
#  - Anahtarlar, bir değere referans vermek için kullanılır ve benzersiz olmalıdır.
#  - Değerler herhangi bir veri türünden olabilir (int, str, list, dict vb.).
# Python 3.7'den itibaren, dictionary'ler ekleme sırasını korur.

#  Dictionary Performansı
# Dictionary'nin veri arama performansı oldukça yüksektir (ortalama O(1)).
# Büyük miktarda veriyle çalışırken dictionary kullanımı performans açısından faydalıdır.

# Anahtar hakkında bilgiler
# 1. Anahtarlar Benzersiz Olmalı:
# - Aynı anahtar birden fazla kez tanımlanamaz.
# 2. Anahtarlar Immutable Olmalı:
# - Anahtarlar değiştirilemez veri tiplerinden (str, int, tuple) oluşmalıdır.
# 3. KeyError:
# Mevcut olmayan bir anahtara erişmek `KeyError` hatasına yol açar.
# print(my_dict["adres"])   KeyError

# Boş Dictionary:
empty_dict = {}

my_dict={
    "isim":"Mustafa",
    "surname": "Bingöl",
    "yas": 25,
    "adres": {
        "il": "Istanbul",
        "ilce": "Beyoğlu"
    }
}

# Print
print(my_dict)
print(my_dict["isim"])
print(my_dict["adres"]["il"])


# 2. dict() Fonksiyonu ile:
my_dict_cast = dict(isim="değer1", soyisim="değer2")
print(my_dict_cast)
print(my_dict_cast["isim"])

# keys, values, items
print(my_dict.keys())
print(my_dict.values())
print(my_dict.items())

# key döngü
for key in my_dict:
       print(key)

# key, value döngü
for key, value in my_dict.items():
       print(f"{key}: {value}")


# - Anahtara karşılık gelen değeri döndürür, anahtar yoksa `None` döner (hata vermez).
print(my_dict.get("isim"))
print(my_dict.get("isim44"))

###############################################################################
# Update
# - Sözlüğe yeni anahtar-değer çiftleri ekler veya mevcut değerleri günceller.
my_dict.update({"meslek": "Mühendis"})
print(my_dict)

# pop
# Belirtilen anahtarı ve değerini sözlükten çıkarır.
my_dict.pop("yas")
print(my_dict)

# Copy
# Sözlüğün bir kopyasını oluşturur
new_dict = my_dict.copy()
print("copy", new_dict)

# Clear
# - Sözlüğü temizler (boşaltır).
# my_dict.clear()
# print(my_dict)

###############################################################################
# 1. JSON Veri Modeli: Dictionary, JSON formatında veri işlemek için çok kullanışlıdır.
data = {"isim": "Ahmet", "yas": 25}
import json # import etmek
json_data = json.dumps(data)
print(json_data)

# 2. Veri Tabanı ve API İşlemleri: Veri tabanından çekilen veya API'den gelen veri genellikle dictionary formatında olur.

# 3. Sayma ve Gruplama: Listelerdeki öğelerin sayısını tutmak için kullanılabilir.
from collections import Counter
my_list = ["elma", "armut", "elma", "çilek"]
count = Counter(my_list)
print(count)


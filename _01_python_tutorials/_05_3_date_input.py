from datetime import datetime

# Python Yıl bilgisi olarak formatter datetime modülünü kullanıyoruz.

# Kullanıcıdan Veri al
user_input = input("Tarih giriniz: (YYYY-MM-DD): ")

# Tarih Nesnesi dönüştürmek(cast)
date_object = datetime.strptime(user_input, '%Y-%m-%d')
print(date_object)

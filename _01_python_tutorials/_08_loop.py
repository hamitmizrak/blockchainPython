##########################################################################################
#### For Loop ###########################################################################
# Ctrl + Alt + L
from django.db.models.lookups import Range

# for eleman in iterable:
#      Döngü bloğu
# - eleman: Döngü sırasında, iterable içindeki her bir öğe sırayla bu değişkene atanır.
# - iterable: Döngüde üzerinde gezilecek nesne (örneğin liste, tuple, dize, sözlük, küme veya bir range nesnesi).

# Loop over
print("#### Loop over ############################")
number = [1, 2, 3, 4, 5, 6, 7, 8, 9]
for temp in number:
    print(temp)

print("#### Range ################################")
# range() fonksiyonu belirli bir aralıkta sayılar üretir ve genellikle for döngüsüyle kullanılır.
for temp in range(9):  # 1<=SAYI<=9-1
    print(temp)

# range() Kullanımı:
# range(n): 0’dan n-1’e kadar olan sayıları üretir.
# range(start, stop): start'tan başlayıp stop-1’e kadar olan sayıları üretir.
# range(start, stop, step): Belirtilen artış miktarına göre sayılar üretir.
for i in range(1, 10, 2):   # 1'den başlayarak 2'şer artar
    print(i)


##########################################################################################
#### While Loop ##########################################################################
i = 0
while i < 5:
    print(i)
    i += 1   #i değerini artırmayı unutursanız sonsuz döngü oluşur


# Örnek Şifre
# password_data=""
# count=0
# while password_data !=123456:
#     password_data = int(input("Şifrenizi giriniz\n"))
#     count +=1
# print("Şifreniz Doğru: deneme hakkınız. ",count)


# Sonsuz
# while True:
#     print("Sonsuz döngü")


##########################################################################################
#### While break, continue, pass #########################################################
# 1 -10 arasındaki toplamları
# Eğer sayılarda 5 varsa toplamadan diğer döngüye geç
# Eğer sayı 10'dan büyükse döngüyü bitir
# Eğer sayı 6 eşitse o anlık birşey yapma(pass)
total = 0
for i in range(1,1100,1):
    if i == 5:
        continue  # Döngünün o anki yinelemesini sonlandırır ve bir sonraki yinelemeye geçer
    if i >= 11:
        break  # Bu döngüyü bitir
    if i ==6:
        pass  # Bu satırda birşey yapılmadığını belirtir
        print(" Bu satırda birşey yapılmadığını belirtir")
    total += i
print("Toplam:", total)

##########################################################################################
#### içice Döngü / else  ########################################################################
for j in range(1, 11):  # Satırları oluşturmak için
    for i in range(1, 11):  # Her iki sütunu yazdırmak için (örnekte 2 tablo)
        print(f"{i} x {j} = {i*j:<10}", end="\t")  # Çıktıyı hizalamak için <4 ile genişlik belirleniyor
    print()  # Satır sonunda bir alt satıra geç
else:
    print("Çarpım tablosu tamamlandı")






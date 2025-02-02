
################################################################
# GC(Garbarage Collector)
"""Python'da değişkenler bellek yönetimi açısında otomatik olarak işlenir """
# GC: Gereksiz hale gelmiş ve kullanılmayan çöp olan nesleri otomatik olarak siler
number1=44 # Buradaki number1=44 olan ver artık bir çöptür
number1=23

#####################################################################################
#### None ###########################################################################
# None: Python'da None özel bir veri türüdür ve boş veya tanımsız bir değeri ifade eder.
data = None    #Tanımsız veya boş değeri temsil eder
print("boş değer: ", data)

# - is None: None'un aynı nesne olup olmadığını kontrol eder.
# - == None: None'a eşit olup olmadığını kontrol eder.

"""
x = None

 Doğru kullanım
if x is None:
    print("x gerçekten None")

 Yanlış olmasa da önerilmeyen kullanım
if x == None:
    print("x None'a eşit")

"""

###################################################################
# Cast: Type Casting yani Değişkenlerin Tip dönüşümlerini kullanmak

# int()          : Tam Sayıya çevirir.
# float()        : Virgüllü Sayıya çevirir.
# str()          : kelime  çevirir.
# bool()         : Boolean çevirir.
number2="44"
print(number2)
print("string: ",type(number2))
print("integer: ",type(int(number2)))
print("float: ",type(float(number2)))

################################################################################
# Escape Character: Kaçış karekteri
print("1.satır\n2.satır")
print("3.satır\n\t4.satır")
print("5.satır\n\r\t6.satır")

# Unicode Karakter 16bit(u) ve 32bit(U)
print("\u0001")
print("\U0001F600")

# Dosya Yollarına
print("C:\\User\\AppData")
print(r"C:\User\AppData")   # Ham String: (r) Kaçış karakterini devre dışı bırakmak için kullanıyoruz.

# None
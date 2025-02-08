# Single Comment

"""
Multiple Comment (Docstring)
"""

##################################################
#### print #######################################
# Python Dinamik türe (dynamics type)
# string
print("Python Öğreniyorum")

# Tam sayı
print(44)

# Virgüllü sayı (Floating Point )
print(44.23)

# Birden fazla değer yazdırma
print("Merhaba", "Python", "Öğreniyorum")


#####################################################################################
#### değişken #######################################################################
# a) Tek Değişken Atama
x = 5
print(x)

#  b) Birden Fazla Değişken Atama
x, y, z = 1, 2, 3   # x=1, y=2, z=3
print(x, y, z)

# c) Aynı değeri birden fazla değişkene atayabilirsiniz.
a = b = c = 0   # a=0, b=0, c=0
print(a, b, c)

# d) Değişkenlerin Değerlerini Değiştirme
x, y = 5, 10
print(x,y)
x, y = y, x
print(x,y)

#####################################################################################
#### print ##########################################################################
# Kelime yazdırmak
print("Merhabalar, Nasılsınız")

# Sayı yazdırmak
print(44)

#####################################################################################
#### seperate ########################################################################
# sep: datalar arasında hangi karaktere göre göstersin
# seperate parameter: Her virgül sonuna Ayraç ekle
print("Merhaba", "Python", "Öğreniyorum")
print("Merhaba", "Python", "Öğreniyorum", sep=" - ")

#####################################################################################
#### end  ########################################################################
# end parametresi, print() fonksiyonu her çağrıldığında varsayılan olarak yeni bir satıra geçmeyi engeller ve
# bunun yerine belirtilen değeri kullanır.
# end parameter: Yeni bir satıra geçmesini engellesin
print("Merhaba", "Python", "Öğreniyorum", " ***", "Python Dünyasına hoşgeldiniz")  # failed: non best practice

# Aynısı
print("Merhaba", "Python", "Öğreniyorum ", end=" *** ")
print("Python Dünyasına hoşgeldiniz")




#####################################################################################
#### formatter ######################################################################
# Formatter
name="Hamit"
surname="Mızrak"
school="Firat University"
# f-string
print(f"formatter: Benim adım:{name} Soyadım:{surname} okulum:{school}")


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


######################################################################################
### const ############################################################################
# docstring
print("""
    Python
    Öğreniyorum
    """)

######################################################################################
#### const ###########################################################################
# Python’da sabitleri korumak için özel bir dil özelliği yoktur,
# ancak büyük harflerle yazmak, sabitin değiştirilmemesi gerektiğini belirten bir konvansiyondur.
PI = 3.14159
print(PI)

MAX_CONNECTIONS = 100
print(MAX_CONNECTIONS)

# Escape Character
#\n: new  \r:alt satıra en soldan başla \t:boşluk bırak
print("""\n\r\tdocstring 
    Python
         Öğreniyorum
    """)

# Değişken yazdırma
isim = "Hamit"
soyisim = "Mızrak"

# 1.YOL
print("Adım:", isim, " Soyadım: ", soyisim)

# 2.YOL  %s:string %d:decimal %f:virgüllü
print("Adım: %s, Soyadım: %s " % (isim, soyisim))

# 3.YOL Formatter (Python>=3.6)
print(f"Adım: {isim}, Soyadım:  {soyisim}")
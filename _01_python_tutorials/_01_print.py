# Single Comment

"""
Multiple Comment (Docstring)
"""

##################################################
#### print #######################################
# string
print("Python Öğreniyorum")

# Tam sayı
print(44)

# Virgüllü sayı
print(44.23)

# Birden fazla değer yazdırma
print("Merhaba","Python","Öğreniyorum")

#####################################################################################
#### seperate ########################################################################
# sep: datalar arasında hangi karaktere göre göstersin
# sep parameter: Ayraç ekle
print("Merhaba", "Python", "Öğreniyorum", sep=" * ")



#####################################################################################
#### end  ########################################################################
# end parametresi, print() fonksiyonu her çağrıldığında varsayılan olarak yeni bir satıra geçmeyi engeller ve
# bunun yerine belirtilen değeri kullanır.
# end parameter: Yeni bir satıra geçmesini engellesin
print("Merhaba", "Python", "Öğreniyorum"," *** ","Dünya'ya hoşgeldin") # failed: non best practice
print("Merhaba", "Python", "Öğreniyorum ", end=" *** ")
print("Dünya'ya hoşgeldin")

# docstring
print( """docstring 
    Python
    Öğreniyorum
    """)

# Escape Character
print("""\n\r\tdocstring 
    Python
    Öğreniyorum
    """)

# Değişken yazdırma
isim = "Hamit"
soyisim = "Mızrak"
print("Adım:", isim," Soyadım: ", soyisim)    # 1.YOL
print("Adım: %s, Soyadım:%s"%(isim,soyisim))  # 2.YOL  %s:string %d:decimal %f:virgüllü
print(f"Adım: {isim}, Soyadım:  {soyisim}")   # 3.YOL Formatter (Python>=3.6)



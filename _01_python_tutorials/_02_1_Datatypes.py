# pylint: disable=C0114
"""  """
# Data types

# camelCase
# PascalCase
# snake_case
# kebap_case

# Dynamics Types
# Değişken isimlendirme: Sayı ile başlama
# _ ile başlayabilirsiniz
# snake_case olarak yazınız.

#####################################################################################
#### sayılar ########################################################################
# Number
number1 = 10  # Pozitif Tam sayı
number1 = +10  # Pozitif Tam sayı
number2 = -10  # Negatif Tam sayı
PI = 3.14159  # Virgüllü sayı

# string karakter
string1 = "Hello World1"
string2 = 'Hello World2'
print(string1, "", string2)

# Type: Tür Verilen data type(Veri türününü gösterir)
print(type(string1))
print(type(number1))
print(type(number2))
print(type(PI))

################################################################
# Değişken atama tek satırda da gösterebilirsiniz
x, y, z = 1, 2, 3

################################################################
# Sabitler BÜYÜK_KARAKTERLER
DATA_CONNECTION = 255

#####################################################################################
#### boolean ########################################################################
# Boolean: İlk karakter büyük olacak, True, False
# Boolean
is_login = True  # False
print(is_login)
print(type(is_login))
admin = "Login mi ? {isLogin}"
print(admin)

#####################################################################################
#### List ########################################################################
# List: Birden fazla veriyi tek bir bileşende tutmak
# List
print("\nList")
my_list1 = [1, 2, 3, 4, 5]
print(my_list1)
print(type(my_list1))

my_list2 = [1, 2, 3, 4, 5, "Malatya"]
print(my_list2)
print(type(my_list2))

#####################################################################################
#### Tuple ########################################################################
# Tuple: Birden fazla veriyi tek bir bileşende tutmak ancak veriler değiştirilemez
# Tuple(Demet) : Liste çok benzer ancak buradaki değerler değiştirilmez(immutable)
print("\nTuple")
my_tuple1 = (1, 2, 3, 4, 5)  # Tuple(Demet)
print(my_tuple1)

#####################################################################################
#### Set ########################################################################
# Set: List'e benzer ancak tekrar eden verileri bir kere gösterir(Tekrarsız)
print("\nSet")
my_Set1 = {1, 1, 2, 3, 4, 4, 4, 4, 4, 4}
print(type(my_Set1))
print(my_Set1)

#####################################################################################
#### Dictionary ########################################################################
# Dictionary: key-value olarak çalışan verilerdir.
# Dictionary(Sözlük)
print("\nDictionary")
my_dictionary1 = {
    "name": "Hamit",
    "surname": "Mızrak",
    "is_login": True
}
print(my_dictionary1)
print(type(my_dictionary1))



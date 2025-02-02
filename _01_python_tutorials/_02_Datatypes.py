
#pylint: disable=C0114
"""  """

# Dynamics Types
# Değişken isimlendirme: Sayı ile başlama
# _ ile başlayabilirsiniz
# snake_case olarak yazınız.

#####################################################################################
#### sayılar ########################################################################
# Number
number1= 10  # Pozitif Tam sayı
number2= -10 # Negatif Tam sayı
PI=3.14159

# string karakter
string1= "Hello World"
string2= 'Hello World'
print(string1,"",string2)

#####################################################################################
#### type ###########################################################################
print(type(string1))

#####################################################################################
#### boolean ########################################################################
# Boolean
is_login=True #False
print(type(is_login))
admin="Login mi ? {isLogin}"
print(admin)

# List
my_list1=[1,2,3,4,5]
my_list2=[1,2,3,4,5,"Malatya"]
print(type(my_list2))

# Tuple(Demet) : Liste çok benzer ancak buradaki değerler değiştirilmez(immutable)
my_tuple1=(1,2,3,4,5) # Tuplle(Demet)

# Dictionary(Sözlük)
my_dictionary1 ={
    "name":"Hamit",
    "surname":"Mızrak",
    "is_login":True
}
print(type(my_dictionary1))

# Set: Her elemenanın benzersiz olduğunu göstermek içindir
my_Set1={1,1,2,3,4,4}
print(type(my_Set1))

################################################################
# Değişken atama
x,y,z=1,2,3

################################################################
# Sabitler BÜYÜK_KARAKTERLER
DATA_CONNECTION= 255



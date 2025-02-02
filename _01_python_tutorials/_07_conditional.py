#####################################################################################
#### Conditional ####################################################################

# Sayı Negatif Pozitif
# if else
number=5
if number > 0:
    print("pozitif sayı")
else:
    print("negatif sayı")

# Ternary
terna= "Pozitif sayı" if number > 0 else "Negatif sayı"
print(terna)

# if - elif -else
if number==1:
    print("bir")
elif number==2:
    print("iki")
elif number==3:
    print("üç")
else:
    print("1<=X<=5")

# Sayı Negatif Çift, Tek
if number >0:
    if number % 2 == 0:
        print("çift sayı")
    else:
        print(number," sayısı tek sayı")
else:
    print("Sayı negatif")


# pass: Koşul bloklarında geçici olarak bir işlem yapmamak için pass kullanılır.
# Bu, daha sonra doldurulacak blokları oluştururken faydalıdır.
# Sayı Negatif Çift, Tek
number_pass=int(input("Lütfen sayı giriniz\n"))
if number_pass >0:
    if number_pass % 2 == 0:
        print("çift sayı")
        if number_pass % 2 == 0:
            pass #Daha sonra kod eklenecek
    else:
        print(number_pass," sayısı tek sayı")
else:
    print("Sayı negatif")
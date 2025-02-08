#####################################################################################
# Math
import math
from random import randint, uniform


#####################################################################################
#### Sabit Sayılar  #################################################################
print("PI: " ,math.pi)
print("E: " ,math.e)

#####################################################################################
#### Sayısal İşlemler Math ##########################################################
print("karekök: ",math.sqrt(16))
print("üslü: ",math.pow(2,5))
print("faktöriyel: ",math.factorial(4))
print("Ceil Yukarı Yuvarlamak: ",math.ceil(4.3))
print("Floor Aşağı Yuvarlamak: ",math.floor(4.3))



######################################################################################
number1=[1,2,3,4,5]
print("Max:", max(number1))
print("Min:", min(number1))
print("Sum:", sum(number1))
print("Average:", sum(number1)/ len(number1))

### Trigonometrik Math ##########################################################
print("SINUS: ",math.sin(math.pi/2))
print("Sinüs: " , str(math.sin(math.radians(90))))
print("Kosinüs: " , str(math.cos(math.radians(90))))
print("COSINUS: ",math.cos(math.pi/2))
print("Logaritma: " , str(math.log(100)))

print("Trigonometrik açıların radyan cevresi: " , str(math.radians(90)))
print("Trigonometrik açıların derece cevresi: " , str(math.degrees(math.pi/2)))

#######################################################################################
#### Sayısal İşlemler Rastgele  #######################################################
print("Rastgele Tam sayı: ",randint(1,100))
print("Rastgele Ondalık sayı: ",uniform(0,1))

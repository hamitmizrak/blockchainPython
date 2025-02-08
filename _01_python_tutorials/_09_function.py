##########################################################################################
#### Function ############################################################################
# : kullanım yerleri =>  for, if, function
# 1-) Parametresiz Returnsuz Function
def hesap_topla1():
    """ docstring
    Bu function parametresiz Returnsuz toplama yapar
    """
    sayi1=10
    sayi2=20
    sayi3=sayi1+sayi2
    print(sayi3)

# Function Çağır
hesap_topla1()
#################################################################################

# 2-) Parametreli Returnsuz Function
def hesap_topla2(sayi1,sayi2):
    """ docstring
     Bu function parametresiz Returnsuz toplama yapar
    """
    sayi3=sayi1+sayi2
    print(sayi3)

# Function Çağır
hesap_topla2(10,20)
#################################################################################

# 3-) Default Değerli Parametreli Returnsuz Function
def hesap_topla3(sayi1,sayi2=20):
    """ docstring
    Default Değerli Parametreli Returnsuz Function
    """
    sayi3=sayi1+sayi2
    print(f"sayi3: %s" %sayi3)

# Function Çağır
# hesap_topla3(10)
hesap_topla3(10,20)


#################################################################################
# 4-) Parametresiz Returnlu Function
def hesap_topla4():
    """ docstring
    Bu Parametresiz Returnlu Function toplama yapar
    """
    sayi1=10
    sayi2=20
    sayi3=sayi1+sayi2
    return sayi3

# Function Çağır
result4=hesap_topla4()
print(result4)

#################################################################################
# 5-) Parametreli Returnlu Function
def hesap_topla5(sayi1,sayi2=20):
    """ docstring
    Bu Parametreli Returnlu Function toplama yapar
    """
    sayi3=sayi1+sayi2
    return sayi3

# Function Çağır
result5=hesap_topla5(10)
print(result5)


#################################################################################
# 6-) Parametreli Function
global_variable = 10  # Global değişken tanımı fonksiyon dışında yapılır

def hesap_topla6():
    # global sadece mevcut bir global değişkene erişim sağlamak için kullanılır.
    global global_variable  # Mevcut global değişkene erişim
    global_variable=50
    # Local variables
    local_variable = 20
    print("local,global: ",global_variable + local_variable)

hesap_topla6()
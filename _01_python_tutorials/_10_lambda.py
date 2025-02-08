##########################################################################################
#### Lambda Expression ###################################################################

# Normal Function
def norm_topla(x,y):
    return x + y
# Çıktı
print(f"{norm_topla(10,20)}")

# Lamda Expression
# lambda yaz otomatik olarak özel lambda ekler
topla_lambda = lambda x,y:x+y
# Çıktı
print(f"{topla_lambda(10,20)}")

from datetime import datetime

#####################################################################
# Python Yıl bilgisi olarak formatter datetime modülünü kullanıyoruz.
# Şu anda ki zaman
current_time = datetime.now()
print(f"Şimdiki Zaman:{current_time}")

# Formatter
formatter_year_long = current_time.strftime("%Y-%m-%d")
print(f"Güncel Yıl: {formatter_year_long}")

# Formatter
formatter_year_short = current_time.strftime("%y")
print(f"Güncel Yıl: {formatter_year_short}")

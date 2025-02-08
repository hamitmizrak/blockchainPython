# import
from typing import List  # List type
import time  # Blok zaman damgası için kullandım
import json  # Blok verilerini JSON formatında saklamak istersek
import hashlib  # Hash fonksiyonlarını kullanmak içindir.


################################
# Fonksiyonlar

# Block Function
class Block:
    """
    Blockchain içindeki bir blok temsili
    """

    """
    __init__ : 
    Yeni bir nesne (object) oluşturulduğunda çalışır.
    Nesneye ait başlangıç değerlerini (attributes) tanımlar.
    return ifadesi kullanılmaz çünkü doğrudan nesneyi başlatır.

    self:
    self, bir sınıf içinde kullanılan özel bir değişkendir ve sınıfa ait özelliklere ve metotlara erişmeyi sağlar.
    Özellikleri:
    self, her nesneye özgü değişkenleri temsil eder.
    Sınıfın içindeki metotlarda, nesnenin kendi verilerine erişmesini sağlar.
    Python'da bir sınıf metodu içinde self yazılması zorunludur (ancak adı değiştirilebilir, yine de Python topluluğu self kullanır).
    """

    # Constructor
    def __init__(self, index: int, previous_hash: str, transactions: List[dict], nonce: int = 0):
        """
        Bir blok nesnesi oluşturur.

        bir sınıftan yeni bir nesne oluşturulduğunda, otomatik olarak çalışan özel bir metottur

        :param index: Blok zinciri içindeki sıra numarası (0'dan başlar).
        :param previous_hash: Önceki bloğun SHA-256 hash değeri.
        :param transactions: Blok içinde saklanan işlem listesi.
        :param nonce: Madencilik sürecinde kullanılan sayısal değer (başlangıç değeri 0).
        """
        self.index = index  # Blok numarası
        self.timestamp = time.time()  # Blok oluşturma zamanı
        self.previous_hash = previous_hash  # önceki bloğun hash değeri
        self.transactions = transactions  # Blokta yapılan işlemler
        self.nonce = nonce  # Nonce (Rastgele değer)
        self.hash = self.calculate_hash()  # Blok hash değeri hesaplayan fonksiyon

    # Calculate hash
    def calculate_hash(self):
        """
        Blok verilerini kullanarak hash değerini hesaplar ve döndürür
        """
        # Hash hesaplaması için bir string olarak birleştiriyoruz
        block_string = json.dumps(
            {
                'index': self.index,
                'timestamp': self.timestamp,
                'previous_hash': self.previous_hash,
                'transactions': self.transactions,
                'nonce': self.nonce
            }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()  # SHA-256 hash üretimi


# Blockchain Function
class Blockchain:
    """
    Blockchain, bir listeye bloklar ekleyerek oluşturulur ve blokları yönetir
    """

    def __init__(self):
        self.chain: List[Block] = []  # Blokchain zinciri
        self.pending_transactions: List[dict] = []  # Bekleyen işlemler listesi
        self.difficulty = 4  # Blok hash değerinin uzunluk katsayısı (Proof of Work madenciliği zorluk seviyesi)
        self.create_genesis_block()  # İlk bloğu oluştur

    # İlk bloğu oluşuran function ilk değer:0 (Genesis Block)
    def create_genesis_block(self):
        """ Blockchain ilk(genesis) bloğu oluşturur."""
        genesis_block = Block(0, "0", [], nonce=0)
        self.chain.append(genesis_block)  # Genesis bloğunu zincire ekler

    # YEni bir işlem ekleyen fonskiyon
    def add_transaction(self, sender: str, recipient: str, amount: float):
        """ Yeni bir işlem bloğuna ekler."""
        self.pending_transactions.append({
            "sender": sender,
            "recipient": recipient,
            "amount": amount
        })

    # Yeni bir blok madenciliğini yaparak blockchain'e eklesin
    def mine_block(self):
        """
        Yeni bir blok madenciliğini yaparak blockchain'e ekler.
        """
        if not self.pending_transactions:
            print("İşlem kuyruğu boştur, madencilik için yapılacak işlem yoktur")
            return  None

        # Zincirin en son bloğunu al
        last_block = self.chain[-1]

        # yeni blok
        new_block= Block(
            index=len(self.chain),
            previous_hash=last_block.hash,
            transactions=self.pending_transactions,
            nonce=0
        )

        # Proof of Work madenciliği
        # (Belirli bir sayıda sıfır ile başlayan ve hash bulana kadar nonce artır)
        while not new_block.hash.startswith("0" * self.difficulty):
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()
        print(f"Yeni blok madenciliğini tamamlandı: {new_block.hash}")
        # YEni bloğu blockchain'e ekle
        self.chain.append(new_block)

        # İşlem listesini sıfırlamalıyız
        self.pending_transactions=[]

    # Blockchain için veri bütünlüğünü doğrulansın
    #def is_chain_valid(self):

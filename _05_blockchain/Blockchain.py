# import
from typing import List # List type
import time  # Blok zaman damgası için kullandım
import json # Blok verilerini JSON formatında saklamak istersek
import hashlib  # Hash fonksiyonlarını kullanmak içindir.

################################
# Fonksiyonlar

# Block Function
class Block:
    """
    Blockchain içindeki bir blok temsili
    """
    # Constructor
    def __init__(self, index:int, previous_hash:str, transactions: List[dict],  nonce:int=0):
        self.index = index  # Blok numarası
        self.timestamp = time.time() # Blok oluşturma zamanı
        self.previous_hash = previous_hash # önceki bloğun hash değeri
        self.transactions = transactions # Blokta yapılan işlemler
        self.nonce = nonce  # Nonce (Rastgele değer)
        self.hash = self.calculate_hash()  # Blok hash değeri

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
        return hashlib.sha256(block_string).hexdigest() # SHA-256 hash üretimi

# Blockchain Function
class Blockchain:
    """
    Blockchain, bir listeye bloklar ekleyerek oluşturulur ve blokları yönetir
    """
    def __init__(self):
        self.chain:List[Block]=[] # Blokchain zinciri
        self.pending_transactions: List[dict] = []  # Bekleyen işlemler listesi
        self.difficulty = 4  # Blok hash değerinin uzunluk katsayısı (Proof of Work madenciliği zorluk seviyesi)
        self.create_genesis_block() # İlk bloğu oluştur

    # İlk bloğu oluşuran function ilk değer:0 (Genesis Block)
    def create_genesis_block(self):
        """ Blockchain ilk(genesis) bloğu oluşturur."""
        genesis_block = Block(0, "0", [],nonce=0)
        self.chain.append(genesis_block) # Genesis bloğunu zincire ekler

    # YEni bir işlem ekleyen fonskiyon
    def add_transaction(self, sender:str, recipient:str, amount:float):
        """ Yeni bir işlem bloğuna ekler."""
        self.pending_transactions.append({
            "sender":sender,
            "recipient": recipient,
            "amount": amount
        })

    # Yeni bir blok madenciliğini yaparak blockchain'e eklesin
    #def mine_block(self):

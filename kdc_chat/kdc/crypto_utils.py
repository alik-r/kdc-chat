import datetime
import random
import ast
import uuid

class MiniRSA:
    def __init__(self, bits: int = 8):
        self.bits = bits
        self.public_key, self.private_key = self.generate_keypair()

    def set_keys(self, public_key: tuple[int, int], private_key: tuple[int, int]) -> None:
        self.public_key = public_key
        self.private_key = private_key

    def load_keypair_from_str(self, keypair_str: str) -> None:
        keypair = ast.literal_eval(keypair_str)
        self.set_keys(keypair[0], keypair[1])

    @staticmethod
    def get_public_key_from_keypair_str(keypair_str: str) -> tuple[int, int]:
        keypair = ast.literal_eval(keypair_str)
        return keypair[0]
    
    @staticmethod
    def get_private_key_from_keypair_str(keypair_str: str) -> tuple[int, int]:
        keypair = ast.literal_eval(keypair_str)
        return keypair[1]
    
    def is_prime(self, n: int) -> bool:
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0 or n % 3 == 0:
            return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                return False
            i += 6
        return True

    def generate_prime(self) -> int:
        while True:
            p = random.randint(10, 99)
            if self.is_prime(p):
                return p

    def gcd(self, a: int, b : int) -> int:
        while b != 0:
            a, b = b, a % b
        return a

    def extended_gcd(self, a: int, b: int) -> tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        else:
            g, x, y = self.extended_gcd(b % a, a)
            return (g, y - (b // a) * x, x)

    def mod_inv(self, a: int, m: int) -> int:
        g, x, _ = self.extended_gcd(a, m)
        if g != 1:
            raise Exception("Modular inverse does not exist")
        else:
            return x % m

    def generate_keypair(self) -> tuple[tuple[int, int], tuple[int, int]]:
        p = self.generate_prime()
        q = self.generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        while True:
            e = random.randrange(2, phi)
            if self.gcd(e, phi) == 1:
                break
        d = self.mod_inv(e, phi)
        return ((e, n), (d, n))

    def encrypt(self, plaintext: str) -> str:
        e, n = self.public_key
        ciphertext = [pow(ord(char), e, n) for char in plaintext]
        return ",".join(map(str, ciphertext))

    @staticmethod
    def encrypt_with_key(plaintext: str, public_key: tuple[int, int]) -> str:
        e, n = public_key
        ciphertext = [pow(ord(char), e, n) for char in plaintext]
        return ",".join(map(str, ciphertext))
    
    @staticmethod
    def decrypt_with_key(ciphertext: str, private_key: tuple[int, int]) -> str:
        d, n = private_key
        decrypted_message = [chr(pow(int(char), d, n)) for char in ciphertext.split(",")]
        return "".join(decrypted_message)
    
    @staticmethod
    def encrypt_with_keypair(plaintext: str | int, keypair_str: str) -> str:
        if type(plaintext) == int:
            plaintext = str(plaintext)
        public_key = MiniRSA.get_public_key_from_keypair_str(keypair_str)
        return MiniRSA.encrypt_with_key(plaintext, public_key)
    
    @staticmethod
    def decrypt_with_keypair(ciphertext: str, keypair_str: str) -> str:
        private_key = MiniRSA.get_private_key_from_keypair_str(keypair_str)
        return MiniRSA.decrypt_with_key(ciphertext, private_key)

    def decrypt(self, ciphertext: str) -> str:
        d, n = self.private_key
        decrypted_message = [chr(pow(int(char), d, n)) for char in ciphertext.split(",")]
        return "".join(decrypted_message)
    
    def __str__(self) -> str:
        return f"({self.public_key}, {self.private_key})"

class Caesar:
    @staticmethod
    def generate_key() -> int:
        return random.randint(1, 25)

    @staticmethod
    def encrypt(text: str | int, key: str | int):
        if type(text) == int:
            text = str(text)

        if type(key) != int:
            key = int(key)
        
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                shifted = ord(char) + key
                if char.islower():
                    if shifted > ord("z"):
                        shifted -= 26
                    elif shifted < ord("a"):
                        shifted += 26
                elif char.isupper():
                    if shifted > ord("Z"):
                        shifted -= 26
                    elif shifted < ord("A"):
                        shifted += 26
                encrypted_text += chr(shifted)
            else:
                encrypted_text += char
        return encrypted_text

    @staticmethod
    def decrypt(text : str | int, key: str | int):
        if type(key) != int:
            key = int(key)
        return Caesar.encrypt(text, -key)

def generate_rsa_keypair():
    rsa = MiniRSA()
    return str(rsa) 

def generate_timestamp() -> int:
    return int(datetime.datetime.now().timestamp() * 1e6)

def generate_nonce() -> str:
    return uuid.uuid4().hex

def print_with_timestamp(message: str) -> None:
    print(f"[{datetime.datetime.now()}] {message}")
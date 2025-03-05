import base64
import os
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

def xor_encrypt(data, key):
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return base64.b64encode(encrypted.encode()).decode()

def xor_decrypt(encoded_data, key):
    encrypted = base64.b64decode(encoded_data.encode()).decode()
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted))

def xor_encrypt_file(input_path: str, output_path: str, key: str):
    """Enkripsi file menggunakan XOR."""
    if not key:
        raise ValueError("Kunci tidak boleh kosong!")

    with open(input_path, "rb") as f:
        data = f.read()

    key_bytes = key.encode()
    encrypted_data = bytearray(len(data))

    for i in range(len(data)):
        encrypted_data[i] = data[i] ^ key_bytes[i % len(key_bytes)]

    with open(output_path, "wb") as f:
        f.write(encrypted_data)


def xor_decrypt_file(input_path: str, output_path: str, key: str):
    """Dekripsi file menggunakan XOR."""
    xor_encrypt_file(input_path, output_path, key)


def rc4_crypt(data, key):
    """Enkripsi atau dekripsi data menggunakan RC4."""
    S = list(range(256))
    j = 0
    out = bytearray()
    key = key.encode() if isinstance(key, str) else key
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)


def rc4_encrypt(text: str, key: str) -> str:
    """Enkripsi teks menggunakan RC4 dan mengembalikan hasil dalam format hex."""
    encrypted_bytes = rc4_crypt(text.encode(), key)
    return encrypted_bytes.hex()  


def rc4_decrypt(hex_text: str, key: str) -> str:
    """Dekripsi teks RC4 dari format hex kembali ke string asli."""
    encrypted_bytes = bytes.fromhex(hex_text) 
    decrypted_bytes = rc4_crypt(encrypted_bytes, key)
    return decrypted_bytes.decode(errors="ignore") 
def rc4_encrypt_file(input_path: str, output_path: str, key: str):
    """Enkripsi file menggunakan RC4."""
    with open(input_path, "rb") as f:
        data = f.read() 

    encrypted_data = rc4_crypt(data, key)  

    with open(output_path, "wb") as f:
        f.write(encrypted_data)  


def rc4_decrypt_file(input_path: str, output_path: str, key: str):
    """Dekripsi file menggunakan RC4."""
    with open(input_path, "rb") as f:
        encrypted_data = f.read() 
    decrypted_data = rc4_crypt(encrypted_data, key) 
    with open(output_path, "wb") as f:
        f.write(decrypted_data)  

def generate_aes_key(password):
    return password[:16].encode().ljust(16, b"\0")

def aes_encrypt_ecb(data, password):
    key = generate_aes_key(password)
    cipher = AES.new(key, AES.MODE_ECB)
    data_padded = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(data_padded)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt_ecb(ciphertext, password):
    key = generate_aes_key(password)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted_data.decode()

def aes_encrypt_cbc(data, password):
    key = generate_aes_key(password)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(data_padded)
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt_cbc(ciphertext, password):
    key = generate_aes_key(password)
    raw_data = base64.b64decode(ciphertext)
    iv, ciphertext = raw_data[:AES.block_size], raw_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

def aes_encrypt_ctr(data, password):
    key = generate_aes_key(password)
    nonce = get_random_bytes(8)  
    ctr = Counter.new(64, prefix=nonce, initial_value=0)  
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    ciphertext = cipher.encrypt(data.encode())
    return base64.b64encode(nonce + ciphertext).decode() 

def aes_decrypt_ctr(ciphertext, password):
    key = generate_aes_key(password)
    raw_data = base64.b64decode(ciphertext)
    nonce, ciphertext = raw_data[:8], raw_data[8:] 
    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode()

def aes_encrypt_file(input_path, output_path, password, mode="ECB"):
    key = generate_aes_key(password)

    with open(input_path, "rb") as f:
        data = f.read() 

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    
    elif mode == "CBC":
        iv = get_random_bytes(16) 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))  
    
    elif mode == "CTR":
        nonce = get_random_bytes(8) 
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        encrypted_data = nonce + cipher.encrypt(data)  

    with open(output_path, "wb") as f:
        f.write(encrypted_data)  

def aes_decrypt_file(input_path, output_path, password, mode="ECB"):
    key = generate_aes_key(password)

    with open(input_path, "rb") as f:
        encrypted_data = f.read()  

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    elif mode == "CBC":
        iv, encrypted_data = encrypted_data[:16], encrypted_data[16:]  
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    elif mode == "CTR":
        nonce, encrypted_data = encrypted_data[:8], encrypted_data[8:] 
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)  


def generate_des_key(password):
    return password[:8].encode().ljust(8, b"\0")  

def generate_des_key(password):
    return password[:8].encode().ljust(8, b"\0")

def des_encrypt_ecb(data, password):
    key = generate_des_key(password)
    cipher = DES.new(key, DES.MODE_ECB)
    data_padded = pad(data.encode(), DES.block_size)
    ciphertext = cipher.encrypt(data_padded)
    return base64.b64encode(ciphertext).decode()

def des_decrypt_ecb(ciphertext, password):
    key = generate_des_key(password)
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(ciphertext)), DES.block_size)
    return decrypted_data.decode()

def des_encrypt_cbc(data, password):
    key = generate_des_key(password)
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data_padded = pad(data.encode(), DES.block_size)
    ciphertext = cipher.encrypt(data_padded)
    return base64.b64encode(iv + ciphertext).decode()

def des_decrypt_cbc(ciphertext, password):
    key = generate_des_key(password)
    raw_data = base64.b64decode(ciphertext)
    iv, ciphertext = raw_data[:DES.block_size], raw_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_data.decode()

def des_encrypt_ctr(data, password):
    key = generate_des_key(password)
    nonce = get_random_bytes(4)  
    ctr = Counter.new(32, prefix=nonce, initial_value=0)  
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    
    ciphertext = cipher.encrypt(data.encode())  
    return base64.b64encode(nonce + ciphertext).decode()

def des_decrypt_ctr(ciphertext, password):
    key = generate_des_key(password)
    raw_data = base64.b64decode(ciphertext)
    nonce, ciphertext = raw_data[:4], raw_data[4:] 
    ctr = Counter.new(32, prefix=nonce, initial_value=0)  
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    decrypted_data = cipher.decrypt(ciphertext)  
    return decrypted_data.decode()

def des_encrypt_file(input_path, output_path, password, mode="ECB"):
    key = generate_des_key(password)

    with open(input_path, "rb") as f:
        data = f.read()  

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(data, DES.block_size))
    
    elif mode == "CBC":
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(data, DES.block_size))  
    
    elif mode == "CTR":
        nonce = get_random_bytes(4)  
        ctr = Counter.new(32, prefix=nonce, initial_value=0)
        cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
        encrypted_data = nonce + cipher.encrypt(data)  

    with open(output_path, "wb") as f:
        f.write(encrypted_data)  

def des_decrypt_file(input_path, output_path, password, mode="ECB"):
    key = generate_des_key(password)

    with open(input_path, "rb") as f:
        encrypted_data = f.read()  

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
    
    elif mode == "CBC":
        iv, encrypted_data = encrypted_data[:8], encrypted_data[8:]  
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
    
    elif mode == "CTR":
        nonce, encrypted_data = encrypted_data[:4], encrypted_data[4:]  
        ctr = Counter.new(32, prefix=nonce, initial_value=0)
        cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
        decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)  

import base64

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    out = []

    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)

def rc4_encrypt(data, key):
    encrypted = rc4_crypt(data, key)
    return base64.b64encode(encrypted.encode()).decode()

def rc4_decrypt(encoded_data, key):
    encrypted = base64.b64decode(encoded_data).decode()
    return rc4_crypt(encrypted, key)

def rc4_encrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted_data = rc4_crypt(data.decode(errors="ignore"), key).encode()

    with open(output_path, "wb") as f:
        f.write(encrypted_data)

def rc4_decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        encrypted_data = f.read().decode(errors="ignore")

    decrypted_data = rc4_crypt(encrypted_data, key).encode()

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

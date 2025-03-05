import os
import struct
import random
import string
from xor import aes_encrypt_file, aes_decrypt_file, des_encrypt_file, des_decrypt_file
from xor import xor_encrypt, xor_decrypt, xor_encrypt_file, xor_decrypt_file 
from xor import rc4_encrypt_file, rc4_decrypt_file

def generate_random_filename():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

def encrypt_file_with_metadata(input_path, output_folder, password, mode="ECB", algorithm="AES"):
    file_extension = os.path.splitext(input_path)[1]
    random_filename = generate_random_filename()
    output_path = os.path.join(output_folder, random_filename)

    if algorithm == "AES":
        aes_encrypt_file(input_path, output_path, password, mode)
    elif algorithm == "DES":
        des_encrypt_file(input_path, output_path, password, mode)
    elif algorithm == "XOR":
        xor_encrypt_file(input_path, output_path, password)
    elif algorithm == "RC4":
        rc4_encrypt_file(input_path, output_path, password)
    else:
        raise ValueError("Algoritma tidak didukung. Gunakan 'AES', 'DES', 'XOR', atau 'RC4'.")

    with open(output_path, "rb") as f:
        encrypted_data = f.read()
    metadata = struct.pack("I", len(file_extension)) + file_extension.encode()
    with open(output_path, "wb") as f:
        f.write(metadata + encrypted_data)

    return output_path

def decrypt_file_with_metadata(input_path, output_folder, password, mode="ECB", algorithm="AES"):
    with open(input_path, "rb") as f:
        metadata_size = struct.calcsize("I")
        metadata_raw = f.read(metadata_size)
        extension_length = struct.unpack("I", metadata_raw)[0]
        file_extension = f.read(extension_length).decode()
        encrypted_data = f.read()
    original_filename = generate_random_filename() + file_extension
    output_path = os.path.join(output_folder, original_filename)
    temp_encrypted_path = input_path + "_temp"
    with open(temp_encrypted_path, "wb") as f:
        f.write(encrypted_data)
    if algorithm == "AES":
        aes_decrypt_file(temp_encrypted_path, output_path, password, mode)
    elif algorithm == "DES":
        des_decrypt_file(temp_encrypted_path, output_path, password, mode)
    elif algorithm == "XOR":
        xor_decrypt_file(temp_encrypted_path, output_path, password)
    elif algorithm == "RC4":
        rc4_decrypt_file(temp_encrypted_path, output_path, password)
    else:
        raise ValueError("Algoritma tidak didukung. Gunakan 'AES', 'DES', 'XOR', atau 'RC4'.")

    os.remove(temp_encrypted_path)

    return output_path

import os
from flask import Flask, render_template, request, send_file, jsonify
from xor import xor_encrypt, xor_decrypt
from xor import rc4_crypt, rc4_encrypt, rc4_decrypt
from xor import (
    aes_encrypt_ecb, aes_decrypt_ecb,
    aes_encrypt_cbc, aes_decrypt_cbc,
    aes_encrypt_ctr, aes_decrypt_ctr,
    des_encrypt_ecb, des_decrypt_ecb,
    des_encrypt_cbc, des_decrypt_cbc,
    des_encrypt_ctr, des_decrypt_ctr
)
from file_encryptor import encrypt_file_with_metadata, decrypt_file_with_metadata

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    file_result = None
    action = request.form.get("action", "encrypt")
    method = request.form.get("method", "xor")
    mode = request.form.get("mode", "ECB")
    key = request.form.get("key", "")

    # Validasi panjang kunci
    if method == "aes" and len(key) != 16:
        result = "⚠️ Kunci AES harus 16 karakter!"
    elif method == "des" and len(key) != 8:
        result = "⚠️ Kunci DES harus 8 karakter!"
    else:
        # Proses teks
        if "text" in request.form and request.form["text"]:
            text = request.form["text"]
            try:
                if action == "encrypt":
                    if method == "xor":
                        result = xor_encrypt(text, key)
                    elif method == "rc4":
                        result = rc4_encrypt(text, key)
                    elif method == "aes":
                        if mode == "ECB":
                            result = aes_encrypt_ecb(text, key)
                        elif mode == "CBC":
                            result = aes_encrypt_cbc(text, key)
                        elif mode == "CTR":
                            result = aes_encrypt_ctr(text, key)
                    elif method == "des":
                        if mode == "ECB":
                            result = des_encrypt_ecb(text, key)
                        elif mode == "CBC":
                            result = des_encrypt_cbc(text, key)
                        elif mode == "CTR":
                            result = des_encrypt_ctr(text, key)
                else:
                    if method == "xor":
                        result = xor_decrypt(text, key)
                    elif method == "rc4":
                        result = rc4_decrypt(text, key)
                    elif method == "aes":
                        if mode == "ECB":
                            result = aes_decrypt_ecb(text, key)
                        elif mode == "CBC":
                            result = aes_decrypt_cbc(text, key)
                        elif mode == "CTR":
                            result = aes_decrypt_ctr(text, key)
                    elif method == "des":
                        if mode == "ECB":
                            result = des_decrypt_ecb(text, key)
                        elif mode == "CBC":
                            result = des_decrypt_cbc(text, key)
                        elif mode == "CTR":
                            result = des_decrypt_ctr(text, key)
            except Exception:
                result = "❌ Error: Data tidak valid!"

        # Proses file
        elif "file" in request.files:
            file = request.files["file"]
            if file.filename:
                filename = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filename)

                try:
                    if action == "encrypt":
                        output_filename = encrypt_file_with_metadata(filename, UPLOAD_FOLDER, key, mode, method.upper())
                    else:
                        output_filename = decrypt_file_with_metadata(filename, UPLOAD_FOLDER, key, mode, method.upper())

                    file_result = output_filename
                except Exception:
                    result = "❌ Error: File tidak valid atau terjadi kesalahan!"
    
    return render_template("index.html", result=result, file_result=file_result, action=action, method=method, mode=mode)

@app.route("/download/<path:filename>")
def download_file(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)

README - Aplikasi Kriptografi

Deskripsi
Aplikasi ini adalah implementasi berbagai algoritma kriptografi, termasuk Simple XOR, RC4, DES, dan AES dalam berbagai mode operasi (ECB, CBC, dan CTR). Aplikasi ini dikembangkan menggunakan bahasa Python dan framework Flask untuk memberikan antarmuka berbasis web.

Persyaratan Sistem
Sebelum menjalankan aplikasi, pastikan sistem Anda telah menginstal:
1. Python (versi 3.6 atau lebih baru)
2. Pip (Python package manager)

Struktur Folder
📂
├── app.py                 # File utama untuk menjalankan Flask
├── file_encryptor.py      # Modul untuk enkripsi dan dekripsi file
├── xor.py                 # Implementasi algoritma XOR, RC4, AES, dan DES
├── xrc4.py                # Implementasi tambahan untuk RC4
├── templates/
│   ├── index.html        # Halaman utama antarmuka web
├── static/
│   ├── style.css         # File styling
├── uploads/              # Folder penyimpanan file sementara

Cara Menjalankan Aplikasi
1. Masuk ke direktori file : "cd (lokasifile)"
2. Jalankan server Flask : "python app.py"
3. Akses aplikasi melalui browser, buka browser dan masuk ke: "http://127.0.0.1:5000/"

Cara Menggunakan Aplikasi
1. Pilih metode enkripsi atau dekripsi
2. Masukkan teks atau unggah file
3. Masukkan kunci yang sesuai: AES (16 karakter), DES (8 karakter)
4. Pilih mode operasi : Simple XOR, RC4, DES (ECB, CBC, Counter), dan AES (ECB, CBC, Counter) 
5. Klik tombol "Proses" untuk melakukan enkripsi atau dekripsi
6. Lihat hasil enkripsi atau unduh file hasilnya dengan klik tombol "Unduh hasil"

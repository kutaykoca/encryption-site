# Kutay KOCA - 191522028
# https://github.com/kutaykoca/encryption-site

from flask import Flask, request, send_file, render_template
import codecs

# RC4 algoritması
def rc4(key, plaintext):
    S = list(range(256))
    j = 0
    out = []
    key = bytes(key, 'utf-8')
    # key scheduling algorithm
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # pseudo-random generation algorithm
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

# RC4 şifre çözme fonksiyonu
def decrypt_rc4(key, ciphertext):
    return rc4(key, ciphertext)

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Dosyayı oku
        file = request.files['file']
        data = file.read()
        if request.form['submit_button'] == 'Şifrele':
            # Anahtar üret
            key = "mykey"
            key_hex = codecs.encode(key.encode(), 'hex')
            # Dosyayı şifrele
            ciphertext = rc4(key, data)
            # Şifrelenmiş veriyi dosyaya yaz
            with open("encrypted.txt", "wb") as f:
                f.write(ciphertext)
                #f.write(f'\n{key_hex}'.encode())
                f.write(f'\n{codecs.encode(key.encode(), "hex").decode()}'.encode())
            # Şifrelenmiş dosyayı kullanıcıya gönder
            return send_file("encrypted.txt", as_attachment=True)
        elif request.form['submit_button'] == 'Şifre Çöz':
            # Son satırda anahtar var
            data = data.split(b'\n')
            ciphertext = data[0]
            key_hex = data[1]
            # Anahtarı hex'ten string'e çevir
            key = codecs.decode(key_hex.strip(), 'hex').decode()
            # Dosyayı şifre çöz
            decrypted_data = decrypt_rc4(key, ciphertext)
            # Şifresi çözülmüş veriyi dosyaya yaz
            with open("decrypted.txt", "wb") as f:
                f.write(decrypted_data)
            # Şifresi çözülmüş dosyayı kullanıcıya gönder
            return send_file("decrypted.txt", as_attachment=True)
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
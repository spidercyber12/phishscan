# PhishScan

**Analisis URL untuk mendeteksi phishing — tanpa API key, tanpa setup ribet.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Repo:** https://github.com/spidercyber12/phishscan

---

## Fitur

- **Zero dependency** — berjalan dengan stdlib Python
- **Tanpa API key** — tidak butuh daftar layanan pihak ketiga
- **7 modul analisis** — URL, heuristik, DNS, TLS, redirect, HTML, skor
- **SSRF guard** — blokir otomatis request ke jaringan internal
- **Output JSON** — cocok untuk otomasi

---

## Cara download / install

### Clone via Git

    git clone https://github.com/spidercyber12/phishscan.git
    cd phishscan

### Install sebagai command global

    pip install git+https://github.com/spidercyber12/phishscan.git

---

## Penjelasan setiap perintah

### 1. Scan URL (perintah dasar)

    python phishscan.py "<url>"

Perintah utama. Menganalisis satu URL melalui 7 tahap: parse URL, heuristik, DNS, TLS, redirect, HTML, skor.

URL boleh tanpa skema — otomatis ditambah http://

    python phishscan.py example.com

Exit code: 0 (sukses, apapun verdict-nya).

### 2. --help / -h

    python phishscan.py --help
    python phishscan.py -h

Tampilkan bantuan lengkap lalu keluar. Isinya: deskripsi tool, daftar opsi, contoh pemakaian, tabel skor, environment variable, link repo.

Dipakai saat pertama kali pakai, atau lupa nama opsi.

### 3. --version / -V

    python phishscan.py --version
    python phishscan.py -V

Tampilkan versi lalu keluar. Output: PhishScan 0.1.0

Dipakai untuk cek versi terinstall atau lapor bug.

### 4. --json

    python phishscan.py --json "<url>"

Output JSON, bukan tabel berwarna. Cocok untuk dipipe ke jq, disimpan ke file log, atau integrasi ke sistem lain.

Isi JSON: url, score, verdict, indicators, notes, fatal_error.

Contoh:

    python phishscan.py --json "https://example.com"
    python phishscan.py --json "https://example.com" | jq .score
    python phishscan.py --json "https://example.com" > hasil.json

--json otomatis mematikan warna dan progress log.

### 5. --verbose / -v

    python phishscan.py --verbose "<url>"
    python phishscan.py -v "<url>"

Tampilkan timing setiap modul. Output tambahan:

    [1/6] parse URL ...
    [2/6] heuristics ...
    [3/6] DNS lookup example.com ...
    [4/6] SSL inspect example.com ...
    [5/6] redirect trace ...
    [6/6] HTML scan ...

      Timing:
        url_parser        0.2 ms   ok
        heuristics        1.5 ms   ok
        dns             147.8 ms   ok
        ssl             191.1 ms   ok
        redirect        114.7 ms   ok
        html            143.2 ms   ok

Dipakai untuk debug atau cek modul mana yang lambat / error / di-skip.

### 6. --no-color

    python phishscan.py --no-color "<url>"

Matikan warna ANSI. Output jadi teks polos.

Dipakai kalau output disimpan ke file/log, dipipe ke tool lain (grep/awk), atau terminal tidak mendukung warna.

Setara dengan env NO_COLOR=1.

### 7. Tanpa argumen

    python phishscan.py

Kalau dijalankan tanpa URL, PhishScan tidak error — tapi menampilkan pesan ramah + contoh + bantuan otomatis.

Exit code: 0.

### 8. NO_COLOR

    NO_COLOR=1 python phishscan.py "<url>"

Environment variable standar (mengikuti https://no-color.org). Setara dengan flag --no-color.

Bisa di-set global di shell profile:

    export NO_COLOR=1

Dipakai di CI/CD pipeline atau saat jalan dari script lain.

### 9. PHISHSCAN_YES

    PHISHSCAN_YES=1 python phishscan.py "<url>"

Auto-install dependency opsional (dnspython, cryptography) tanpa bertanya y/N.

Default-nya PhishScan akan tanya:

      Paket 'dnspython' belum terpasang.
      Kegunaan: Cek MX & NS record (lebih akurat)
      Install sekarang? [y/N]:

Prompt ini bikin hang di CI / script otomatis. Set PHISHSCAN_YES=1 untuk auto-jawab y.

Kalau paket sudah ada, tidak install ulang.

### 10. PHISHSCAN_ALLOW_PRIVATE

    PHISHSCAN_ALLOW_PRIVATE=1 python phishscan.py "http://192.168.1.1"

Menonaktifkan SSRF guard — mengizinkan PhishScan mengakses IP privat / loopback / link-local.

Default: SSRF guard aktif. Request ke IP berikut diblokir dengan kode SSRF_BLOCKED:

- 127.0.0.0/8, ::1 (loopback)
- 10/8, 172.16/12, 192.168/16 (privat)
- 169.254/16, fe80::/10 (link-local / metadata cloud)
- Reserved & multicast

Dipakai untuk scan lab / server internal milik sendiri. Hanya pakai di lingkungan yang Anda miliki / punya izin.

### Ringkasan semua perintah

| Perintah / Env | Fungsi |
|---|---|
| python phishscan.py "<url>" | Scan URL |
| --help / -h | Bantuan lengkap |
| --version / -V | Versi tool |
| --json | Output JSON |
| --verbose / -v | Timing per modul |
| --no-color | Matikan warna |
| (tanpa argumen) | Tampil help otomatis |
| NO_COLOR=1 | Matikan warna (env) |
| PHISHSCAN_YES=1 | Auto-install dependency (env) |
| PHISHSCAN_ALLOW_PRIVATE=1 | Izinkan scan IP privat (env) |

---

## Contoh output

### Scan URL aman

    python phishscan.py "https://google.com"

      URL      : https://google.com
      Skor     :   0/100
      Verdict  : AMAN

      Tidak ada indikator mencurigakan.

### Scan URL phishing

    python phishscan.py "http://paypa1-login.tk/verify"

      URL      : http://paypa1-login.tk/verify
      Skor     : 100/100
      Verdict  : BERBAHAYA

      Indikator (5):
        [ 45] Mirip "paypal.com"  TYPOSQUAT
        [ 30] Host tidak bisa di-resolve  UNRESOLVED
        [ 25] TLD ".tk" sering dipakai phishing  SUSPICIOUS_TLD
        [ 15] Kata kunci mencurigakan  SUSPICIOUS_KEYWORD
        [ 10] Tidak pakai HTTPS  HTTP_NO_TLS

      BAHAYA. Jangan buka di browser, jangan masukkan kredensial.

### Output JSON

    python phishscan.py --json "https://example.com"

    {
      "url": "https://example.com",
      "score": 0,
      "verdict": "safe",
      "indicators": [],
      "notes": [],
      "fatal_error": null
    }

---

## Skor & verdict

| Skor | Verdict | Arti |
|---|---|---|
| 0-19 | AMAN | Tidak ada indikator mencurigakan |
| 20-49 | MENCURIGAKAN | Ada beberapa tanda, hati-hati |
| 50-74 | KEMUNGKINAN BESAR PHISHING | Jangan masukkan data apapun |
| 75-100 | BERBAHAYA | Jangan buka sama sekali |

---

## Yang diperiksa

| Modul | Deteksi |
|---|---|
| URL Parser | Struktur URL, IP langsung, shortener, karakter aneh, subdomain berlebih |
| Heuristics | Typosquatting, kata kunci login, TLD murah, file berbahaya, punycode |
| DNS | A/AAAA, MX, NS record |
| TLS/SSL | Sertifikat kadaluarsa, self-signed, hostname mismatch |
| Redirect | Rantai redirect + SSRF guard per hop |
| HTML | Form password lintas domain, iframe tersembunyi, meta refresh, blob base64 |

---

## Keamanan

PhishScan memblokir semua request ke:

- Loopback (127.0.0.0/8, ::1)
- IP privat (10/8, 172.16/12, 192.168/16, fc00::/7)
- Link-local & metadata cloud (169.254/16, fe80::/10)
- Reserved & multicast

Guard berlaku di setiap hop redirect, bukan cuma URL awal.

---

## Lisensi

MIT

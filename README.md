# PhishScan

Analisis URL untuk mendeteksi phishing — tanpa API key, tanpa setup ribet.

Cukup Python 3.8+ dan internet. Dependency opsional (dnspython, cryptography)
akan ditawarkan otomatis saat pertama dijalankan.

## Cara pakai

    git clone <repo> phishscan
    cd phishscan
    python phishscan.py "http://suspicious-site.tk/login"

## Opsi CLI

- `--json`         : output JSON mentah
- `--verbose` / -v : tampilkan timing per modul
- `--no-color`     : matikan warna (untuk pipe/log)
- `--help` / -h    : bantuan

## Environment variable

- `NO_COLOR=1`                 : matikan warna
- `PHISHSCAN_YES=1`            : auto-install dependency opsional
- `PHISHSCAN_ALLOW_PRIVATE=1`  : izinkan scan IP privat (hati-hati!)

## Yang diperiksa

- URL parsing   : struktur, IP langsung, shortener, karakter aneh
- Heuristik     : typosquatting, kata kunci login, TLD murah
- DNS           : A/AAAA, MX, NS record
- TLS           : sertifikat kadaluarsa, self-signed, hostname mismatch
- Redirect      : rantai redirect + SSRF guard per hop
- HTML          : form password lintas domain, iframe tersembunyi, meta refresh

## Keamanan

PhishScan memblokir semua request ke:

- Loopback (127.0.0.0/8, ::1)
- IP privat (10/8, 172.16/12, 192.168/16, fc00::/7)
- Link-local & metadata cloud (169.254/16, fe80::/10)
- Reserved & multicast

Guard ini berlaku di setiap hop redirect, bukan cuma URL awal.

## Lisensi

MIT

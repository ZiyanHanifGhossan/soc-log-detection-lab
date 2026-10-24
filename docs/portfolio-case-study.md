# Studi Kasus: Deteksi Percobaan Login di Honeypot Cowrie

## Tujuan

Menganalisis apakah login gagal terkonsentrasi pada akun dan alamat sumber tertentu, lalu mencari pola satu sumber yang mencoba banyak nilai username dalam waktu singkat.

## Ruang lingkup data

- Sumber: Salty Seagull Cowrie honeynet, berkas tanggal 3 April 2025; waktu UTC.
- Total 669 event: 197 login gagal, 236 event koneksi, dan 236 event sesi ditutup.
- Seluruh 236 sesi menggunakan Telnet. Berkas tidak memiliki event login berhasil.
- Data adalah aktivitas yang direkam oleh honeypot; alamat IP telah dianonimkan dan bukan identitas pelaku yang terverifikasi.

## Metode

- Aturan 1: sedikitnya 5 login gagal untuk pasangan username dan IP yang sama dalam 10 menit.
- Aturan 2: login berhasil dalam 2 menit setelah kegagalan terakhir pada pasangan yang memicu Aturan 1.
- Aturan 3: sedikitnya 5 nilai username berbeda dari satu IP dalam 10 menit sebagai kandidat password spraying.
- Event tanpa username dikeluarkan dari analisis per akun. Password dan message tidak digunakan.

## Hasil

| IP sumber (anonim) | Login gagal | Nilai username berbeda | Sesi gagal | Aturan 1 | Aturan 3 |
|---|---:|---:|---:|---|---|
| 198.5.233.14 | 90 | 17 | 5 | root 51; admin 21 | Kandidat |
| 36.157.238.137 | 90 | 17 | 5 | root 51; admin 21 | Kandidat |
| 163.98.253.135 | 4 | 3 terisi, 1 event kosong | 3 | Tidak mencapai ambang | Tidak mencapai ambang |

Untuk dua sumber teratas, jumlah tebakan per nilai username sama persis: root 51, admin 21, guest 3, supervisor 2, dan 13 nilai lain masing-masing 1. Urutan jumlah percobaan per sesi berbeda. Kemiripan ini konsisten dengan daftar tebakan atau otomasi yang sama, tetapi tidak membuktikan satu alat atau satu pelaku.

Normalizer menghasilkan 196 event login gagal yang memiliki timestamp, username, dan source IP. Satu event gagal dari 163.98.253.135 tidak memiliki username sehingga dilewati. Tiga nilai username terisi pada IP tersebut juga menyerupai teks protokol, bukan nama akun yang dapat dipastikan. Karena itu laporan menghitung nilai field, bukan mengklaim jumlah akun sungguhan.

## Penilaian analis

Volume tinggi, pengulangan pada root dan admin, serta banyak nilai username dari dua IP dalam waktu singkat konsisten dengan otomasi tebakan kredensial terhadap honeypot. Status yang tepat adalah aktivitas mencurigakan yang perlu dicatat sebagai kandidat pemindaian atau password spraying. Data ini tidak membuktikan serangan terhadap organisasi tertentu atau keberhasilan akses.

Aturan 2 tidak dapat dievaluasi pada log Cowrie karena tidak ada login berhasil. Aturan tersebut tetap dapat didemonstrasikan menggunakan data sintetis di data/sample_log.csv, yang memuat rangkaian kegagalan lalu login berhasil untuk satu akun simulasi.

## Keterbatasan dan langkah berikutnya

- Hanya satu hari data; belum cukup untuk menggambarkan tren jangka panjang.
- Tidak ada login berhasil, reputasi IP, lokasi, identitas perangkat, atau konteks MFA.
- Honeypot merekam tebakan terhadap layanan umpan, bukan percobaan terhadap akun organisasi.
- Ambang 5 percobaan dalam 10 menit adalah parameter latihan, bukan kebijakan produksi.
- Perlu diuji pada periode log lebih panjang, kemudian nilai ambang ditinjau terhadap pola dasar sebelum dipakai di lingkungan nyata.

## Sumber

- [Salty Seagull Dataset, Zenodo](https://zenodo.org/records/18088113)
- [README dataset dan petunjuk sitasi](https://zenodo.org/records/18088113/preview/README.md?include_deleted=0)
- Makrakis, G. M., Pijpker, J., Hassing, R., Loves, R., & McCombie, S. (2025). Salty Seagull: A VSAT Honeynet to Follow the Bread Crumb of Attacks in Ship Networks. [arXiv:2508.11325](https://arxiv.org/abs/2508.11325).
# Analisis Cowrie: 198.5.233.14

**Sumber:** Salty Seagull Cowrie honeynet dataset, berkas cowrie.json.2025-04-03.anon. Dataset mencatat interaksi terhadap honeynet; alamat IP dianonimkan.  
**Waktu:** 3 April 2025, UTC.

## Fakta

- Antara 15:52:11.907882 dan 15:54:25.706065 UTC (sekitar 2 menit 14 detik), log mencatat 90 login gagal dari 198.5.233.14, dalam 5 sesi koneksi dan dengan 17 nilai username berbeda.
- Dua pasangan username dan IP melewati ambang Aturan 1 (5 kegagalan dalam 10 menit):
  - root: 51 kegagalan, dari 15:52:12.816779 sampai 15:54:24.783193 UTC.
  - admin: 21 kegagalan, dari 15:52:14.646418 sampai 15:54:25.706065 UTC.
- Sisa 18 kegagalan tersebar pada 15 username lain, masing-masing di bawah ambang.
- Tidak ada cowrie.login.success di seluruh berkas, termasuk untuk IP ini.

## Penilaian awal

Volume tinggi dalam waktu singkat, percobaan berulang pada beberapa sesi, dan pemakaian nama seperti root serta admin konsisten dengan otomasi tebakan kredensial terhadap layanan honeypot. Honeypot tidak memiliki pengguna sah yang lupa kata sandi, sehingga penjelasan itu tidak sesuai untuk data ini.

Log ini saja belum membedakan pemindaian internet yang luas dari serangan yang memilih target tertentu. Log menunjukkan aktivitas dari alamat sumber yang tercatat menuju honeypot; statusnya adalah **aktivitas yang konsisten dengan percobaan kredensial otomatis**, bukan bukti serangan terhadap organisasi tertentu.

## Keterbatasan

- Ini data honeypot, bukan log sistem produksi. Username adalah nilai yang dicoba, bukan akun sungguhan.
- Tidak ada login berhasil, sehingga Aturan 2 tidak dapat diuji dan tidak ada bukti akses pasca-login dalam berkas ini.
- Cakupan berkas hanya satu hari. Reputasi sumber dan lokasi tidak dapat disimpulkan dari log ini.
- Alamat IP di dataset telah dianonimkan; jangan menafsirkannya sebagai alamat asli.
- Ambang 5 kegagalan dalam 10 menit adalah parameter latihan, bukan kebijakan produksi.
- Kolom password dan message sengaja tidak dipakai dalam analisis.

## Perbandingan sumber lain

36.157.238.137 menunjukkan pola serupa pada hari yang sama: 90 kegagalan, 17 nilai username, dan 5 sesi, dari 23:57:34.215244 sampai 23:59:00.378024 UTC. Kemiripan pola merupakan petunjuk untuk dibandingkan lebih lanjut, tetapi belum membuktikan kedua sumber memakai alat yang sama atau dikendalikan pelaku yang sama.

## Sumber data

- [Salty Seagull Dataset (Zenodo)](https://zenodo.org/records/18088113)
- [README dataset dan keterangan anonimisasi](https://zenodo.org/records/18088113/preview/README.md?include_deleted=0)

## Ringkasan per IP sumber

| IP (anonim) | Gagal | Nilai username nonkosong berbeda | Sesi | Rentang kegagalan (UTC) | Protokol |
|---|---:|---:|---:|---|---|
| 198.5.233.14 | 90 | 17 | 5 | 15:52:11.907882–15:54:25.706065 | telnet |
| 36.157.238.137 | 90 | 17 | 5 | 23:57:34.215244–23:59:00.378024 | telnet |
| 163.98.253.135 | 4 | 3 (1 event tanpa username) | 3 | 21:56:05.818671–21:56:59.959929 | telnet |
| 20.196.52.135 | 3 | 3 | 1 | 19:22:45.601618–19:22:45.615888 | telnet |
| 154.223.200.153 | 3 | 3 | 1 | 20:28:09.897941–20:28:09.910794 | telnet |
| 92.192.55.190 | 3 | 3 | 1 | 21:06:55.778321–21:06:55.782856 | telnet |
| 213.36.152.155 | 2 | 1 | 2 | 20:32:27.872583–23:16:41.216608 | telnet |
| 130.32.89.134 | 2 | 1 | 2 | 22:47:25.247692–23:37:28.023928 | telnet |

Seluruh 236 sesi unik dalam berkas menggunakan Telnet. Dari 114 alamat sumber unik yang tercatat pada keseluruhan event, 8 memiliki setidaknya satu event login gagal dan 106 hanya memiliki event koneksi tanpa login gagal.

Untuk dua sumber dengan volume tertinggi, distribusi username yang tercatat sama persis: root 51, admin 21, guest 3, supervisor 2, dan 13 nilai lain masing-masing 1. Jumlah percobaan per sesi berbeda: [10, 17, 20, 20, 23] untuk 198.5.233.14 dan [4, 21, 21, 21, 23] untuk 36.157.238.137. Kemiripan distribusi ini mendukung hipotesis daftar tebakan atau otomasi yang sama, tetapi tidak mengidentifikasi pelaku.

Catatan kualitas data: ada satu event gagal dari 163.98.253.135 tanpa username. Untuk aturan yang mengelompokkan per username, event itu dikeluarkan; jangan menghitung nilai kosong sebagai akun keempat. Beberapa nilai pada field username dapat menyerupai teks protokol, sehingga jumlah ini menghitung nilai field nonkosong dan bukan akun nyata yang terverifikasi.

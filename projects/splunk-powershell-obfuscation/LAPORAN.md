# Laporan dan Panduan: Analisis PowerShell Ter-encode di Splunk

**Jenis latihan:** analisis log SOC / blue-team  
**Tanggal:** 25 Oktober 2026  
**Status:** dataset latihan; pemeriksaan Event ID 3 khusus sekitar 10:24 masih terbuka  
**Lingkungan:** Splunk Enterprise 10.6.1 lokal  
**Index / sourcetype:** `soc_lab` / `sysmon_xml_local`

## 1. Ringkasan

Kita sedang membuat **Project 2: deteksi dan investigasi obfuscated PowerShell dengan Splunk**. Jadi, kita melakukan analisis keamanan sekaligus menyusun dokumentasi proyek portofolio.

Temuan utama adalah rangkaian sekitar 10:24 pada 19 Januari 2021: `winrshost.exe → cmd.exe → powershell.exe` dengan `-ExecutionPolicy Unrestricted` dan `-EncodedCommand`. Setelah didekode sebagai teks, payload menunjukkan wrapper yang membaca skrip dari input standar. Isi input tersebut tidak ada di log yang tersedia, jadi perilaku akhir skrip belum bisa dipastikan.

Jalur lain, PID `7244`, meminta DNS untuk `bit.ly` dan `www.leeholmes.com` lalu memiliki koneksi HTTP ke alamat hasil DNS. PID ini dimulai oleh `explorer.exe` pada 12:16 dan berbeda dari rangkaian encoded sekitar 10:24. Hasil yang ada belum cukup untuk menyimpulkan kompromi. Dataset adalah simulasi Attack Range, bukan bukti insiden produksi.

## 2. Dataset dan konfigurasi Splunk

Sumber data adalah file `windows-sysmon.log` dari [Splunk Attack Data, teknik T1059.001](https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log).

Dalam Add Data, file dimasukkan sebagai file input dengan index `soc_lab`, host `win-dc-397.attackrange.local`, dan sourcetype khusus `sysmon_xml_local`. Timestamp diambil dari `TimeCreated SystemTime=`. Formatnya `%Y-%m-%dT%H:%M:%S`, dan zona waktunya GMT/UTC karena timestamp XML berakhiran `Z`. Event dipisahkan berdasarkan baris baru. Karena timestamp dataset sudah lama, pengaturan lanjutan `MAX_DAYS_AGO=3000` dipakai agar tanggal 2021 diterima. Input disetel untuk diindeks sekali.

Pencarian `stats count` menghasilkan **29.943 event**, sehingga ingest berhasil.

## 3. Urutan proses yang kita lakukan

| Langkah | Apa yang dilakukan | Tujuannya | Hasil |
|---|---|---|---|
| 1. Memuat file | Pilih file log, index, host, dan sourcetype. | Menyimpan data di Splunk dengan label yang tepat. | Data masuk ke `soc_lab`. |
| 2. Mengatur timestamp | Tentukan prefix, format waktu, dan UTC. | Menampilkan waktu kejadian dari log, bukan waktu unggah. | Event muncul pada tanggal 19 Januari 2021. |
| 3. Validasi | Jalankan `stats count`. | Memastikan ingest sukses. | 29.943 event. |
| 4. Memahami Event ID | Ekstrak nomor `EventID` dari XML dan hitung jumlahnya. | Mengetahui jenis aktivitas yang tersedia. | ID 1 adalah pembuatan proses, 3 koneksi jaringan, 11 file dibuat, 22 DNS. |
| 5. Cari PowerShell | Cari istilah PowerShell dan pisahkan Windows PowerShell dari `splunk-powershell.exe`. | Menghindari hasil yang hanya mirip namanya. | Pencarian luas menghasilkan 319 baris, banyak terkait Universal Forwarder; itu bukan bukti serangan. |
| 6. Cari encoded command | Cari `EncodedCommand` dan ekstrak Base64 sebagai teks. | Menemukan kandidat yang perlu dianalisis. | 30 event, enam nilai payload berbeda. Event berulang tidak sama dengan proses unik. |
| 7. Lihat process lineage | Bandingkan PID dan ParentProcessId pada Event ID 1. | Mengetahui proses induk PowerShell. | Sekitar 10:24 tampak `winrshost.exe → cmd.exe → powershell.exe`. |
| 8. Decode teks | Ubah Base64 menjadi teks UTF-16LE tanpa menjalankannya. | Memahami bentuk payload dengan aman. | Payload memuat wrapper yang membaca input standar, membaginya pada karakter NUL, dan menjalankan bagian pertama sebagai script block. |
| 9. Korelasi jaringan | Bandingkan Event ID 3 (koneksi) dan 22 (DNS). | Mencocokkan proses, domain, dan alamat tujuan. | PID 7244 memiliki DNS dan koneksi pada sekitar 12:24; ini jalur berbeda dari proses 10:24. |
| 10. Cek file/proses anak | Periksa Event ID 11 dan proses yang parent-nya PID 7244. | Mencari file hasil aktivitas atau proses lanjutan. | Tercatat dua file saat PowerShell mulai; tidak ditemukan proses anak. Isi file tidak ada di event Sysmon. |

## 4. Jenis event yang ditemukan

| Event ID | Jumlah | Arti |
|---:|---:|---|
| 10 | 26.597 | Process access |
| 1 | 1.261 | Process creation |
| 13 | 967 | Registry value set |
| 11 | 621 | File created |
| 22 | 405 | DNS query |
| 15 | 38 | File stream created |
| 12 | 15 | Registry object create/delete |
| 7 | 15 | Image loaded |
| 3 | 8 | Network connection |
| 6 | 8 | Driver loaded |
| 5 | 5 | Process terminated |
| 4 | 2 | Sysmon service state changed |
| 16 | 1 | Sysmon configuration changed |

Angka ini adalah jumlah catatan di dataset, bukan jumlah serangan. Event ID 10 paling banyak karena konfigurasi log banyak merekam akses proses.

## 5. Temuan A — PowerShell encoded sekitar 10:24

Pada Event ID 1, proses berjalan berantai dari `winrshost.exe` ke `cmd.exe` dan kemudian `powershell.exe`. Command line memuat opsi:

- `-NoProfile`: tidak memuat profil pengguna.
- `-NonInteractive`: berjalan tanpa menunggu input terminal.
- `-ExecutionPolicy Unrestricted`: meminta kebijakan eksekusi yang lebih longgar untuk sesi itu.
- `-EncodedCommand`: perintah diberikan dalam bentuk Base64, umumnya teks UTF-16LE.

Opsi itu bisa muncul pada otomasi sah. Kombinasi parent process jarak jauh, command shell, dan encoded command membuat rangkaian ini layak ditinjau.

Payload yang didekode **bukan isi lengkap skrip akhir**. Ia menjalankan PowerShell kedua dengan wrapper. Wrapper membaca input standar, memisahkannya menjadi dua bagian pada empat karakter NUL, memasukkan bagian kedua ke `json_raw`, lalu menjalankan bagian pertama sebagai script block. Isi yang diberikan melalui input standar tidak terdapat pada command line atau log Sysmon yang kita punya. Perintah hanya dibaca sebagai teks; tidak dijalankan.

## 6. Temuan B — PID 7244 sekitar 12:16–12:24

Ini proses berbeda, jadi jangan gabungkan dengan temuan A.

- PID `7244` dimulai pada 12:16:31.722 oleh `explorer.exe`; command line hanya menampilkan executable PowerShell.
- Event ID 22 pada 12:24:56 mencatat pencarian DNS untuk `bit.ly` dan `www.leeholmes.com`.
- Event ID 3 beberapa milidetik kemudian mencatat koneksi PowerShell melalui port 80 ke `67.199.248.10` dan `172.67.154.157`, yang cocok dengan jawaban DNS yang terlihat.
- Event ID 11 mencatat `__PSScriptPolicyTest_...ps1` dan `ConsoleHost_history.txt` saat PowerShell mulai. Nama file ini konsisten dengan artefak awal PowerShell/PSReadLine; event tidak berisi konten file.
- Pencarian Event ID 1 untuk proses anak dengan `ParentProcessId=7244` menghasilkan 0 event.

**Penilaian:** aktivitas jaringan dari PowerShell perlu dicatat, tetapi domain dan port saja tidak membuktikan malware. Tidak ada proses anak atau file unduhan yang terlihat pada event yang diperiksa.

## 7. Pemeriksaan sekitar 10:25

Pencarian gabungan Event ID 3 dan 22 menampilkan permintaan DNS internal. Baris yang sempat terpotong adalah Event ID 22 dari `Microsoft.ActiveDirectory.WebServices.exe` PID 1516, untuk `win-dc-397.attackrange.local`. Hasilnya mencakup alamat internal `10.0.1.14` dan IPv6 lokal. Baris itu bukan koneksi keluar PowerShell.

Pemeriksaan Event ID 3 saja untuk rentang 10:24:30–10:26:00 belum selesai. Karena itu kita belum dapat mengatakan apakah ada atau tidak ada koneksi jaringan yang terkait langsung dengan rangkaian encoded pada 10:24.

## 8. Kesimpulan triase sementara

| Pertanyaan | Kesimpulan |
|---|---|
| Apakah data sudah masuk? | Ya, 29.943 event di index `soc_lab`. |
| Apakah ada command PowerShell encoded? | Ya, 30 event memuat `EncodedCommand` dan ada enam payload berbeda. |
| Apakah isi skrip akhir diketahui? | Belum; wrapper membaca skrip terpisah dari input standar. |
| Apakah ada rantai proses yang patut ditinjau? | Ya: `winrshost.exe → cmd.exe → powershell.exe` sekitar 10:24. |
| Apakah PID 7244 memiliki aktivitas jaringan? | Ya, DNS dan koneksi HTTP sekitar 12:24; ini jalur terpisah. |
| Apakah log membuktikan kompromi? | Tidak. Dataset simulasi dan bukti yang tersedia belum cukup. |

**Status:** aktivitas mencurigakan dalam latihan, belum terkonfirmasi sebagai kompromi. Jangan menyebut domain atau IP sebagai indikator berbahaya tanpa verifikasi dan konteks tambahan.

## 9. Apa yang masih perlu dilakukan

1. Jalankan query Event ID 3 saja pada rentang 19 Januari 2021, 10:24:30–10:26:00. Lihat PID, Image, IP sumber/tujuan, port, dan Initiated.
2. Jika tidak ada koneksi di rentang itu, catat hanya bahwa koneksi tidak tercatat di data yang tersedia; itu bukan bukti bahwa skrip tidak pernah berkomunikasi.
3. Untuk mengetahui isi skrip, diperlukan PowerShell Script Block Logging (Event ID 4104), transkrip PowerShell, atau file input standar dari host.
4. Jangan unggah file log mentah atau Base64 panjang ke repo publik.

## 10. Istilah dasar

| Istilah | Penjelasan singkat |
|---|---|
| Event | Satu catatan kejadian, seperti proses dibuat atau DNS dicari. |
| Index | Tempat penyimpanan event di Splunk; latihan ini memakai `soc_lab`. |
| Sourcetype | Label format data; di sini `sysmon_xml_local`. |
| PID | Nomor proses; dapat digunakan ulang oleh sistem. |
| ParentProcessId | PID proses yang membuat proses lain; dipakai untuk menyusun rantai proses. |
| DNS | Menerjemahkan nama host/domain menjadi alamat IP. DNS query sendiri tidak membuktikan koneksi sukses. |
| Event ID 3 | Catatan koneksi jaringan Sysmon. |
| Event ID 11 | Catatan file yang dibuat; biasanya bukan isi file. |
| Event ID 22 | Catatan DNS Sysmon. |
| Base64 | Cara merepresentasikan data sebagai teks; bukan enkripsi dan bukan bukti bahwa perintah aman. |
| False positive | Aktivitas sah yang cocok dengan pola deteksi dan perlu diperiksa dengan konteks. |

## Sumber

- [Dataset Splunk Attack Data: T1059.001 obfuscated PowerShell](https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log)
- Data ini adalah dataset Attack Range simulasi; laporan ini tidak menyatakan adanya insiden produksi.




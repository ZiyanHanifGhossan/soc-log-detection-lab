# Project 2 — Analisis PowerShell ter-encode dengan Splunk

Latihan portofolio blue-team untuk membaca log Sysmon, menemukan PowerShell dengan `-EncodedCommand`, memeriksa process lineage, lalu mencocokkan event DNS dan koneksi jaringan.

## Hasil ringkas

- Dataset publik Splunk Attack Data untuk teknik MITRE ATT&CK T1059.001, PowerShell.
- **29.943 event** berhasil diindeks ke `soc_lab` dengan sourcetype `sysmon_xml_local`.
- Pencarian menemukan **30 event berisi `EncodedCommand`** dan enam payload Base64 berbeda. Jumlah event bukan jumlah proses unik.
- Salah satu payload terluar menjalankan PowerShell kedua dengan wrapper yang membaca input standar. Isi skrip dikirim terpisah dan tidak dapat diketahui dari command line itu saja.
- Sekitar 10:24 terlihat `winrshost.exe → cmd.exe → powershell.exe` dengan `-ExecutionPolicy Unrestricted` dan `-EncodedCommand`. Layak ditinjau, tetapi dataset simulasi tidak membuktikan kompromi.
- PID PowerShell `7244` adalah jalur terpisah: DNS untuk `bit.ly` dan `www.leeholmes.com` cocok dengan koneksi HTTP yang tercatat. File yang dibuat tampak sebagai artefak awal PowerShell; tidak ditemukan proses anak atau file unduhan pada hasil yang diperiksa.

## Berkas

- [Laporan dan penjelasan urutan kerja](LAPORAN.md)
- [Query Splunk](splunk-queries.md)

## Batasan

Dataset Attack Range ini simulasi, bukan insiden produksi. Sysmon tidak menyediakan isi input standar, riwayat PowerShell, atau PowerShell Script Block Logging (Event ID 4104) yang diperlukan untuk memastikan isi skrip. Query khusus Event ID 3 sekitar 10:24 masih menjadi tindak lanjut.

## Sumber

[Splunk Attack Data — obfuscated PowerShell / windows-sysmon.log](https://github.com/splunk/attack_data/blob/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log)



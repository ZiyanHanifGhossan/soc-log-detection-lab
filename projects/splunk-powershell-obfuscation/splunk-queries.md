# Query Splunk untuk Project 2

Jalankan query satu per satu pada Splunk Search. `earliest=0` menjaga data Januari 2021 tetap masuk dalam rentang pencarian.

## 1. Pastikan event sudah terindeks

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0
| stats count
```

Hasil latihan: 29.943 event.

## 2. Hitung jenis event Sysmon

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

## 3. Cari command line yang memuat EncodedCommand

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0 "EncodedCommand"
| rex field=_raw "(?i)-EncodedCommand\s+(?<EncodedPayload>[A-Za-z0-9+/=]+)"
| stats count as EventCount by EncodedPayload
| eval PayloadLength=len(EncodedPayload), PayloadPreview=substr(EncodedPayload,1,24)
| table EventCount PayloadLength PayloadPreview
| sort - EventCount
```

Hasil: 30 event berisi teks EncodedCommand; enam payload Base64 berbeda. Jumlah event bukan jumlah proses unik. Decode hanya sebagai teks, jangan jalankan.

## 4. Tampilkan parent dan command line proses encoded

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0 "EncodedCommand"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='UtcTime'>(?<UtcTime>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentProcessId'>(?<ParentProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| table UtcTime ProcessId ParentProcessId ParentImage Image CommandLine
| sort UtcTime
```

## 5. Periksa koneksi jaringan sekitar rangkaian 10:24 (tindak lanjut)

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest="01/19/2021:10:24:30" latest="01/19/2021:10:26:00"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name='UtcTime'>(?<UtcTime>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='Protocol'>(?<Protocol>[^<]+)</Data>"
| rex field=_raw "<Data Name='Initiated'>(?<Initiated>[^<]+)</Data>"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='SourcePort'>(?<SourcePort>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| table UtcTime ProcessId Image Protocol Initiated SourceIp SourcePort DestinationIp DestinationPort
| sort UtcTime
```

Jika kosong, artinya tidak ada koneksi Event ID 3 tercatat pada rentang itu, bukan bukti bahwa proses tidak pernah berkomunikasi.

## 6. Lihat DNS untuk PID 7244

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=22
| rex field=_raw "<Data Name='UtcTime'>(?<UtcTime>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='QueryName'>(?<QueryName>[^<]+)</Data>"
| rex field=_raw "<Data Name='QueryResults'>(?<QueryResults>[^<]+)</Data>"
| search ProcessId=7244
| table UtcTime ProcessId Image QueryName QueryResults
| sort UtcTime
```

## 7. Cek file yang dibuat PID 7244

```spl
index=soc_lab sourcetype=sysmon_xml_local earliest=0
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=11
| rex field=_raw "<Data Name='UtcTime'>(?<UtcTime>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>"
| search ProcessId=7244
| table UtcTime ProcessId Image TargetFilename
| sort UtcTime
```




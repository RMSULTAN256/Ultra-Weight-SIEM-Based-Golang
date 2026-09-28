# 📂 Dataset & Log Examples (Folder `data/`)

Folder ini berisi kumpulan dataset **Example IP (Threat Intelligence)** dan **Example Logs (Benchmark & Simulated Attacks)** yang siap digunakan untuk pengujian, pemindaian reputasi, dan evaluasi korelasi SIEM.

---

## 🌐 1. Folder `data/ips/` (Example IP Datasets)

| File | Sumber / Tipe | Jumlah Data | Kegunaan Pengujian SIEM |
| :--- | :--- | :---: | :--- |
| **`malicious_threat_feed_ips.txt`** | **CINS Army Threat Intelligence Feed** (`cinsscore.com`) | ~15.000+ IP | Deteksi penyerang aktif di internet (scanner, botnet, brute force). |
| **`tor_exit_nodes.txt`** | **The Tor Project** (`check.torproject.org`) | ~1.000+ IP | Pengujian aturan deteksi akses anonim / Dark Web (Proxy/Tor). |
| **`datacenter_hosting_ips.txt`** | **Cloud & VPS Providers** (AWS, DO, Hetzner, GCP, Azure, Linode, OVH, Alibaba) | 35 IP | Pengujian aturan deteksi login dari Datacenter Hosting (`"hosting": true`). |
| **`residential_clean_ips.txt`** | **ISP Residensial & Seluler** (Telkom IndiHome, Telkomsel, Biznet, XL, Indosat) | 35 IP | Simulasi trafik pengguna normal (`"hosting": false, "proxy": false`). |
| **`sample_targets_mixed.txt`** | **Kombinasi 30 IP Campuran** (Clean + Hosting + Tor + Malicious) | 30 IP | **File siap pakai langsung** untuk diuji dengan skrip `main2.go`. |

### 🚀 Cara Uji Coba Example IP:
Ganti path input file di [`main2.go`](file:///c:/Users/mixto/Documents/MyCodeMyBackup/golang/TA/main2.go#L16) menjadi:
```go
inputFile, err := os.Open("data/ips/sample_targets_mixed.txt")
```
Lalu jalankan pemindaian pengayaan CTI:
```powershell
go run main2.go
```

---

## 📜 2. Folder `data/logs/` (Example Log Datasets)

| File | Format Log | Sumber / Jenis Skenario | Kegunaan Pengujian SIEM |
| :--- | :--- | :--- | :--- |
| **`auth_ssh_bruteforce.log`** | Syslog / OpenSSH | **LogPAI Loghub Academic Benchmark** (2.000 Baris) | Pengujian korelasi *Sliding Window* pada serangan SSH Brute Force. |
| **`linux_system.log`** | Syslog Linux OS | **LogPAI Loghub Academic Benchmark** (2.000 Baris) | Pengujian parsing log sistem Linux, daemon error, dan kernel messages. |
| **`web_apache_access.log`** | Combined Log Format | **LogPAI Loghub Academic Benchmark** (2.000 Baris) | Analisis pola akses web normal dan variasi HTTP User-Agent. |
| **`web_attack_payloads.log`** | Nginx Access Log | Simulasi Serangan Aplikasi Web | Uji deteksi SQL Injection (`UNION SELECT`), Path Traversal (`../../etc/passwd`), XSS, dan Scanner Probes (`/.env`, `/shell.php`). |
| **`laravel_realkabil_auth.log`** | Laravel Monolog | Target App (`RealKABIL`) | Audit autentikasi aplikasi web, gagal login berulang, dan eksekusi perintah `sudo`. |
| **`siem_events_ndjson.json`** | NDJSON (*Newline Delimited JSON*) | Format Pipeline Native SIEM | **Langsung cocok** dengan aturan Sigma di [`rule.yaml`](file:///c:/Users/mixto/Documents/MyCodeMyBackup/golang/TA/rule.yaml) (*Failed Login Brute Force* & *Privilege Escalation*). |


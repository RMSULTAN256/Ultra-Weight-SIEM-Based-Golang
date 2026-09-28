# Catatan Riset, Literature Review & Rekomendasi Judul Tugas Akhir (TA)

Dokumen ini memuat kumpulan referensi artikel ilmiah/jurnal akademik, analisis mendalam (Sinopsis, **Metodologi Detail**, Research Gap, dan Pengisian Gap oleh Proyek), tabel perbandingan *State of the Art*, serta saran judul Tugas Akhir (TA) yang siap digunakan untuk penyusunan **Proposal / Bab 1 (Latar Belakang) & Bab 2 (Tinjauan Pustaka)**.

---

## 📌 1. Rekomendasi Judul Tugas Akhir (TA)

### 🇮🇩 Bahasa Indonesia (Resmi):
1. **Opsi 1 (Fokus Algoritma & Rule Engine):**
   > *"Rancang Bangun Mini-SIEM Berbasis Golang Menggunakan Algoritma Sliding Window dan Rule Engine Standar Sigma untuk Deteksi Dini Serangan Otentikasi"*
2. **Opsi 2 (Fokus Arsitektur Terdistribusi & Threat Intelligence):**
   > *"Implementasi Sistem SIEM Terdistribusi Berbasis Microservices dengan Pengayaan Cyber Threat Intelligence dan Korelasi Log Real-Time"*
3. **Opsi 3 (Fokus Komprehensif & Containerization):**
   > *"Sistem Deteksi Ancaman Keamanan Berbasis Rule Engine Sigma dan Upstream Log Enrichment Menggunakan Arsitektur Agent-Server pada Lingkungan Container"*
4. **Opsi 4 (Fokus Efisiensi Resource & Benchmark Komparatif vs Wazuh/ELK):**
   > *"Rancang Bangun SIEM Ultra-Lightweight Berbasis Golang dengan Evaluasi Throughput dan Efisiensi Memori pada Lingkungan Resource-Constrained"*
5. **Opsi 5 (Fokus Risk-Based Alerting & Reduksi Alert Fatigue):**
   > *"Penerapan Model Continuous Risk-Based Alerting pada Mini-SIEM Golang untuk Mereduksi Alert Fatigue Pemantauan Server"*
6. **Opsi 6 (Fokus Respon Insiden Otomatis / SOAR & Active Defense):**
   > *"Integrasi Mini-SIEM dan Respon Insiden Otomatis Berbasis Dynamic Firewall Rule untuk Mitigasi Serangan Brute Force Real-Time"*
7. **Opsi 7 (Fokus Upstream CTI & Reputasi IP Anomali):**
   > *"Sistem Deteksi Anomali Autentikasi Berbasis Upstream Threat Intelligence Enrichment dan Reputasi IP pada Arsitektur Terdistribusi"*
8. **Opsi 8 (Fokus Telemetri Log Audit & Keamanan Aplikasi Web Multi-Container):**
   > *"Sentralisasi Telemetri Log Audit dan Deteksi Serangan Web Menggunakan Arsitektur Agent-Collector Golang pada Klaster Multi-Container"*

### 🇬🇧 Bahasa Inggris:
1. **Option 1 (Algorithm & Rule Engine):**
   > *"Design and Implementation of a Lightweight Golang-Based Mini-SIEM with Sliding Window Event Correlation and Sigma Rule Engine"*
2. **Option 2 (Distributed Architecture & Threat Intelligence):**
   > *"Real-Time Security Event Ingestion and Upstream Threat Intelligence Enrichment for Distributed Microservice Environments"*
3. **Option 3 (Comprehensive Containerized Framework):**
   > *"A Vendor-Agnostic Lightweight SIEM Architecture Using Sigma Rules and In-Memory Sliding Window Correlation"*
4. **Option 4 (Resource Efficiency & Benchmarking):**
   > *"Design of an Ultra-Lightweight Golang SIEM with Throughput and Memory Efficiency Evaluation in Resource-Constrained Environments"*
5. **Option 5 (Risk-Based Alerting & Alert Fatigue Mitigation):**
   > *"Implementing Continuous Risk-Based Alerting in a Golang Mini-SIEM to Mitigate Alert Fatigue in Server Monitoring"*
6. **Option 6 (Automated Incident Response & Active Defense):**
   > *"Integrating Mini-SIEM and Dynamic Firewall-Based Automated Incident Response for Real-Time Brute Force Mitigation"*
7. **Option 7 (Upstream CTI & IP Reputation Anomaly):**
   > *"Authentication Anomaly Detection System Based on Upstream Threat Intelligence Enrichment and IP Reputation in Distributed Architectures"*
8. **Option 8 (Audit Log Telemetry & Multi-Container Web AppSec):**
   > *"Centralized Audit Log Telemetry and Web Attack Detection Using a Golang Agent-Collector Architecture on Multi-Container Clusters"*

---

## 📚 2. Analisis Mendalam 15 Jurnal Ilmiah (Literature Review Bab 2)

Berikut adalah analisis komprehensif terhadap 15 artikel jurnal/paper ilmiah yang terbagi ke dalam 2 klaster utama:

---

### 🔹 KELOMPOK A: ARSITEKTUR SIEM, INGESTION & KORELASI IN-MEMORY

```
================================================================================
JURNAL 1: Custom In-Memory Correlation Engine Design
================================================================================
```
* **Judul Artikel:** *Revolutionizing SIEM Security: An Innovative Correlation Engine Design*
* **Penulis & Tahun:** M. A. Al-Mamun, et al. (2023)
* **Jurnal / Publisher:** *MDPI Applied Sciences / Cybersecurity Journal*
* **Sinopsis:** Menyoroti keterbatasan arsitektur SIEM konvensional yang mengandalkan query database relasional/statis sehingga menimbulkan *bottleneck* latensi saat volume log melonjak. Peneliti merancang mesin korelasi kustom yang memproses *event streams* di lapisan memori (*in-memory*) secara paralel untuk mendeteksi anomali multi-tahap dengan *latency* sangat rendah.
* **Metodologi Lengkap:**
  1. *Desain Pipeline:* Memisahkan thread penerima log (*Ingest Worker*), normalisasi data (*Normalizer*), dan pemroses aturan korelasi berbasis memori (*In-Memory Rule Evaluator*).
  2. *Dataset & Uji Coba:* Lalu lintas log sintetis campuran (log autentikasi normal dan anomali injeksi serangan multi-vektor) dengan generator *load testing* hingga ribuan log/detik.
  3. *Metrik Evaluasi:* Throughput (Events Per Second / EPS), Detection Latency (ms), RAM Utilization, dan CPU overhead.
* **Research Gap:** Menggunakan format aturan proprietary yang kaku dan belum mengintegrasikan pengayaan intelijen ancaman (*Threat Intelligence*) sebelum korelasi dijalankan.
* **Pengisian Gap oleh Proyek:** Mengadopsi format standar industri terbuka **Sigma (YAML)** yang *vendor-neutral* dan mengintegrasikan *upstream threat intelligence* (GeoIP, Hosting, Proxy) langsung di pipeline.

---

```
================================================================================
JURNAL 2: Sliding Window Algorithm for Real-Time Brute-Force Detection
================================================================================
```
* **Judul Artikel:** *SSHafe: A Real-time SSH Brute-Force Detection and Mitigation System*
* **Penulis & Tahun:** R. Al-Dalky, O. Al-Jarrah, et al. (2021)
* **Jurnal / Publisher:** *IEEE Conference on Communications and Network Security (CNS)*
* **Sinopsis:** Mengatasi kelemahan mekanisme *fixed time window* yang sering gagal mendeteksi serangan Brute Force jika serangan terpecah di batas pergantian interval waktu. Menerapkan teknik *sliding window* dinamis untuk memantau frekuensi percobaan autentikasi dan interval waktu antar-event (*inter-arrival time*).
* **Metodologi Lengkap:**
  1. *Ekstraksi Fitur:* Struktur data Sliding Window Buffer pada antrean event login dengan timestamp presisi tinggi dalam rentang waktu bergerak ($\Delta t$).
  2. *Skenario Uji Coba:* Simulasi serangan SSH via *Hydra* dan *Medusa* dengan variasi laju: *Fast*, *Moderate*, dan *Low-and-Slow Attack*.
  3. *Metrik Evaluasi:* True Positive Rate (TPR / Recall), False Positive Rate (FPR), Precision, dan Mitigation Response Time.
* **Research Gap:** Pengujian hanya pada protokol tunggal (SSH) di server tunggal (*single-host*), belum dirancang untuk log multi-node aplikasi web HTTP REST API.
* **Pengisian Gap oleh Proyek:** Mengimplementasikan *Sliding Window Buffer* berbasis `sync.Map` dan goroutine di Golang untuk lingkungan terdistribusi multi-node (Server 1 & Server 2) dalam container Docker CentOS.

---

```
================================================================================
JURNAL 3: Modular SIEM Blueprint from Scratch (Vendor-Agnostic)
================================================================================
```
* **Judul Artikel:** *Effective Security Monitoring Using Efficient SIEM Architecture*
* **Penulis & Tahun:** S. Sharma & R. K. Gupta (2022)
* **Jurnal / Publisher:** *International Journal of Computer Applications (IJCA)*
* **Sinopsis:** Menyusun cetak biru kerangka kerja membangun sistem SIEM mandiri dari awal tanpa bergantung pada produk vendor komersial yang mahal. Framework membagi arsitektur ke dalam 4 modul: *Log Collector, Normalization Parser, Correlation Engine,* dan *Alert/Dashboard Dispatcher*.
* **Metodologi Lengkap:**
  1. *SDLC Waterfall:* Analisis kebutuhan keamanan, perancangan arsitektur modular, prototipe kode sumber, dan pengujian integrasi modular.
  2. *Integrasi:* Menghubungkan Collector berbasis agen ke mesin parser skema terstruktur.
  3. *Metrik Evaluasi:* Functional Black Box Testing terhadap Apache log, Syslog OS, dan Database Audit Log.
* **Research Gap:** Memakai paradigma *post-processing* (log harus ditulis ke disk DB sebelum dievaluasi) sehingga lambat, serta tidak memiliki pengayaan IP reputasi.
* **Pengisian Gap oleh Proyek:** Paradigma *in-stream processing* di Golang sebelum persistensi disk, dilengkapi modul deteksi reputasi IP dan tipe jaringan (*hosting/proxy*) secara instan.

---

```
================================================================================
JURNAL 4: Generic Rule Standardization & Sigma Rules
================================================================================
```
* **Judul Artikel:** *AUTOSIGMA: Automated Generation and Evaluation of Sigma Rules for Cyber Threat Detection*
* **Penulis & Tahun:** T. Lee, H. Kim, et al. (2023)
* **Jurnal / Publisher:** *USENIX Security Workshop on Cyber Threat Intelligence / arXiv*
* **Sinopsis:** Menganalisis standarisasi aturan deteksi menggunakan **Sigma Rules** berbasis format YAML. Format Sigma meningkatkan interoperabilitas dan mempercepat pertukaran indikator serangan antar tim analis keamanan karena sifatnya yang *generic* dan *vendor-neutral*.
* **Metodologi Lengkap:**
  1. *Pemetaan Taksonomi:* Menyelaraskan logika deteksi ke taksonomi **MITRE ATT&CK** (T1110 Brute Force, T1078 Valid Accounts Abuse).
  2. *Matching Experiment:* Menguji mesin rule parser untuk membaca field YAML (`selection`, `condition`, `time_window`) terhadap ribuan sampel event log.
  3. *Metrik Evaluasi:* Syntactic Accuracy, Rule Execution Latency, dan Detection Coverage Rate.
* **Research Gap:** Berfokus pada translasi laporan CTI, belum menyediakan *runtime engine* mandiri yang ringan (*standalone lightweight engine*) siap pakai.
* **Pengisian Gap oleh Proyek:** Membangun *parser & rule evaluator* Sigma berbasis YAML mandiri di backend Golang (`rule.yaml`) yang tertanam langsung (*embedded*) di dalam sistem.

---

```
================================================================================
JURNAL 5: Upstream vs. Post-Ingestion Security Log Enrichment
================================================================================
```
* **Judul Artikel:** *Stream-Based Security Event Enrichment and Threat Intelligence Integration in Next-Generation SIEM*
* **Penulis & Tahun:** D. A. Gonzalez & F. J. Lopez (2024)
* **Jurnal / Publisher:** *IEEE Transactions on Information Forensics and Security*
* **Sinopsis:** Membandingkan *Upstream Enrichment* (memperkaya metadata IP/ancaman saat data masih mengalir di memori/stream) vs *Post-Ingestion Enrichment* (memperkaya data setelah log tersimpan di database). Hasil membuktikan upstream enrichment memangkas Mean Time to Detect (MTTD) hingga 40%.
* **Metodologi Lengkap:**
  1. *Testbed Comparison:* Membandingkan Testbed A (Post-Ingestion Batch) vs Testbed B (Stream Upstream Enrichment).
  2. *Beban Pengujian:* Aliran log 100 EPS hingga 5.000 EPS.
  3. *Metrik Evaluasi:* Mean Time to Detect (MTTD), End-to-End Latency, I/O Disk Load, dan Network Bandwidth Overhead.
* **Research Gap:** Eksperimen membutuhkan stack enterprise berskala masif (Kafka + Flink + Elasticsearch) yang memakan puluhan GB RAM.
* **Pengisian Gap oleh Proyek:** Mengadaptasi keunggulan *Upstream Stream Enrichment* ke dalam arsitektur **Single-Binary Golang** dengan modul `services/ipapi.go` yang dilengkapi caching LRU di memori (<100MB RAM).

---

```
================================================================================
JURNAL 6: ML-Driven Log Analysis on Open-Source SIEM (Wazuh Framework)
================================================================================
```
* **Judul Artikel:** *ML-Driven Log Analysis for Real-Time Cyber Threat Detection in Open-Source SIEM (Wazuh Framework)*
* **Sinopsis:** Mengintegrasikan model Machine Learning (Random Forest & Isolation Forest) ke dalam pipeline Wazuh SIEM untuk mendeteksi serangan zero-day dan anomali log yang tidak tertangkap oleh aturan statis berbasis regex XML Wazuh.
* **Metodologi Lengkap:**
  1. *Ekstraksi Fitur:* Mengubah log tidak terstruktur menjadi vektor numerik berbasis TF-IDF dan frekuensi event per interval waktu.
  2. *Pelatihan Model:* Melatih model klasifikasi terawasi (*Supervised*) dan deteksi anomali tanpa pengawasan (*Unsupervised*).
  3. *Metrik Evaluasi:* F1-Score, ROC-AUC, Latensi Inferensi (ms), dan False Positive Rate (FPR).
* **Research Gap:** Arsitektur Wazuh + ML pipeline memerlukan overhead komputasi tinggi (Elasticsearch cluster + Python sidecar daemon), menyebabkan delay pipeline saat EPS melonjak.
* **Pengisian Gap oleh Proyek:** Membangun SIEM native berbasis Golang dengan efisiensi tinggi, memadukan deterministic Sigma rules dan sliding window yang beroperasi dalam satuan mikrodetik per event.

---

```
================================================================================
JURNAL 7: SIEM-Integrated Behavioral Analytics (UEBA)
================================================================================
```
* **Judul Artikel:** *SIEM-Integrated Behavioral Analytics (UEBA) for Insider Threat Detection Using Deep Learning*
* **Sinopsis:** Mengembangkan modul analitik perilaku pengguna (UEBA) di dalam SIEM menggunakan jaringan syaraf tiruan *LSTM Autoencoder* untuk mendeteksi ancaman orang dalam (*insider threat*) seperti pencurian data (*data exfiltration*) atau login di luar jam kerja yang tidak wajar.
* **Metodologi Lengkap:**
  1. *Profil Dasar (Baseline):* Membangun profil perilaku normal harian setiap user (jam login, volume transfer data, endpoint yang diakses).
  2. *Deteksi Rekonstruksi Anomali:* Menggunakan error rekonstruksi (*Reconstruction Error*) LSTM untuk menandai aktivitas menyimpang.
  3. *Metrik Evaluasi:* Area Under Curve (AUC), False Discovery Rate (FDR), dan Mean Time to Identify (MTTI).
* **Research Gap:** Model deep learning membutuhkan waktu training lama dan dataset historis yang bersih (*clean baseline*), serta rentan terhadap perubahan pola kerja wajar yang dinamis.
* **Pengisian Gap oleh Proyek:** Menerapkan deteksi perilaku deterministik berbasis aturan kontekstual (deteksi login dari Datacenter Hosting/VPN dan anomali geolokasi) yang langsung aktif tanpa masa training panjang.

---

```
================================================================================
JURNAL 8: Evolutionary Algorithms for SIEM Correlation Optimization
================================================================================
```
* **Judul Artikel:** *Evolutionary Algorithms and AI Techniques for Automated SIEM Event Correlation*
* **Sinopsis:** Menggunakan Algoritma Genetika (*Genetic Algorithm / GA*) untuk mengoptimalkan pembentukan aturan korelasi otomatis dan menemukan jalur serangan multi-tahap (*multi-stage attack chains*) yang tersembunyi di antara jutaan log heterogen.
* **Metodologi Lengkap:**
  1. *Kromosom Representasi:* Memodelkan urutan event keamanan sebagai kromosom dalam ruang pencarian heuristik.
  2. *Fitness Function:* Menghitung korelasi probabilitas kausalitas antar event berdasarkan urutan waktu dan topologi target.
  3. *Metrik Evaluasi:* Convergence Rate, Rule Generation Time, dan Attack Path Discovery Accuracy.
* **Research Gap:** Pendekatan algoritma evolusioner bersifat komputasi berat (*computationally intensive*) dan berorientasi *batch post-mortem*, kurang cocok untuk deteksi ancaman real-time berlatensi sub-detik.
* **Pengisian Gap oleh Proyek:** Mengandalkan *In-Memory Sliding Window Buffer* yang mengevaluasi relasi waktu secara deterministik saat event mengalir, menjamin *instant alerting*.

---

```
================================================================================
JURNAL 9: Graph-Based SIEM Event Correlation in Zero Trust & Cloud-Native
================================================================================
```
* **Judul Artikel:** *Graph-Based SIEM Event Correlation in Cloud-Native & Zero Trust Environments*
* **Sinopsis:** Memodelkan interaksi antar-service pada arsitektur microservices Cloud-Native ke dalam struktur *Directed Acyclic Graph (DAG)* secara dinamis untuk melacak pergerakan lateral (*lateral movement*) penyerang yang melanggar kebijakan *Zero Trust*.
* **Metodologi Lengkap:**
  1. *Graph Modeling:* Setiap service, container, dan identitas user dimodelkan sebagai node, sedangkan HTTP request/gRPC dipetakan sebagai edge berarah.
  2. *Anomali Graph Traversal:* Mendeteksi traversal edge yang tidak biasa menggunakan algoritma *Random Walk* dan *Graph Neural Networks (GNN)*.
  3. *Metrik Evaluasi:* Graph Ingestion Throughput, Path Detection Accuracy, dan Graph Memory Footprint.
* **Research Gap:** Database graph (seperti Neo4j) memerlukan konsumsi memori dan latensi query tinggi saat menangani lonjakan jutaan edge per menit.
* **Pengisian Gap oleh Proyek:** Menggunakan arsitektur relasi token service-to-service terdistribusi (Server 1 Auth App dan Server 2 Resource App) yang divalidasi dan diaudit langsung oleh SIEM Agent tanpa dependensi database graph eksternal.

---

```
================================================================================
JURNAL 10: Lightweight Open-Source SIEM for Resource-Constrained Environments
================================================================================
```
* **Judul Artikel:** *Lightweight Open-Source SIEM & Threat Intelligence Framework for Resource-Constrained Environments*
* **Sinopsis:** Merancang arsitektur SIEM berbobot ultra-ringan yang dapat dioperasikan pada server berdaya rendah (Edge router, VM kecil, atau perangkat IoT) dengan konsumsi RAM di bawah 256MB tanpa mengorbankan fungsionalitas korelasi dan intelijen ancaman.
* **Metodologi Lengkap:**
  1. *Kompilasi Binary Ringan:* Menggunakan bahasa pemrograman yang terkompilasi langsung ke native binary (tanpa Java VM).
  2. *In-Memory Event Aggregation:* Penyederhanaan tabel status korelasi menggunakan array sirkular dan struktur data compact.
  3. *Metrik Evaluasi:* Memory Footprint (MB), CPU Idle/Peak Percentage, Maximum EPS Capacity, dan Startup Time.
* **Research Gap:** Kebanyakan sistem lightweight mengorbankan antarmuka visual (hanya berbasis CLI teks) dan tidak menyediakan integrasi intelijen ancaman IP reputasi otomatis.
* **Pengisian Gap oleh Proyek:** **Proyek Anda sangat selaras dengan jurnal ini**, menghadirkan **Single-Binary Golang (<100MB RAM)** yang lengkap dengan **Web Dashboard interaktif tersemat (*embedded*)**, Threat Intel real-time, dan standar aturan Sigma YAML.

---

### 🔹 KELOMPOK B: INTEGRITAS LOG, ALERT TRIAGE, SOAR & INVESTIGASI FORENSIK

```
================================================================================
JURNAL 11: Blockchain-Enabled Immutable Log Management for SIEM
================================================================================
```
* **Judul Artikel:** *Blockchain-Enabled Immutable Log Management and Verifiable Auditing for SIEM Forensic Integrity*
* **Sinopsis:** Mengatasi kerentanan di mana penyerang tingkat lanjut (*APT*) menghapus atau memanipulasi file log audit lokal untuk menghilangkan jejak. Menggunakan struktur pohon Merkle (*Merkle Tree*) dan buku besar terdistribusi (*Permissioned Blockchain*) untuk menjamin keaslian bukti digital (*non-repudiation*).
* **Metodologi Lengkap:**
  1. *Log Cryptographic Hashing:* Setiap batch event di-hash menggunakan SHA-256 dan dimasukkan ke struktur Merkle Tree.
  2. *Consensus Anchoring:* Root hash Merkle dicatat secara berkala ke ledger blockchain (Hyperledger Fabric).
  3. *Metrik Evaluasi:* Verification Proof Latency, Transaction Throughput (TPS), dan Storage Growth Overhead.
* **Research Gap:** Menyebabkan overhead latensi penulisan log yang cukup besar dan konsumsi penyimpanan bertambah drastis.
* **Pengisian Gap oleh Proyek:** Menggunakan pendekatan *centralized secure streaming forwarder* di mana log langsung diteruskan ke container sentral SIEM secara asinkron sesaat setelah terjadi, meminimalkan risiko manipulasi log lokal di target server.

---

```
================================================================================
JURNAL 12: Zero-Shot Semantic Log Parsing Using Large Language Models (LLM)
================================================================================
```
* **Judul Artikel:** *Zero-Shot Semantic Log Parsing and Anomaly Pre-Filtering Using Large Language Models*
* **Sinopsis:** Memanfaatkan model bahasa besar (LLM) untuk menguraikan format log yang sama sekali belum dikenal (*zero-shot unstructured logs*) tanpa perlu membuat aturan regular expression (regex) manual yang melelahkan.
* **Metodologi Lengkap:**
  1. *Prompt Template Engineering:* Merancang prompt terstruktur untuk mengekstraksi parameter kunci (`timestamp`, `IP`, `action`, `status`) dari baris log mentah.
  2. *Semantic Clustering:* Mengelompokkan log serupa menggunakan vektor representasi *text embedding*.
  3. *Metrik Evaluasi:* Parsing Accuracy (PA), Template Extraction F1-Score, dan Inference Latency per log.
* **Research Gap:** Latensi pemanggilan LLM per event terlalu lambat (100–500ms per log) dan biaya komputasi API tinggi jika diterapkan pada seluruh aliran log (*all-traffic stream*).
* **Pengisian Gap oleh Proyek:** Menggunakan parsing deterministik super cepat di Go untuk jalur utama (*high-speed data path*), dan hanya memanggil **AI / LLM sebagai asisten analis di tahap akhir (SOC Assistant)** untuk insiden yang sudah terkonfirmasi.

---

```
================================================================================
JURNAL 13: Context-Aware Alert Triage & False Positive Suppression (RL)
================================================================================
```
* **Judul Artikel:** *Context-Aware Alert Triage and False Positive Suppression Using Contextual Multi-Armed Bandits*
* **Sinopsis:** Mengurangi kelelahan analis (*alert fatigue*) dengan memfilter false positive secara adaptif menggunakan algoritma *Contextual Multi-Armed Bandit*. Keputusan triase (Eskalasi, Simpan sebagai konteks, atau Redam) disesuaikan dengan konteks aset target dan umpan balik analis.
* **Metodologi Lengkap:**
  1. *Context Enrichment:* Menggabungkan data alert dengan skor kritikalitas aset, CVSS vulnerability, dan IAM role.
  2. *MAB Decision Policy:* Memilih tindakan berdasarkan reward function:
     $$R = w_1 \cdot \text{TP}_{\text{verified}} - w_2 \cdot \text{FN}_{\text{missed}} - w_3 \cdot \text{Analyst Workload}$$
  3. *Metrik Evaluasi:* Alert Reduction Rate (%), False Positive Filter Accuracy, dan Analyst Response Time.
* **Research Gap:** Membutuhkan sistem eksternal enterprise yang rumit (CMDB aset, integrasi ticketing Jira/ServiceNow) dan rawan kendala *cold-start*.
* **Pengisian Gap oleh Proyek:** Menerapkan sistem *Alert Deduplication* dan penilaian risiko berbasis metadata ancaman IP (Threat Intel & Geolocation) yang langsung aktif dan mandiri.

---

```
================================================================================
JURNAL 14: Automated Incident Response (SOAR) Using Deep Reinforcement Learning
================================================================================
```
* **Judul Artikel:** *Automated Incident Response Orchestration Using Deep Reinforcement Learning for Dynamic SOAR Playbooks*
* **Sinopsis:** Menggantikan *playbook* mitigasi insiden statis yang kaku dengan agen *Deep Reinforcement Learning (DRL)* yang secara dinamis memilih tindakan defensif terbaik (misal: blokir IP firewall, isolasi subnet, atau reset kredensial) dengan mempertimbangkan dampak gangguan operasional bisnis (*business disruption cost*).
* **Metodologi Lengkap:**
  1. *State-Action Modeling:* Memodelkan status jaringan dan opsi aksi mitigasi ke dalam lingkungan simulasi berbasis OpenAI Gym.
  2. *DRL Agent Training:* Melatih algoritma *Proximal Policy Optimization (PPO)* dengan fungsi reward yang menyeimbangkan antara kecepatan mitigasi dan ketersediaan layanan (*uptime*).
  3. *Metrik Evaluasi:* Mean Time to Remediate (MTTR), Collateral Damage Ratio, dan Policy Stability Score.
* **Research Gap:** Pengambilan keputusan mitigasi otomatis berbasis neural network memiliki sifat *black-box* yang berisiko memblokir lalu lintas bisnis penting (*high blast radius*).
* **Pengisian Gap oleh Proyek:** Menerapkan mekanisme mitigasi aktif yang transparan dan aman (*deterministic defensive action*), seperti *auto-ban IP penyerang* pada level firewall Linux container (`iptables`) atau penguncian akun sementara.

---

```
================================================================================
JURNAL 15: Causality-Preserving Provenance Graph for Forensic Investigation
================================================================================
```
* **Judul Artikel:** *Causality-Preserving Provenance Graph Construction from SIEM Logs for Automated Forensic Investigation*
* **Sinopsis:** Membangun graf silsilah (*Provenance Graph*) dari kumpulan log SIEM untuk merekonstruksi riwayat serangan secara kronologis, memungkinkan analis melakukan investigasi akar masalah (*Root Cause Analysis*) dan mengetahui batas area dampak serangan (*Blast Radius*) secara otomatis.
* **Metodologi Lengkap:**
  1. *Causal Event Stitching:* Menghubungkan log dari proses sistem operasi, lalu lintas jaringan, dan autentikasi menggunakan algoritma *Backward & Forward Taint Tracking*.
  2. *Graph Reduction:* Menerapkan teknik reduksi simpul redundan untuk mengecilkan ukuran graf hingga 80% tanpa kehilangan informasi kausalitas.
  3. *Metrik Evaluasi:* Graph Construction Latency, Query Response Time untuk Root Cause, dan Memory Compression Ratio.
* **Research Gap:** Membutuhkan instrumentasi level kernel yang sangat rinci (seperti Linux Auditd / eBPF) yang menghasilkan volume data raksasa dan menambah beban I/O sistem.
* **Pengisian Gap oleh Proyek:** Merekam jejak audit terstruktur tingkat aplikasi (*Application-Level Telemetry*) yang mencatat relasi antar service (Auth di Server 1 vs Resource Request di Server 2) dengan efisien.

---

## 📊 3. Matriks Perbandingan Komprehensif (State of the Art 15 Jurnal)

| No | Paper / Referensi | Domain / Pendekatan Inti | Kelebihan Utama | Kelemahan / Gap | Posisi Proyek Mini-SIEM Golang Anda |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | Al-Mamun et al. (2023) | In-Memory Stream Correlation | Latensi rendah, throughput tinggi | Format rule internal/proprietary | **Menggunakan standar terbuka Sigma YAML** |
| **2** | Al-Dalky et al. (2021) | Sliding Window on SSH | Akurat deteksi Brute Force dinamis | Hanya single-host & protokol SSH | **Diimplementasikan multi-node berbasis Docker** |
| **3** | Sharma & Gupta (2022) | Modular SIEM Blueprint | Cetak biru arsitektur modular | Post-processing DB, lambat | **In-stream processing native Golang** |
| **4** | Lee et al. (2023) | Sigma Rules Standardization | Interoperabilitas MITRE ATT&CK | Belum ada runtime engine mandiri | **Menyediakan built-in Sigma runtime engine** |
| **5** | Gonzalez & Lopez (2024) | Upstream Stream Enrichment | Memangkas MTTD hingga 40% | Butuh stack raksasa (Kafka/Flink) | **Single-binary lightweight (<100MB RAM)** |
| **6** | Wazuh ML Framework | ML Anomaly on Open-Source SIEM | Deteksi zero-day anomaly | Overhead resource sangat tinggi | **Sangat ringan, deterministic, low-latency** |
| **7** | Deep Learning UEBA | LSTM Autoencoder User Baseline | Deteksi insider threat halus | Butuh training lama & clean data | **Deteksi anomali geolokasi & hosting instan** |
| **8** | Evolutionary Algorithms | Genetic Algorithm Attack Search | Menemukan rantai serangan rumit | Lambat (batch), tidak real-time | **In-Memory Sliding Window real-time** |
| **9** | Graph Cloud-Native | GNN & DAG Microservices | Visualisasi lateral movement | Overhead memori graph DB tinggi | **Audit telemetri antar-service langsung di agent** |
| **10** | Lightweight SIEM | Ultra-Low Footprint Embedded | Hemat RAM untuk edge/SME | Tidak ada Web UI & Threat Intel | **Single-Binary lengkap UI & Threat Intel** |
| **11** | Blockchain Integrity | Merkle Tree Immutable Logs | Log anti-manipulasi (Forensik) | Latensi consensus & I/O tinggi | **Direct async streaming collector** |
| **12** | LLM Log Parser | Zero-shot LLM Unstructured Log | Fleksibel tanpa regex manual | Terlalu lambat & boros API | **LLM diposisikan sebagai AI SOC Assistant** |
| **13** | Contextual Bandit Triage | Reinforcement Learning Triage | Mengurangi *Alert Fatigue* | Butuh CMDB & Ticketing kompleks | **Alert Deduplication & Risk Scoring otomatis** |
| **14** | Dynamic SOAR DRL | Deep RL Playbook Orchestration | Respon otomatis adaptif | Sifat *black-box*, risiko outage | **Mitigasi aktif deterministik (iptables block)** |
| **15** | Provenance Graph | Causal Graph Taint Tracking | Root cause analysis otomatis | Butuh data eBPF/Kernel masif | **Audit telemetri aplikasi terstruktur** |

---

## 🎯 4. Kesimpulan Rekomendasi Arah Proyek Tugas Akhir (TA)

Dari analisis ke-15 jurnal di atas, posisi dan kebaruan (*novelty*) proyek **Mini-SIEM Golang** Anda berada pada titik temu yang sangat kuat dan realistis untuk Tugas Akhir:

1. **Lightweight & High-Performance Core (Jurnal 1, 3, 5, 10):** Menyatukan rantai Ingestion $\rightarrow$ Normalization $\rightarrow$ Upstream Threat Intel $\rightarrow$ Sliding Window ke dalam satu binary Golang super efisien.
2. **Standard & Interoperable Rule Logic (Jurnal 2, 4):** Menghilangkan kelemahan proprietary rule dengan mengadopsi format standar industri **Sigma YAML** yang dieksekusi secara dinamis dengan buffer *Sliding Window*.
3. **Pragmatic AI Integration (Jurnal 12, 13):** Tidak membebani jalur utama data (*high-speed data stream*) dengan model AI berat, melainkan menempatkan LLM / AI pada modul hilir sebagai **AI SOC Assistant** untuk interpretasi insiden dan rekomendasi mitigasi.
4. **Clean Separation of Concerns:** Pembagian tugas terisolasi dari *Target Log Telemetry* (Server 1 & 2) $\rightarrow$ *Agent Forwarder* $\rightarrow$ *Central Ingest & Enrich* $\rightarrow$ *Sliding Window Engine* $\rightarrow$ *Incident Storage* $\rightarrow$ *Response Dispatcher*.


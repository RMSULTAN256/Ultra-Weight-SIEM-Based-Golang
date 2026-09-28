# BAB 2 LANDASAN TEORI

## 2.1 Tinjauan Pustaka

Tinjauan pustaka memetakan lima penelitian terdahulu yang menjadi rujukan dalam perancangan arsitektur, algoritma korelasi, standardisasi aturan deteksi, serta pengayaan intelijen ancaman pada sistem ini.

### Tabel 2.1 Matriks Tinjauan Pustaka

| Pembahasan | Masalah | Solusi | Hasil |
| :--- | :--- | :--- | :--- |
| **Revolutionizing SIEM Security: An Innovative Correlation Engine Design**<br>*(Al-Mamun et al., 2023 / Sheeraz et al., 2024)* | Kueri basis data relasional/disk pada SIEM konvensional menimbulkan *bottleneck* latensi dan konsumsi I/O tinggi saat volume aliran log (*event stream*) melonjak drastis. | Merancang arsitektur mesin korelasi *in-memory* paralel yang mengevaluasi aliran data keamanan secara langsung di lapisan memori komputasi sebelum disimpan ke basis data. | Mempercepat waktu respon deteksi hingga 21 kali lebih cepat dibandingkan sistem berbasis kueri penyimpanan disk, serta meningkatkan *throughput* pemrosesan log secara signifikan. |
| **SSHafe: A Real-time SSH Brute-Force Detection and Mitigation System**<br>*(Al-Dalky et al., 2021 / Mitra et al., 2026)* | Mekanisme pertahanan berbasis batas waktu kaku (*fixed time window*) sering gagal mendeteksi serangan *brute force* yang serangannya sengaja dipecah di batas interval waktu (*boundary window issue*). | Menerapkan algoritma *sliding window* dinamis pada antrean *event* autentikasi dengan stempel waktu presisi tinggi untuk memantau frekuensi percobaan dan *inter-arrival time*. | Mencapai tingkat akurasi deteksi (*True Positive Rate*) sebesar 99.96% dan memangkas waktu respon mitigasi insiden menjadi di bawah 10 detik. |
| **Effective Security Monitoring Using Efficient SIEM Architecture**<br>*(Sharma & Gupta, 2022)* | Biaya lisensi SIEM komersial sangat mahal dan arsitektur tertutup menyulitkan implementasi sistem pemantauan mandiri pada organisasi berskala kecil. | Menyusun cetak biru arsitektur SIEM modular dari awal (*from scratch*) yang terbagi menjadi 4 komponen: *Collector, Normalizer, Correlation Engine,* dan *Alert Dispatcher*. | Berhasil membangun prototipe SIEM mandiri yang fungsional memantau log heterogen (Apache, Syslog, dan audit basis data) secara terstruktur. |
| **AUTOSIGMA: Automated Generation and Evaluation of Sigma Rules for Cyber Threat Detection**<br>*(Lee et al., 2023 / Ghaffarzadegan et al., 2026)* | Format aturan deteksi pada SIEM komersial bersifat tertutup (*proprietary*), sehingga menyulitkan interoperabilitas dan pertukaran aturan deteksi ancaman antar-organisasi. | Menerapkan standardisasi aturan deteksi berbasis format terbuka *Sigma Rules* (YAML) yang dipetakan langsung ke taksonomi MITRE ATT&CK. | Menghasilkan aturan deteksi ancaman yang bersifat *vendor-neutral* dengan validitas sintaksis tinggi dan kompatibel digunakan lintas berbagai platform SIEM. |
| **Stream-Based Security Event Enrichment and Threat Intelligence Integration in Next-Generation SIEM**<br>*(Gonzalez & Lopez, 2024)* | Pengayaan data ancaman setelah log disimpan ke basis data (*post-ingestion enrichment*) memicu latensi deteksi tinggi dan membebani media penyimpanan server. | Menerapkan *upstream enrichment*, yaitu memperkaya metadata ancaman IP (reputasi, GeoIP, proxy/Tor) saat log masih mengalir di lapisan memori (*stream*). | Memangkas waktu deteksi (*Mean Time to Detect* / MTTD) hingga 40% dan mengeliminasi beban baca-tulis disk untuk proses pengayaan data. |

### Sintesis Gap Penelitian Terdahulu

Berdasarkan telaah terhadap kelima penelitian di atas, ditemukan beberapa kelemahan pada solusi yang telah dikembangkan:
1. Penelitian korelasi *in-memory* (Al-Mamun et al., 2023) masih mengandalkan format aturan *proprietary* yang tertutup dan bergantung pada instruksi perangkat keras khusus.
2. Penelitian algoritma *sliding window* (Al-Dalky et al., 2021) masih terbatas pada protokol tunggal (SSH) dan diuji pada lingkungan *single-host*.
3. Penelitian arsitektur SIEM modular (Sharma & Gupta, 2022) masih mengandalkan penulisan basis data disk sebelum evaluasi korelasi dijalankan (*post-processing*).
4. Penelitian standardisasi aturan Sigma (Lee et al., 2023) hanya berfokus pada otomasi pembuatan aturan tanpa menyediakan mesin eksekusi (*runtime engine*) mandiri yang ringan.
5. Penelitian pengayaan *upstream* (Gonzalez & Lopez, 2024) membutuhkan infrastruktur klaster enterprise berskala besar yang boros memori.

Oleh karena itu, pada penelitian Tugas Akhir ini diusulkan **Rancang Bangun Ultra-Lightweight SIEM Terdistribusi Berbasis Golang untuk Deteksi Ancaman pada Server Terbatas**. Sistem ini mengintegrasikan seluruh keunggulan di atas: pemrosesan aliran log *in-memory* yang hemat sumber daya (<80 MB RAM), algoritma *sliding window* dinamis untuk pengawasan *multi-node*, mesin evaluasi aturan standar terbuka *Sigma Rules* (YAML) yang dipetakan ke MITRE ATT&CK, serta pengayaan *threat intelligence upstream* dalam satu berkas biner mandiri (*single executable binary*) tanpa ketergantungan pada klaster basis data yang berat.

---

## 2.2 Dasar Teori

### 2.2.1 Konsep SIEM dan Arsitektur Terdistribusi (Agent-Collector)
Security Information and Event Management (SIEM) merupakan pendekatan komprehensif dalam pengelolaan keamanan informasi yang menggabungkan kapabilitas Security Information Management (SIM) untuk analisis log jangka panjang serta Security Event Management (SEM) untuk pemantauan dan korelasi insiden secara real-time. Arsitektur dasar SIEM bekerja melalui empat tahapan utama: pengumpulan data (*ingestion*), penyeragaman skema log heterogen (*normalization*), analisis keterkaitan ancaman (*correlation*), serta penerbitan notifikasi insiden (*alerting*) kepada analis keamanan (Sharma & Gupta, 2022).

Dalam implementasi skala modern, SIEM mengadopsi model terdistribusi berbasis agen dan pengumpul terpusat (*Agent-Collector Architecture*). *Forwarder agent* berbobot ringan diinstal pada setiap node server target untuk menangkap rekaman aktivitas sistem dan mengirimkannya melalui jalur asinkron ke server sentral. Pendekatan ini memisahkan beban ekstraksi data dari mesin pemrosesan analitik, sehingga server target tetap beroperasi optimal tanpa terbebani proses korelasi yang intensif.

### 2.2.2 Konkurensi dan Manajemen Memori Golang
Bahasa pemrograman Golang dirancang khusus untuk menangani komputasi berkinerja tinggi melalui model konkurensi berbasis *Communicating Sequential Processes* (CSP). Alih-alih mengalokasikan *thread* sistem operasi yang berat (2 MB per thread), Go memanfaatkan goroutine dengan alokasi tumpukan (*stack*) memori awal hanya sebesar 2 KB yang dapat bertambah secara dinamis. Komunikasi data antar-goroutine diatur menggunakan *buffered channels*, memungkinkan aliran log dipindahkan antar-pekerja (*worker pool*) secara aman tanpa memicu kondisi perlombaan data (*race conditions*).

Selain efisiensi eksekusi, Golang menyediakan struktur data aman-ulir `sync.Map` yang dioptimalkan untuk pola pembacaan berulang dengan penguncian minimal (*lock-free read*). Karakteristik ini memungkinkan data streaming log dievaluasi langsung pada lapisan memori acak (RAM) tanpa bergantung pada runtime pihak ketiga yang berat seperti *Java Virtual Machine* (JVM). Hasil kompilasi biner statis tunggal (*single executable binary*) menjadikan aplikasi Go sangat ideal untuk dioperasikan pada server dengan keterbatasan memori (<80 MB RAM) (Al-Mamun et al., 2023).

### 2.2.3 Algoritma Sliding Window Correlation
Algoritma *sliding window* merupakan metode evaluasi data berbasis deret waktu (*time-series*) yang menghitung frekuensi anomali dalam rentang jendela waktu dinamis $[T - \Delta t, T]$, di mana batas jendela bergerak maju secara kontinu mengikuti stempel waktu kejadian terbaru (Mitra et al., 2026). Mekanisme ini berbeda secara mendasar dari pendekatan jendela waktu kaku (*fixed time window*) yang membagi waktu ke dalam blok interval tetap dan mereset penghitung secara berkala. Perbedaan konseptual antara kedua pendekatan ini diilustrasikan pada Gambar 2.1.

Secara matematis, penetapan batas jendela geser dinamis dirumuskan sebagai berikut:
$$\text{Window}(T) = [T - \Delta t, \; T]$$

Kondisi peringatan (*alert*) terpicu apabila akumulasi kejadian anomali yang cocok dengan kriteria aturan dalam rentang jendela waktu memenuhi ambang batas:
$$\text{Kondisi Terpicu} = \sum_{e \in E} f(e) \ge \theta, \quad \text{di mana } t(e) \in \text{Window}(T)$$

*Keterangan:*
* $T$ = Stempel waktu kejadian (*event*) terbaru yang masuk ke dalam sistem.
* $\Delta t$ = Rentang durasi jendela waktu pemantauan (*timeframe*, misalnya 300 detik / 5 menit).
* $e$ = Objek rekaman log keamanan dalam himpunan log $E$.
* $f(e)$ = Fungsi seleksi filter (bernilai 1 jika kondisi terpenuhi, misalnya HTTP status 401 atau 404, dan 0 jika tidak).
* $t(e)$ = Stempel waktu terjadinya kejadian $e$.
* $\theta$ = Ambang batas frekuensi kejadian (*threshold*, misalnya $\ge 5$ kali).

Pendekatan *sliding window* secara efektif menyelesaikan permasalahan batas waktu (*boundary window issue*), di mana penyerang sengaja memecah laju percobaan serangan di sekitar batas pergantian interval menit agar tidak melampaui batas ambang sistem pertahanan konvensional. Di dalam memori sistem, algoritma memelihara antrean stempel waktu per entitas alamat IP. Pemangkasan (*pruning*) stempel waktu yang telah melewati ambang batas durasi ($< T - \Delta t$) dilakukan seketika sebelum kalkulasi frekuensi dijalankan, menghasilkan evaluasi berlatensi mikrodetik tanpa beban kueri disk.

Guna mengantisipasi variasi kecepatan serangan penyerang—mulai dari serangan kilat (*burst attacks*) hingga serangan lambat yang dicicil perlahan (*low-and-slow attacks*)—algoritma ini diperluas menggunakan pendekatan *Multi-Scale Sliding Window* (Mitra et al., 2026). Alih-alih hanya mengandalkan satu jendela waktu tunggal, sistem mengevaluasi korelasi kejadian secara simultan pada tiga skala jendela temporal yang berbeda:
1. **Skala Mikro (*Micro-Window*, $\Delta t = 30$ detik):** Dirancang untuk mendeteksi serangan otomasi skrip agresif berkecepatan tinggi dengan ambang batas ketat ($\theta \ge 3$ kali kegagalan).
2. **Skala Standar (*Standard Window*, $\Delta t = 5$ menit):** Menangani pola serangan *brute force* umum pada lapisan autentikasi ($\theta \ge 5$ kali kegagalan).
3. **Skala Makro (*Macro-Window*, $\Delta t = 30$ menit):** Mengidentifikasi serangan merayap (*stealthy brute force* atau *credential spraying*) yang sengaja diberi jeda antar-request untuk menghindari deteksi jendela pendek ($\theta \ge 10$ kali kegagalan).

Secara matematis, evaluasi multi-skala dirumuskan sebagai himpunan jendela waktu bertingkat $k \in \{\text{mikro}, \text{standar}, \text{makro}\}$:
$$\text{Window}_k(T) = [T - \Delta t_k, \; T]$$
$$\text{Kondisi Terpicu}_k = \sum_{e \in E} f(e) \ge \theta_k, \quad \text{di mana } t(e) \in \text{Window}_k(T)$$

Pada implementasi bahasa Golang, efisiensi penggunaan memori dijaga melalui teknik *Single-Slice Multi-Inspection*. Sistem tidak menduplikasi antrean data untuk tiap skala jendela, melainkan hanya menyimpan satu slice stempel waktu tunggal (`[]time.Time`) per alamat IP sepanjang durasi skala makro terbesar (30 menit) di dalam struktur aman-ulir `sync.Map`. Setiap event baru yang masuk cukup mengiterasi satu slice memori yang sama untuk mengevaluasi ketiga kondisi ambang batas, sehingga kapabilitas deteksi multi-skala dapat beroperasi dengan konsumsi memori yang sangat rendah (<250 byte per entitas alamat IP aktif).

### 2.2.4 Standar Aturan Deteksi Sigma Rules
Sigma Rules merupakan format spesifikasi aturan deteksi ancaman berskala terbuka (*open standard*) yang independen terhadap vendor tertentu (*vendor-neutral*) berbasis sintaksis YAML (Lee et al., 2023). Konsep ini mengusung paradigma *Detection-as-Code*, di mana logika identifikasi serangan ditulis sekali dalam bentuk berkas terstruktur yang mencakup metadata aturan, kriteria seleksi field (*selection*), relasi logika kondisi (*condition*), durasi pemantauan (*timeframe*), serta tingkat keparahan insiden (*level*).

Dengan mengadopsi format Sigma, sistem pemantauan keamanan tidak lagi terkunci pada bahasa kueri tertutup milik vendor komersial tertentu. Pada implementasi sistem mandiri, berkas YAML diuraikan ke dalam struktur *Abstract Syntax Tree* (AST) oleh parser internal untuk mencocokkan nilai field event log secara deterministik, menghadirkan fleksibilitas penambahan deteksi ancaman baru tanpa memerlukan kompilasi ulang kode sumber sistem.

### 2.2.5 Taksonomi MITRE ATT&CK (Teknik T1595 dan T1110)
MITRE ATT&CK (*Adversarial Tactics, Techniques, and Common Knowledge*) merupakan basis pengetahuan global yang mendokumentasikan taktik dan teknik serangan siber nyata berbasis observasi empiris. Penelitian ini memfokuskan deteksi pada dua teknik serangan berurutan dalam siklus rantai serangan siber (*Cyber Kill Chain*):

1. **Teknik T1595 (Active Scanning):** Berada di bawah taktik *Reconnaissance* (TA0043), khususnya sub-teknik T1595.002 (*Vulnerability Scanning*). Penyerang mengeksekusi pemindaian direktori web secara massal untuk mencari berkas konfigurasi sensitif (`.env`, `.git`, backup), yang diidentifikasi melalui anomali frekuensi lonjakan status kode HTTP 404 (*Not Found*) atau 403 (*Forbidden*) dari alamat IP sumber yang sama.
2. **Teknik T1110 (Brute Force):** Berada di bawah taktik *Credential Access* (TA0006), mencakup sub-teknik T1110.001 (*Password Guessing*), T1110.003 (*Password Spraying*), dan T1110.004 (*Credential Stuffing*). Penyerang mencoba kombinasi kredensial pengguna secara berulang, yang teridentifikasi melalui pola kegagalan autentikasi berkode respons HTTP 401 (*Unauthorized*) dalam jendela waktu tertentu.

### 2.2.6 Upstream Threat Intelligence Enrichment
Pengayaan data intelijen ancaman (*Cyber Threat Intelligence* / CTI) merupakan proses menambahkan konteks keamanan eksternal ke dalam data log mentah guna mempercepat penilaian risiko ancaman. Pada arsitektur SIEM konvensional, proses pengayaan sering kali dilakukan setelah log disimpan ke dalam basis data (*post-ingestion enrichment*), yang menimbulkan beban operasi baca-tulis disk dan meningkatkan latensi deteksi. Perbedaan alur pemrosesan antara kedua pendekatan ini disajikan pada Gambar 2.2.

Metode pengayaan hulu (*upstream enrichment*) mengeksekusi pemeriksaan metadata ancaman tepat saat data log masih mengalir di lapisan memori komputasi sebelum evaluasi korelasi aturan dijalankan (Gonzalez & Lopez, 2024). Sistem memeriksa alamat IP sumber terhadap basis data intelijen untuk mengidentifikasi apakah entitas tersebut terafiliasi dengan jaringan proksi, simpul keluar Tor (*Tor exit node*), atau penyedia hosting/pusat data (*datacenter*). Informasi kontekstual ini digunakan sebagai faktor pengubah risiko (*risk modifier*) guna mempercepat waktu deteksi insiden (*Mean Time to Detect* / MTTD).

### 2.2.7 Respon Insiden Otomatis Multi-Layer dan Firewall Linux
Berdasarkan panduan penanganan insiden keamanan NIST SP 800-61 Rev. 2, tahapan penahanan (*containment*) memegang peranan krusial untuk mencegah penyebaran dampak serangan sebelum kerusakan sistem meluas. Respon insiden otomatis (*dynamic containment*) mentranslasikan deteksi alert terkonfirmasi menjadi tindakan defensif terprogram tanpa menunggu intervensi manual analis keamanan. Pada arsitektur sistem ini, respon insiden diterapkan melalui pendekatan pertahanan berlapis (*defense-in-depth*) yang mencakup layer jaringan, layer aplikasi, serta preservasi bukti forensik:

1. **Penahanan Lapisan Jaringan (Network Layer L3/L4):**
   Pada lingkungan sistem operasi Linux, mitigasi level jaringan dieksekusi secara native melalui antarmuka *packet filtering* `iptables` pada tabel `filter` dan rantai `INPUT` kernel. Perintah pemblokiran dinamis (`iptables -A INPUT -s <IP> -j DROP`) memutus seluruh komunikasi paket data dari alamat IP penyerang sebelum menyentuh antarmuka soket aplikasi. Mekanisme ini meminimalkan beban komputasi server saat menghadapi banjir lalu lintas serangan volumetrik (Sallam et al., 2024).

2. **Penahanan Lapisan Aplikasi (Application Layer L7):**
   Guna mengantisipasi skenario deployment server web yang berada di belakang *reverse proxy*, *container gateway*, atau *Content Delivery Network* (CDN)—di mana pemblokiran `iptables` berisiko memutus antarmuka proxy utama—sistem mengintegrasikan mekanisme *in-memory IP blacklist* pada middleware Golang. Middleware mengekstrak alamat IP asli klien melalui header HTTP `X-Forwarded-For` atau `X-Real-IP` dan menolaknya seketika dengan status respons HTTP 403 (*Forbidden*) tanpa memproses alur kerja aplikasi maupun kueri basis data.

3. **Preservasi Bukti Forensik dan Notifikasi Insiden:**
   Sejalan dengan prinsip *Chain of Custody*, setiap eksekusi penahanan otomatis secara bersamaan mencatat snapshot metadata insiden—meliputi stempel waktu berpresisi tinggi, alamat IP penyerang, aturan Sigma yang terpicu, dan payload URI—ke dalam berkas bukti terstruktur `alerts.json`. Informasi insiden tersebut kemudian disiarkan secara *real-time* ke Web Dashboard pemantauan dan saluran notifikasi eksternal guna memfasilitasi audit investigasi lanjutan oleh tim analis keamanan.

Kecepatan respon mitigasi insiden otomatis (*Response Time / MTTR*) diukur berdasarkan selisih waktu antara terdeteksinya alert dan eksekusi tindakan pemutusan akses:
$$\text{Response Time} = T_{\text{blocked}} - T_{\text{alert}}$$

*Keterangan:*
* $T_{\text{alert}}$ = Stempel waktu saat kondisi aturan Sigma terpenuhi dan alert diterbitkan.
* $T_{\text{blocked}}$ = Stempel waktu saat perintah pemblokiran (`iptables` atau middleware blacklist) aktif mengeksekusi penolakan paket.

### 2.2.8 Metrik Evaluasi Kinerja Sistem
Evaluasi keberhasilan sistem deteksi dan efisiensi arsitektur diukur menggunakan parameter kuantitatif standar keamanan siber:

1. **Akurasi Deteksi (Recall dan Precision):**
   Tingkat keberhasilan sistem dalam mendeteksi serangan nyata (*True Positive*) dan menghindari kesalahan deteksi dihitung menggunakan matriks kebingungan (*Confusion Matrix*):
   $$\text{Recall} = \frac{TP}{TP + FN} \times 100\%$$
   $$\text{Precision} = \frac{TP}{TP + FP} \times 100\%$$

   *Keterangan:*
   * $TP$ (*True Positive*): Jumlah serangan brute force atau scanning yang berhasil dideteksi sistem.
   * $FN$ (*False Negative*): Jumlah serangan nyata yang gagal dideteksi (lolos dari sistem).
   * $FP$ (*False Positive*): Jumlah aktivitas pengguna sah yang salah dideteksi sebagai serangan.

2. **Kapasitas Throughput Pemrosesan Log:**
   Kapasitas pemrosesan aliran data dihitung dalam satuan *Events Per Second* (EPS):
   $$\text{Throughput (EPS)} = \frac{N_{\text{total\_events}}}{\Delta t_{\text{proses}}}$$

   *Keterangan:*
   * $N_{\text{total\_events}}$ = Total jumlah baris log yang diuji dalam aliran data.
   * $\Delta t_{\text{proses}}$ = Total waktu yang dibutuhkan sistem untuk memproses seluruh aliran log (dalam detik).

---

## 2.3 HIPOTESIS PENELITIAN

Berdasarkan rumusan masalah, tujuan penelitian, dan kajian landasan teori yang telah diuraikan, hipotesis yang diajukan dalam penelitian Tugas Akhir ini adalah:

1. **Hipotesis Deteksi Temporal (Sliding Window):**
   * **$H_{a1}$:** Penerapan algoritma *Sliding Window Buffer* berbasis *in-memory* pada Golang mampu mendeteksi serangan *brute force* dan *active scanning* secara akurat tanpa mengalami kegagalan deteksi pada batas interval waktu (*boundary window issue*).
   * **$H_{01}$:** Penerapan algoritma *Sliding Window Buffer* berbasis *in-memory* pada Golang tidak mampu mendeteksi serangan *brute force* dan *active scanning* secara akurat dan tetap mengalami kegagalan deteksi pada batas interval waktu (*boundary window issue*).

2. **Hipotesis Efisiensi Sumber Daya (Ultra-Lightweight Architecture):**
   * **$H_{a2}$:** Purwarupa arsitektur *Ultra-Lightweight SIEM* berbasis Golang mampu memproses aliran log keamanan terdistribusi dengan konsumsi memori di bawah 80 MB RAM pada kondisi beban operasional.
   * **$H_{02}$:** Purwarupa arsitektur *Ultra-Lightweight SIEM* berbasis Golang tidak mampu memproses aliran log keamanan terdistribusi dengan konsumsi memori di bawah 80 MB RAM pada kondisi beban operasional.

3. **Hipotesis Respon Insiden Otomatis (Dynamic Containment):**
   * **$H_{a3}$:** Mekanisme respon insiden otomatis berbasis *iptables* dan *in-memory blacklist* mampu memutus akses penyerang secara instan (sub-detik) setelah aturan deteksi Sigma terpicu.
   * **$H_{03}$:** Mekanisme respon insiden otomatis berbasis *iptables* dan *in-memory blacklist* tidak mampu memutus akses penyerang secara instan (sub-detik) setelah aturan deteksi Sigma terpicu.

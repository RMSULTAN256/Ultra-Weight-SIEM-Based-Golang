# 📂 Indeks & Direktori Catatan Proyek Tugas Akhir (Mini-SIEM Golang)

Folder ini mengumpulkan seluruh dokumentasi riset, tinjauan literatur jurnal akademik, perancangan arsitektur, diagram visual interaktif, dan berkas draf proposal Tugas Akhir (TA) ke dalam satu tempat terstruktur.

---

## 📑 1. Berkas Catatan & Riset Utama (Markdown)

| File | Deskripsi Isi |
| :--- | :--- |
| **[`01_fokus_zero_trust_dan_arsitektur_ta.md`](./01_fokus_zero_trust_dan_arsitektur_ta.md)** | **Catatan Baru:** Formulasi judul resmi, landasan filosofis Zero Trust Architecture (NIST SP 800-207), pemisahan PDP & PEP, optimasi ultra-lightweight (<80MB RAM), alur closed-loop dynamic containment, serta skenario pengujian komparatif untuk sidang TA. |
| **[`02_catatan_literatur_dan_judul_ta.md`](./02_catatan_literatur_dan_judul_ta.md)** | **Tinjauan Pustaka 15 Jurnal:** Analisis mendalam 15 artikel jurnal primer (abstrak, metodologi, kesimpulan, gap, poin adopsi), matriks perbandingan State-of-the-Art, dan 8 opsi variasi judul TA. |
| **[`03_rencana_implementasi_siem.md`](./03_rencana_implementasi_siem.md)** | **Rencana Implementasi Teknis:** Perancangan arsitektur Agent-Server Docker CentOS, mekanisme buffer Sliding Window, single-binary web dashboard, dan konfigurasi multi-node compose. |
| **[`04_tabel_tinjauan_pustaka_bab2.md`](./04_tabel_tinjauan_pustaka_bab2.md)** | **Tabel Matriks Bab 2.1 Resmi:** Tabel 4 kolom (*Pembahasan*, *Masalah*, *Solusi*, *Hasil*) mencakup 15 jurnal sesuai format panduan proposal Polibatam beserta sintesis penutupnya. |
| **[`05_bab2_landasan_teori_lengkap.md`](./05_bab2_landasan_teori_lengkap.md)** | **Naskah Lengkap Bab 2:** Tabel 5 jurnal matriks tinjauan pustaka, paragraf sintesis gap penelitian terdahulu yang telah dikoreksi, dan 7 subbab dasar teori naratif lengkap (2.2.1 s.d. 2.2.7). |
| **[`06_sesi_arsitektur_multi_node_dan_wazuh_dashboard.md`](./06_sesi_arsitektur_multi_node_dan_wazuh_dashboard.md)** | **Catatan Sesi Implementasi:** Rancang bangun simulasi 7 container multi-node Docker, format ingestion NDJSON, Web Dashboard Wazuh-Lean (Go embed + SSE), modul Inbound IP Traffic Tracker, serta pembatasan memori <100MB RAM. |
| **[`07_panduan_setup_nginx_reverse_proxy_dan_systemd.md`](./07_panduan_setup_nginx_reverse_proxy_dan_systemd.md)** | **Panduan Lengkap Web Hosting & Telemetri:** Konfigurasi Nginx Reverse Proxy dari nol, pengelolaan aplikasi backend sebagai Systemd Service, integrasi Cloudflare Tunnel ke Nginx (bukan bypass), perbaikan permission denied, dan mekanisme pembacaan `/var/log/nginx/access.log` untuk sensor SIEM. |

---

## 🖼️ 2. Diagram Arsitektur & Workflow Visual (`catatan/diagram/`)

Semua diagram disajikan dalam format standalone HTML interaktif dengan grafik inline SVG resolusi tinggi:

1. **[`diagram/diagram_full_master_siem.html`](./diagram/diagram_full_master_siem.html)**
   * **Master Arsitektur Lengkap:** Diagram satu kesatuan utuh mencakup zona adversary, container target CentOS, pipeline in-stream Golang core, dynamic firewall response, dan cockpit analis SOC.
2. **[`diagram/referensi_diagram_siem_lain.html`](./diagram/referensi_diagram_siem_lain.html)**
   * **Bedah SIEM Nyata:** Diagram dan analisis internal sistem SIEM nyata (Wazuh Daemons, Simple Event Correlator/SEC, Splunk Enterprise Security RBA, MDPI Optimized Correlator, dan AutoSigma).
3. **[`diagram/arsitektur_detail_mini_siem.html`](./diagram/arsitektur_detail_mini_siem.html)**
   * **Spesifikasi & Toolkit:** Pemetaan detail interaksi subsistem, lingkungan Docker bridge, dan toolkit Go per modul.
4. **[`diagram/koleksi_diagram_arsitektur_siem.html`](./diagram/koleksi_diagram_arsitektur_siem.html)**
   * **Ensiklopedia 5 Diagram Detail:** Diagram teknis per konsep (Sliding Window, Sigma Engine, Upstream CTI, Closed-Loop SOAR, Topologi Port).
5. **[`diagram/diagram_5_jenis_siem.html`](./diagram/diagram_5_jenis_siem.html)**
   * **Taksonomi 5 Generasi SIEM:** Perbandingan alur data dan beban sumber daya dari Gen-1 hingga Gen-5.

---

## 📄 3. Berkas Draf Proposal Resmi (`catatan/proposal/`)

Dokumen formal yang siap diedit di Word dan dicetak untuk keperluan pendaftaran judul / seminar proposal:

* **[`proposal/RINGKASAN_LITERATUR_DAN_PROPOSAL_TA_V2.docx`](./proposal/RINGKASAN_LITERATUR_DAN_PROPOSAL_TA_V2.docx)**: Dokumen Word resmi berformat standar Polibatam (margin 3-4-3-3 cm, font Times New Roman, tabel IEEE).
* **[`proposal/RINGKASAN_LITERATUR_DAN_PROPOSAL_TA_V2.pdf`](./proposal/RINGKASAN_LITERATUR_DAN_PROPOSAL_TA_V2.pdf)**: Dokumen PDF hasil kompilasi.

---

## 🔗 Keterkaitan dengan Folder Lain

* **`artikel/`**: Menyimpan seluruh file PDF asli dan naskah jurnal ilmiah akademik yang diunduh.
* **`data/`**: Menyimpan dataset feed IP ancaman (`data/ips/`) dan contoh log serangan (`data/logs/`).
* **`services/`**: Modul integrasi CTI & GeoIP Go (`ipapi.go`).
* **`rule.yaml`**: Berkas aturan deteksi standar Sigma HQ.

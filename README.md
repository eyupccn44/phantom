# Phantom v3 — Red Team AI Agent

> **YASAL UYARI:** Phantom yalnızca yazılı izin alınmış sistemlerde, kendi laboratuvar ortamlarında veya CTF altyapılarında kullanılmalıdır. Yetkisiz kullanım yasadışıdır.

Phantom, MITRE ATT&CK çerçevesi, NVD/CVE zekası ve çok ajanlı otomasyon sistemini bir arada sunan açık kaynak Red Team AI ajanıdır. Tamamen yerel çalışan Ollama LLM entegrasyonu sayesinde buluta veri göndermez.

---

## Özellikler

- **Otomatik Keşif** — Nmap, WHOIS, ping, subdomain enum (crt.sh + DNS brute-force)
- **MITRE ATT&CK** — 700+ teknik haritalama motoru, Navigator JSON export
- **CVE Zekası** — NVD/CVE veritabanı sorgusu, CVSS skorlama
- **Çok Ajanlı Sistem** — Commander + uzman ajanlar (Recon, CVE, MITRE, Risk, Exploit, Report)
- **APT Simülasyonu** — APT29, Lazarus, APT41, Sandworm ve daha fazlası
- **WAF Tespiti** — Cloudflare, Akamai, ModSecurity ve diğerleri
- **Web Fingerprint** — Teknoloji stack tespiti
- **Default Creds** — Yaygın servisler için varsayılan kimlik bilgisi testi
- **Honeypot Tespiti** — TTL ve banner anomali analizi
- **Red vs Blue** — Hem saldırı hem savunma perspektifinden analiz
- **Raporlama** — Markdown ve HTML çıktı, session kaydı

---

## Kurulum

### Gereksinimler

- Python 3.10+
- [nmap](https://nmap.org/download.html)
- [Ollama](https://ollama.ai)

### Adımlar

```bash
# 1. Klonla
git clone https://github.com/kullanici/phantom
cd phantom

# 2. Sanal ortam oluştur
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. nmap kur (macOS)
brew install nmap

# 4. Ollama kur ve model indir
ollama serve
ollama pull llama3

# 5. Çalıştır
./run.sh --target 192.168.1.1
```

---

## Kullanım

```bash
# Temel tarama
./run.sh --target 192.168.1.1

# Tam kapsam
./run.sh --target 10.0.0.1 --scope full

# Çok ajanlı ekip analizi
./run.sh --target 10.0.0.1 --scope full --agents

# Hızlı mod + subdomain + WAF
./run.sh --target ornek.com --fast --sub --waf

# APT29 adversary simülasyonu
./run.sh --target 10.0.0.1 --adv APT29

# HTML rapor üret
./run.sh --target 10.0.0.1 --report --html

# Honeypot tespiti
./run.sh --target 10.0.0.1 --honeypot

# Red vs Blue simülasyonu
./run.sh --target 10.0.0.1 --redvsblue

# Geçmiş sessionları listele
./run.sh --sessions
```

### Tüm Bayraklar

| Bayrak | Açıklama |
|--------|----------|
| `--target / -t` | Hedef IP veya domain |
| `--scope / -s` | `external` / `internal` / `web` / `full` |
| `--fast / -f` | Hızlı tarama (top 1000 port) |
| `--sub` | Subdomain enumeration |
| `--waf` | WAF tespiti |
| `--fp` | Web teknoloji parmak izi |
| `--creds` | Default credential testi |
| `--adv APT_NAME` | Adversary simulation (örn: APT29, Lazarus) |
| `--navigator` | MITRE Navigator JSON export |
| `--graph` | Attack path graph |
| `--report` | Markdown rapor üret |
| `--html` | HTML rapor üret |
| `--honeypot` | Honeypot tespiti |
| `--drift` | Attack surface drift analizi |
| `--blindspot` | Defender kör nokta matrisi |
| `--redvsblue` | Red vs Blue simülasyonu |
| `--trust IP1,IP2` | Multi-target trust graph |
| `--agents` | Çok ajanlı ekip analizi |
| `--auto` | Tam otomatik mod (interaktif yok) |
| `--model MODEL` | Ollama model seç (varsayılan: otomatik) |
| `--sessions` | Geçmiş session listesi |

---

## Mimari

```
phantom/
├── phantom.py          # Ana CLI giriş noktası
├── run.sh              # Başlatma scripti (venv yönetimi)
├── requirements.txt
├── data/               # MITRE, CVE, default creds veritabanları
├── prompts/            # LLM sistem promptları
├── sessions/           # Tarama geçmişi (otomatik oluşur)
├── reports/            # Markdown/HTML raporlar (otomatik oluşur)
└── core/
    ├── tools.py        # Nmap, ping, whois
    ├── mitre.py        # MITRE ATT&CK haritalama
    ├── cve.py          # CVE/NVD sorgulama
    ├── llm.py          # Ollama istemcisi
    ├── agent_loop.py   # ReAct ajanlik döngüsü
    ├── memory.py       # Session belleği
    ├── subdomain.py    # Subdomain enumeration
    ├── waf.py          # WAF tespiti
    ├── fingerprint.py  # Web fingerprint
    ├── adversary.py    # APT profilleme
    ├── honeypot.py     # Honeypot tespiti
    ├── drift.py        # Attack surface drift
    ├── blindspot.py    # Defender kör nokta
    ├── redvsblue.py    # Red vs Blue
    ├── trustgraph.py   # Multi-target trust graph
    ├── html_report.py  # HTML rapor üretici
    ├── navigator.py    # MITRE Navigator export
    └── agents/         # Çok ajanlı sistem
        ├── commander.py
        ├── recon.py
        ├── intel.py
        ├── threat.py
        ├── exploit.py
        ├── defense.py
        ├── attack.py
        ├── opsec.py
        ├── web.py
        ├── validator.py
        └── referee.py
```

---

## Lisans

MIT License — Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.

> Bu araç yalnızca eğitim, araştırma ve yetkili güvenlik testleri için tasarlanmıştır.

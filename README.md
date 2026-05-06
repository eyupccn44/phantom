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

| Bileşen | Sürüm | Açıklama |
|---------|-------|----------|
| Python | 3.10+ | Ana çalışma ortamı |
| nmap | 7.80+ | Port tarama motoru |
| Ollama | Güncel | Yerel LLM çalıştırıcı |

---

### macOS

```bash
# 1. Depoyu klonla
git clone https://github.com/eyupccn44/phantom
cd phantom

# 2. Python sürümünü kontrol et (3.10+ gerekli)
python3 --version

# 3. Sanal ortam oluştur ve aktifleştir
python3 -m venv .venv
source .venv/bin/activate

# 4. Bağımlılıkları yükle
pip install -r requirements.txt

# 5. nmap kur (Homebrew ile)
brew install nmap

# 6. Ollama kur
#    https://ollama.ai/download adresinden .dmg indir ve yükle
#    veya:
brew install ollama

# 7. Ollama'yı arka planda başlat
ollama serve &

# 8. LLM modelini indir (birini seç)
ollama pull llama3          # Dengeli — önerilen başlangıç
ollama pull mistral         # Hızlı ve hafif
ollama pull deepseek-r1     # Daha derin akıl yürütme

# 9. Çalıştır
./run.sh --target 192.168.1.1
```

---

### Linux (Ubuntu / Debian)

```bash
# 1. Sistem bağımlılıklarını kur
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nmap git curl

# 2. Depoyu klonla
git clone https://github.com/eyupccn44/phantom
cd phantom

# 3. Python sürümünü kontrol et
python3 --version   # 3.10+ olmalı

# Ubuntu 20.04 ise Python 3.10'u elle kur:
# sudo apt install -y python3.10 python3.10-venv

# 4. Sanal ortam oluştur ve aktifleştir
python3 -m venv .venv
source .venv/bin/activate

# 5. Bağımlılıkları yükle
pip install -r requirements.txt

# 6. Ollama kur
curl -fsSL https://ollama.ai/install.sh | sh

# 7. Ollama servisini başlat
ollama serve &

# 8. LLM modelini indir
ollama pull llama3

# 9. run.sh'a çalıştırma izni ver ve başlat
chmod +x run.sh
./run.sh --target 192.168.1.1
```

---

### Windows (WSL2 üzerinden)

```powershell
# 1. WSL2 + Ubuntu kur (PowerShell'i yönetici olarak aç)
wsl --install -d Ubuntu
```

WSL Ubuntu terminalinde devam et:

```bash
# 2. Sistem paketlerini güncelle
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nmap git curl

# 3. Depoyu klonla
git clone https://github.com/eyupccn44/phantom
cd phantom

# 4. Sanal ortam oluştur
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 5. Ollama kur
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve &
ollama pull llama3

# 6. Çalıştır
./run.sh --target 192.168.1.1
```

---

### Kurulumu Doğrulama

```bash
# Ollama çalışıyor mu?
curl http://localhost:11434/api/tags

# Nmap erişilebilir mi?
nmap --version

# Phantom başlıyor mu?
./run.sh --help
```

---

### Sorun Giderme

| Hata | Çözüm |
|------|-------|
| `Ollama bağlantısı başarısız` | `ollama serve` komutunu ayrı bir terminalde çalıştır |
| `Ollama çalışıyor ama kurulu model yok` | `ollama pull llama3` ile model indir |
| `nmap: command not found` | macOS: `brew install nmap` — Linux: `sudo apt install nmap` |
| `Permission denied: run.sh` | `chmod +x run.sh` ile çalıştırma izni ver |
| `ModuleNotFoundError` | `source .venv/bin/activate` ile sanal ortamı aktifleştir, sonra `pip install -r requirements.txt` |
| Python sürümü düşük | `python3.10 -m venv .venv` ile Python 3.10+ sanal ortam oluştur |

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

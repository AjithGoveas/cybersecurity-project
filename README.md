# 🛡️ QRShield — Smart QR Code Security Analyzer

> Detect phishing, quishing, and payload attacks hidden inside QR codes — before you scan.

QRShield is a multi-stage security analysis tool that decodes QR codes, inspects the embedded payload, traces redirect chains, classifies URLs with a machine-learning model, detects Unicode homograph attacks, and renders a safe preview of the target page — all from a single Streamlit dashboard.

---

## 📌 Problem Statement

QR codes are a blind spot in modern security. Traditional email gateways and web filters cannot inspect pixels inside images, so attackers place malicious QR codes over legitimate ones (parking meters, restaurant menus, payment counters) or embed them in phishing emails.

**Attack vectors QRShield detects:**

| Vector | Example |
|---|---|
| Malicious URL redirects | `bit.ly/x` → `evil.com/login` |
| Credential harvesting | Fake login pages behind shortened links |
| Unicode homograph spoofing | `pаypal.com` (Cyrillic `а` instead of Latin `a`) |
| Wi-Fi credential exfiltration | `WIFI:S:Cafe;P:password;;` auto-connect payloads |
| Punycode/IDN obfuscation | `xn--pple-43a.com` encoding |
| Vishing via auto-dial | `TEL:+1-800-SCAM` payloads |
| SMS pre-fill social engineering | `SMSTO:+123:Click this link` payloads |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Input Layer                        │
│    QR Image Upload  ·  Direct URL  ·  Raw Payload   │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Decoding Engine                        │
│         OpenCV + pyzbar (multi-preprocessing)       │
│    ┌──────────────────────────────────────────┐     │
│    │  8 preprocessing variants per image:     │     │
│    │  grayscale · adaptive · otsu · morphed   │     │
│    │  ×0.5 · ×1.5 · ×2.0 scale              │     │
│    └──────────────────────────────────────────┘     │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│          Multi-Stage Security Engine                │
│                                                     │
│  ┌─────────────────┐  ┌──────────────────────────┐  │
│  │  Redirect        │  │  Lexical & Domain        │  │
│  │  Tracer          │  │  Analysis                │  │
│  │  (301/302/307)  │  │  entropy · length · IP   │  │
│  │                  │  │  subdomains · punycode   │  │
│  └────────┬─────────┘  └────────────┬─────────────┘  │
│           │                         │                │
│  ┌────────▼─────────────────────────▼─────────────┐  │
│  │            ML Classifier                       │  │
│  │   pirocheto/phishing-url-detection (HuggingFace)│  │
│  │   LinearSVM · 94.9% accuracy · 0.987 ROC-AUC  │  │
│  └────────┬───────────────────────────────────────┘  │
│           │                                         │
│  ┌────────▼────────┐  ┌───────────────────────────┐  │
│  │  Homograph       │  │  Payload Type Profiler    │  │
│  │  Detector        │  │  WIFI · SMS · TEL         │  │
│  │  Cyrillic/Greek  │  │  EMAIL · VCARD · MECARD   │  │
│  │  mixed-script    │  │                           │  │
│  └─────────────────┘  └───────────────────────────┘  │
│                                                     │
│  ┌─────────────────┐  ┌───────────────────────────┐  │
│  │  Domain           │  │  Safe Preview             │  │
│  │  Intelligence     │  │  (Sandbox)                │  │
│  │  SSL · DNS · WHOIS│  │  HTML fetch → sanitize →  │  │
│  │                   │  │  strip scripts/forms      │  │
│  └─────────────────┘  └───────────────────────────┘  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Presentation Layer                     │
│         Streamlit Dashboard (app.py)                │
│  Threat gauge · Check table · Redirect chain        │
│  Metric cards · Domain intel · Sandbox preview      │
└─────────────────────────────────────────────────────┘
```

---

## ✨ Features

### QR Decoding
- Decodes QR codes from images using OpenCV + pyzbar
- 8 preprocessing variants (grayscale, adaptive threshold, Otsu, morphological, 3 resize scales) for maximum decode rate
- Fallback to OpenCV's built-in `QRCodeDetector` if pyzbar fails
- Handles multiple QR codes in a single image

### URL Analysis
- **Redirect tracer** — recursively follows HTTP 301/302/307/308 chains (up to 10 hops) to find the terminal domain
- **Lexical analysis** — URL length, Shannon entropy, IP-as-hostname, subdomain count, punycode detection, suspicious keyword matching, port anomalies, `@`-sign spoofing
- **Risk scoring** — weighted composite score (0–100) from all lexical features

### ML Classification
- Pre-trained **LinearSVM** model from [HuggingFace](https://huggingface.co/pirocheto/phishing-url-detection) (94.9% accuracy, 0.987 ROC-AUC)
- Auto-downloads on first use, caches locally in `models/`
- Heuristic fallback if model is unavailable

### Homograph / IDN Attack Detection
- Decomposes domains via Unicode NFKD normalization
- Maps known Cyrillic/Greek homoglyphs to ASCII (`а→a`, `е→e`, `о→o`, `р→p`, `с→c`, …)
- Detects mixed-script domains (Latin + Cyrillic/Greek in same domain)
- Flags punycode-encoded (`xn--`) domains

### Payload Type Profiler
- Classifies non-URL payloads: `WIFI:`, `SMSTO:`, `TEL:`, `MATMSG:`, `mailto:`, `BEGIN:VCARD`, `MECARD:`, plain text
- Assigns risk levels (HIGH / MEDIUM / LOW) per payload type
- Extracts structured data (SSID, password, phone number, recipient, etc.)

### Domain Intelligence
- SSL certificate validation (issuer, expiry, validity)
- DNS record resolution (A, MX, TXT)
- WHOIS domain age lookup (via system `whois` command, graceful fallback)

### Safe Preview (Sandbox)
- Fetches the target URL and strips `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, and all `on*` event handlers
- Returns sanitized text preview, page title, meta description
- Reports blocked elements, image count, external link count
- User never has to click the URL

---

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| QR Decoding | `opencv-python`, `pyzbar` | Extract QR data from images |
| Networking | `requests` | Redirect tracing, sandbox fetch |
| ML Engine | `scikit-learn` + HuggingFace Hub | URL phishing classification |
| HTML Parsing | `beautifulsoup4` | Sandbox preview sanitization |
| DNS | `dnspython` | A/MX/TXT record resolution |
| Domain Extraction | `tldextract` | Reliable domain parsing |
| Frontend | `streamlit` | Interactive dashboard |
| Environment | `conda` (prefix) | Reproducible local environment |

---

## 🚀 Setup

### Prerequisites
- [Miniconda](https://docs.conda.io/en/latest/miniconda.html) or Anaconda
- Python 3.11 (installed automatically by conda)

### Installation

```bash
# Clone the repository
git clone https://github.com/AjithGoveas/cybersecurity-project.git
cd cybersecurity-project

# Create the conda environment (local prefix, inside the repo)
conda env create -f environment.yml --prefix ./env

# Activate the environment
conda activate ./env

# Generate sample QR codes for testing
python scripts/generate_samples.py

# Run the app
streamlit run app.py
```

The app opens at **http://localhost:8501**.

---

## 📖 Usage

### 1. Upload a QR Code
1. Open the **Upload QR Code** tab
2. Drop a QR code image (PNG, JPG, BMP, GIF, TIFF)
3. QRShield decodes it and runs the full analysis pipeline
4. Review the threat gauge, check breakdown, and sandbox preview

### 2. Analyze a URL Directly
1. Open the **Enter URL** tab
2. Paste any URL
3. QRShield traces redirects, runs ML classification, checks for homographs, and fetches a safe preview

### Try These Samples

After running `python scripts/generate_samples.py`, upload from `data/sample_qr_codes/`:

| File | Payload | Expected Result |
|---|---|---|
| `safe_url.png` | `https://www.google.com` | ✅ Low risk |
| `phishing_url.png` | `http://192.168.1.1/secure-login-verify-...` | 🔴 High risk |
| `homograph_url.png` | `https://pаypal.com/login` (Cyrillic) | 🔴 Homograph flagged |
| `wifi_payload.png` | `WIFI:T:WPA;S:FreePublicWiFi;P:...` | 🔴 High risk (auto-connect) |
| `shortener_url.png` | `https://bit.ly/3xPhishing` | ⚠️ Redirect chain traced |
| `sms_payload.png` | `SMSTO:+1555...:Click here to verify` | ⚠️ Medium risk |
| `vcard_payload.png` | `BEGIN:VCARD...` | 🟢 Low risk |

---

## 📁 Project Structure

```
cybersecurity-project/
├── app.py                          # Streamlit UI (entry point)
├── config.py                       # Constants, thresholds, homoglyph map
├── environment.yml                 # Conda environment definition
├── .gitignore
│
├── core/                           # Analysis engine
│   ├── decoder.py                  # QR decoding (OpenCV + pyzbar)
│   ├── url_analyzer.py             # Redirect tracing + lexical analysis
│   ├── ml_classifier.py            # HuggingFace pre-trained model
│   ├── homograph_detector.py       # Unicode/IDN homograph detection
│   ├── payload_profiler.py         # WIFI/SMS/TEL/EMAIL/VCARD parsing
│   ├── domain_intel.py             # SSL, DNS, WHOIS intelligence
│   └── sandbox_preview.py          # Safe HTML preview
│
├── utils/                          # Shared utilities
│   ├── url_features.py             # Feature extraction functions
│   └── helpers.py                  # Formatting, validation helpers
│
├── tests/                          # 43 unit tests
│   ├── test_decoder.py
│   ├── test_url_analyzer.py
│   ├── test_homograph.py
│   ├── test_ml_classifier.py
│   └── test_payload.py
│
├── scripts/
│   └── generate_samples.py         # Generates 10 test QR codes
│
├── data/
│   └── sample_qr_codes/            # 10 sample QR images
│
└── models/                         # Cached ML model (gitignored)
```

---

## 🧪 Testing

```bash
conda activate ./env
python -m pytest tests/ -v
```

**43 tests** across 5 test suites:

| Suite | Tests | Covers |
|---|---|---|
| `test_decoder.py` | 10 | QR payload type detection, image decoding, error handling |
| `test_url_analyzer.py` | 13 | Feature extraction, entropy, IP detection, risk scoring |
| `test_homograph.py` | 8 | Cyrillic decomposition, mixed-script detection, punycode |
| `test_ml_classifier.py` | 5 | ML classification, fallback heuristic |
| `test_payload.py` | 7 | WIFI, SMS, TEL, EMAIL, VCARD, URL, text payloads |

---

## 🔬 How the Scoring Works

Each analysis module produces a 0–100 score. The **combined threat score** takes the maximum of:

1. **URL lexical risk** — weighted sum of length, entropy, IP hostname, punycode, subdomains, suspicious tokens, redirect depth
2. **ML classification** — phishing probability from the LinearSVM model
3. **Homograph penalty** — +80 if Unicode spoofing detected
4. **Domain intel penalty** — +15 per warning (expired SSL, young domain, no DNS records)

| Score | Verdict |
|---|---|
| 0 – 40 | 🟢 **Low Risk** — looks safe |
| 41 – 70 | 🟡 **Medium Risk** — proceed with caution |
| 71 – 100 | 🔴 **High Risk** — likely malicious |

---

## 📚 References

- [PhishTank](https://phishtank.org/) — Phishing URL database
- [HuggingFace: pirocheto/phishing-url-detection](https://huggingface.co/pirocheto/phishing-url-detection) — Pre-trained ML model
- [QR Code Standard (ISO/IEC 18004)](https://www.iso.org/standard/62021.html)
- [Unicode Homoglyph Attack Research](https://www.sans.org/reading-room/whitepapers/detection/homoglyph-attacks-36316)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing)

---

## 👤 Author

**Ajith Goveas**

---

## 📄 License

This project is developed as an academic assignment.

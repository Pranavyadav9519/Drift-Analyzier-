# 🎯 Scope Documentation

## What Sentinel Zero Local Protects

Sentinel Zero Local is a **multi-surface phishing shield** covering three attack vectors:

---

## 1. 🌐 Browser Extension (Primary)

**Supported Browsers**: Chrome, Edge, Brave (Chromium-based, Manifest V3)

**What it protects:**
- Links clicked in any web page
- URLs navigated to directly
- Redirects and shortened URLs (bit.ly, t.co, etc.)

**How it works:**
- `content.js` intercepts all link click events
- `background.js` sends URL to local API (`localhost:5050/check-url`)
- Results returned in <200ms; phishing banner shown if high risk
- Cache of 200 recent URLs avoids repeat API calls

**What it does NOT protect:**
- Downloads (executables, PDFs) — URL-based detection only
- Images or embedded content
- Encrypted traffic inspection (no MITM)

---

## 2. 🖥️ Desktop App & Login Protection (Behavior Layer)

**Covered via**: Backend (Node.js) + ML service (Python Flask)

**What it protects:**
- Login attempts to the Sentinel Zero-protected application
- Identity drift detection (new device, unusual hours, location changes)
- Credential theft post-phishing (anomalous login after account compromise)

**How it works:**
- Every login captures: IP, user-agent, hour, device fingerprint
- Isolation Forest model scores the login against historical patterns
- High-risk logins are blocked and trigger auto-healing

**Currently out of scope:**
- Third-party app monitoring (requires OS-level integration)
- VPN/proxy detection (planned future feature)

---

## 3. 📧 Email Client Integration (Roadmap)

**Planned support**: Outlook (VSTO add-in), Thunderbird (WebExtension), Gmail (content script)

**What it will protect:**
- Phishing emails before the user clicks any link
- Malicious attachments (URL extraction from PDFs)
- Display name spoofing ("Jeff Bezos" <no-reply@amaz0n.xyz>)

**Current workaround:**
- Copy suspicious email links and check via `POST /check-url`
- The browser extension will catch phishing links if clicked from email web clients (Gmail, Outlook Web)

---

## Scope Summary Table

| Surface | Status | Method | Coverage |
|---------|--------|--------|---------|
| Web browser (Chrome/Edge/Brave) | ✅ Implemented | Extension content.js | All HTTP/HTTPS links |
| Web browser (Firefox) | 🔄 Planned | Firefox Extension MV2/MV3 | All HTTP/HTTPS links |
| Login protection | ✅ Implemented | Backend + ML service | App-level logins |
| Email (Gmail web) | ✅ Partial | Browser extension catches clicks | Links only |
| Email (Outlook desktop) | 🔄 Planned | VSTO add-in | Links + attachments |
| Email (Thunderbird) | 🔄 Planned | WebExtension | Links + attachments |
| Mobile (Android) | 🔄 Roadmap | React Native + TF Lite | Web links |
| Mobile (iOS) | 🔄 Roadmap | Safari Extension | Web links |
| Desktop apps (general) | 🔄 Roadmap | OS-level proxy | All network traffic |

---

## What Sentinel Zero Local is NOT

- **Not a firewall**: Does not block all network traffic
- **Not an antivirus**: Does not scan files for malware signatures
- **Not a VPN**: Does not encrypt your network traffic
- **Not a password manager**: Does not store or generate passwords
- **Not a full EDR**: Does not monitor all process/file system activity

---

## Target Users

| User Type | Primary Use Case | Deployment |
|---------|----------------|-----------|
| Engineering students (NIT/IIT) | Protection from fake internship scams | Personal browser extension |
| Remote workers | Protection from phishing emails targeting corporate credentials | Browser extension + login protection |
| Small businesses (India) | Affordable alternative to enterprise tools like Proofpoint | Self-hosted full stack |
| Colleges/Universities | Campus-wide deployment without per-user licensing | Docker Compose deployment |

---

## Known Limitations

1. **Homograph attacks**: International domain names (IDN) with lookalike Unicode characters may bypass URL feature detection
2. **HTTPS does not equal safe**: Many phishing sites now use HTTPS; we detect this as low confidence, not safe
3. **Zero-day domains**: Brand-new phishing domains not yet in any dataset may score lower than actual risk
4. **Obfuscated redirectors**: URL shorteners or multi-hop redirectors may hide the final destination
5. **Local API dependency**: Browser extension requires `localhost:5050` to be running; fails silently if the API is down

---

## Out-of-Scope for Hackathon MVP

The following are planned but not implemented in the current version:
- Real federated learning across multiple users
- ONNX-converted DistilBERT model (training notebook provided but model file not included)
- Email client add-ins
- Mobile applications
- OS-level protection beyond browser/login

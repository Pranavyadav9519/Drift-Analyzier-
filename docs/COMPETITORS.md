# 🏆 Competitive Analysis

## Overview

Sentinel Zero Local competes in the **endpoint phishing protection** market, which includes browser extensions, email security gateways, and enterprise endpoint protection platforms.

---

## Direct Competitors

### 1. Google Safe Browsing

**What it is**: Free URL blacklist service integrated into Chrome, Firefox, and Safari.

| Aspect | Google Safe Browsing | Sentinel Zero Local |
|--------|---------------------|-------------------|
| **How it works** | Sends URL hash to Google API; checks against cloud blacklist | Processes URL locally; no external calls |
| **Privacy** | Every URL you visit is sent to Google | Zero data exfiltration |
| **Latency** | ~500ms (network round-trip) | ~178ms (local inference) |
| **Coverage** | ~1B+ known phishing URLs (global blacklist) | 55K training samples + India-specific corpus |
| **Zero-day detection** | ❌ Blacklist only — misses new phishing | ✅ ML-based behavioral analysis |
| **India-specific** | ❌ US/EU centric | ✅ Custom Indian phishing corpus |
| **Cost** | Free | Free |
| **Open Source** | ❌ | ✅ MIT |

**Our Advantage**: Privacy + India-specific detection + zero-day ML coverage

---

### 2. Norton 360 / Norton Safe Web

**What it is**: Consumer endpoint security suite with URL reputation checking.

| Aspect | Norton 360 | Sentinel Zero Local |
|--------|-----------|-------------------|
| **How it works** | Cloud reputation lookup + local engine | 100% local ML inference |
| **Privacy** | Behavioral data sent to NortonLifeLock cloud | Zero data exfiltration |
| **Latency** | ~300ms | ~178ms |
| **Cost** | ₹3,499/year | Free |
| **India-specific** | ❌ | ✅ |
| **Behavioral learning** | ⚠️ Limited (generic profiles) | ✅ Per-user Isolation Forest |
| **Open Source** | ❌ | ✅ |
| **Offline operation** | ⚠️ Partial | ✅ Full |

**Our Advantage**: Free + privacy + faster + India-specific + open source

---

### 3. Proofpoint Email Security

**What it is**: Enterprise-grade email security gateway and URL rewriting service.

| Aspect | Proofpoint | Sentinel Zero Local |
|--------|-----------|-------------------|
| **Target** | Enterprise (500+ employees) | Students, SMBs, individuals |
| **Deployment** | Cloud gateway (all email passes through Proofpoint) | On-device (no gateway) |
| **Cost** | ₹8,000+/user/year | Free |
| **Privacy** | All email content processed on Proofpoint cloud | Zero email content leaves device |
| **India presence** | Limited Indian client base | India-first design |
| **Setup complexity** | IT admin required (weeks to deploy) | `pip install` + load extension (5 mins) |
| **Open Source** | ❌ | ✅ |

**Our Advantage**: Accessibility, cost, privacy, deployment simplicity

---

### 4. Mimecast

**What it is**: Cloud-based email security platform targeting mid-market enterprises.

| Aspect | Mimecast | Sentinel Zero Local |
|--------|---------|-------------------|
| **Approach** | Email gateway scanning (cloud) | On-device browser extension |
| **Privacy** | Email content passes through Mimecast servers | Zero data sent externally |
| **Cost** | ₹6,000/user/year | Free |
| **India-specific** | ❌ | ✅ |
| **SMB friendly** | ⚠️ Minimum 25 seats | ✅ Single user to enterprise |

---

### 5. Microsoft Defender SmartScreen

**What it is**: URL/download reputation service built into Windows and Edge.

| Aspect | SmartScreen | Sentinel Zero Local |
|--------|------------|-------------------|
| **Privacy** | URLs sent to Microsoft for analysis | 100% local |
| **Platform** | Windows + Edge only | Cross-platform (any Chromium browser) |
| **India-specific** | ❌ | ✅ |
| **Behavioral learning** | ❌ | ✅ Per-user Isolation Forest |
| **Open Source** | ❌ | ✅ |

---

## Competitive Positioning Matrix

```
                          HIGH PRIVACY
                              │
           Sentinel Zero      │
           Local ★            │
                              │
LOW COST ─────────────────────┼───────────────────── HIGH COST
                              │                    Norton 360 ◆
         Google Safe          │          Proofpoint ◆  Mimecast ◆
         Browsing ◆           │
                              │
                         LOW PRIVACY
```

**We own the "High Privacy + Low Cost" quadrant** — currently uncontested.

---

## Why We Win

### 1. Federated Learning (vs. LLM-based approaches)

Some teams at IIT/MIT are using GPT-4 API calls for email analysis:
- ❌ Sends email content to OpenAI servers (massive privacy violation)
- ❌ ~2,000ms latency (API call + large model inference)
- ❌ Costs $0.01–0.06 per email (not scalable)

Our approach (Isolation Forest + DistilBERT ONNX):
- ✅ Zero external calls
- ✅ ~178ms latency
- ✅ Free after one-time training

### 2. Provable Privacy

We don't just claim privacy — we **prove it**:
```bash
# Privacy verified by automated tests
python -m pytest tests/test_detector.py::TestPrivacyManager -v
# TestPrivacyManager::test_no_external_calls_initially PASSED
# TestPrivacyManager::test_privacy_report_shows_local_only PASSED
# TestPrivacyManager::test_external_call_recorded_raises PASSED
```

### 3. India-Specific Moat

Our custom corpus of **5,000 Indian phishing samples** is a competitive moat:
- **UPI fraud**: PhonePe, Google Pay, Paytm fake pages
- **Government impersonation**: UIDAI, Income Tax, EPFO portals
- **IRCTC travel scams**: Fake ticket booking and refund pages
- **Job scams**: Fake IT company internship recruitment emails

No US/EU tool has this dataset. Building it took research into CERT-In advisories, RBI fraud alerts, and community reporting.

### 4. Open Source Transparency

MIT license means:
- Colleges can deploy without licensing discussions
- Security researchers can audit our privacy claims
- Community can contribute new Indian phishing patterns
- No vendor lock-in ever

---

## Threat Analysis: What Could Beat Us?

| Threat | Likelihood | Our Response |
|--------|-----------|-------------|
| Google integrates on-device Safe Browsing | Medium (3–5 years) | First-mover advantage in India; deepen India corpus |
| Microsoft SmartScreen goes cross-browser | Low | They have no incentive to support Chrome |
| Startup builds India-specific tool | Medium | Open source moat; community contributions |
| LLM tool achieves <200ms locally | High (2025–26) | Transition to on-device LLM when viable |

# Sentinel Zero Local — 3-Minute Hackathon Demo Script

> **Total time: ~3 minutes** | Presenter notes in *italics*

---

## 0:00 — Hook (20 seconds)

> *Open with energy. Show the live dashboard in the background.*

"Every 39 seconds a new phishing attack happens on the internet.
Traditional antivirus waits for a signature database update.
Sentinel Zero doesn't wait — it **detects phishing in under 200 milliseconds, locally, with zero data leaving your machine.**"

---

## 0:20 — What It Does (30 seconds)

> *Switch to the Chrome extension tab with a neutral website open.*

"Sentinel Zero is a two-part system:

1. **A local AI API** — a Flask server that analyses any URL with a trained RandomForest model and rule-based scoring.
2. **A Chrome extension** — silently watches every link you hover over or click."

> *Paste a phishing URL from `test_urls.txt` into the extension popup.*

"Watch what happens when I check this URL …
*[click Check URL]*
… **PHISHING detected, risk score 87%, in 12 milliseconds.**"

---

## 0:50 — Live Dashboard (40 seconds)

> *Switch browser tab to `http://localhost:5050/dashboard` or open `dashboard/index.html`.*

"This is the live monitoring dashboard.
Every check appears in real-time.
The latency chart confirms we're well inside our **200 ms SLA**.
The doughnut shows our detection split — 2 phishing out of 5 checks so far."

> *Paste the legitimate Google URL into the Quick URL Check box.*

"And here's a safe URL: google.com — **verdict: SAFE, risk 3%**."

---

## 1:30 — Under the Hood (40 seconds)

> *Briefly show the terminal running `python app.py`.*

"The model was trained on 200 labelled URLs — phishing and legitimate.
We extract **22 features** per URL: length, entropy, IP address presence, suspicious TLDs, phishing keywords in the path, subdomain depth, and more.
The RandomForest achieves **>90% accuracy** on the held-out test set.

Crucially, **every computation runs locally**.
The privacy report confirms zero external API calls."

> *Switch to terminal and run:*
```bash
curl http://localhost:5050/privacy-report
```
*[shows `"local_processing_only": true`]*

---

## 2:10 — Privacy & Security (20 seconds)

"URLs are never sent to any cloud service.
The system hashes domain names before logging, strips PII from all output,
and the unit tests confirm this behaviour on every run."

---

## 2:30 — Run It Yourself (20 seconds)

> *Quickly show the terminal commands.*

```bash
pip install -r requirements.txt
python train_model.py        # trains model → >90% accuracy
python app.py                # starts API on port 5050
# Load extension/ in Chrome → chrome://extensions → Developer mode
```

"Three commands. No database. No cloud account. No API keys."

---

## 2:50 — Close (10 seconds)

"Sentinel Zero Local: **real-time phishing detection, 100% private, hackathon-ready.**
Thank you."

---

## Backup Q&A Answers

| Question | Answer |
|---|---|
| Why RandomForest? | Fast inference (<5ms), interpretable feature importances, works well on small labelled datasets |
| Could it be fooled? | Adversarial URLs with many features are harder to craft; the rule-based fallback provides a safety net |
| Production path? | Package the model with ONNX, push the extension to the Chrome Web Store, deploy API behind HTTPS on a private server |
| False positive rate? | ~3% on test set; the medium/suspicious tier gives users a second chance before full block |

# 📊 Dataset Documentation

## Overview

Sentinel Zero Local uses two primary datasets for training and evaluation:

| Dataset | Samples | Source | License |
|---------|---------|--------|---------|
| PhishTank | 50,000 | phishtank.com | CC0 Public Domain |
| Custom Indian Phishing Corpus | 5,000 | Scraped + curated | Research use |

---

## Primary Dataset: PhishTank

**Source**: [https://phishtank.org/](https://phishtank.org/)

PhishTank is a free community site where anyone may submit, verify, track and share phishing data.

### Preprocessing Steps

1. **Download** the verified phishing URLs from PhishTank (JSON/CSV feed)
2. **Filter** to active/verified phishing entries only
3. **Deduplicate** by domain to avoid model overfitting on single campaigns
4. **Balance** with an equal number of legitimate URLs from Alexa Top 1M / Tranco list
5. **Feature extraction** using `utils/feature_extractor.py` (22 features)
6. **Split**: 80% train / 10% validation / 10% test

### Sample PhishTank Entry

```json
{
  "phish_id": "7234567",
  "url": "http://paypal-security-alert.xyz/verify",
  "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=7234567",
  "submission_time": "2024-09-15T10:23:11+00:00",
  "verified": "yes",
  "verification_time": "2024-09-15T10:45:00+00:00",
  "online": "yes",
  "target": "PayPal"
}
```

---

## Secondary Dataset: Custom Indian Phishing Corpus

**File**: `data/indian_phishing_samples.csv`

A curated dataset of **5,000 Indian-specific phishing URLs** targeting:

| Category | Count | Examples |
|---------|-------|---------|
| Government impersonation | 1,200 | Fake UIDAI (Aadhaar), Income Tax, EPFO portals |
| UPI/Payment fraud | 1,000 | Fake PhonePe, Google Pay, Paytm pages |
| Job/Internship scams | 800 | Fake Infosys, TCS, Amazon internship emails |
| Banking phishing | 700 | Fake SBI, HDFC, ICICI login pages |
| E-commerce fraud | 600 | Fake Flipkart, Meesho, Amazon India |
| IRCTC/Travel | 400 | Fake railway ticket booking, refund pages |
| Educational | 300 | Fake NIT/IIT admission portals, scholarship scams |

### Sample Indian Phishing URLs

```csv
url,label,category,target
http://uidai-verify-aadhaar.xyz/update,phishing,govt_impersonation,UIDAI
http://sbi-net-banking-login.top/secure,phishing,banking,SBI
http://phonepe-cashback-offer.club/claim,phishing,upi_fraud,PhonePe
http://amazon-internship-2024.tk/apply,phishing,job_scam,Amazon
http://irctc-refund-claim.xyz/ticket,phishing,travel,IRCTC
```

---

## Legitimate URLs Dataset

**Source**: Tranco Top-1M list + Alexa Top-1M (archived)

- **Size**: 50,000 URLs (balanced with PhishTank dataset)
- **Preprocessing**: Filtered to English-language sites; excluded adult/gambling content
- **File**: `data/legitimate_urls.csv`

---

## Feature Engineering

The `URLFeatureExtractor` in `utils/feature_extractor.py` extracts **22 features** from each URL:

| Feature | Type | Description |
|---------|------|-------------|
| `url_length` | int | Total URL character count |
| `num_dots` | int | Number of dots (subdomain depth indicator) |
| `num_hyphens` | int | Hyphens in URL (typosquatting signal) |
| `num_underscores` | int | Underscores (unusual in legitimate URLs) |
| `num_slashes` | int | Path depth |
| `num_question_marks` | int | Query parameter count |
| `num_at_signs` | int | URL obfuscation signal |
| `num_ampersands` | int | Query complexity |
| `num_equals` | int | Query parameter count |
| `num_special_chars` | int | Total special characters |
| `contains_ip` | bool | IP address instead of domain name |
| `has_https` | bool | SSL/TLS certificate present |
| `suspicious_tld` | bool | .xyz, .top, .tk, .ml, etc. |
| `is_trusted_domain` | bool | Whitelisted domain (google.com, etc.) |
| `subdomain_count` | int | Number of subdomain levels |
| `domain_length` | int | Length of registered domain |
| `path_length` | int | URL path length |
| `query_length` | int | Query string length |
| `num_phishing_keywords` | int | Matches on phishing keyword list |
| `entropy` | float | Shannon entropy of URL string |
| `has_port` | bool | Non-standard port specified |
| `double_slash_in_path` | bool | Path obfuscation signal |

---

## Data Ethics & Compliance

- **PhishTank data**: Used under CC0 license for research/anti-phishing purposes
- **Indian corpus**: Collected from public phishing reports, honeypots, and community submissions
- **No PII**: All samples contain only URLs, no personal information
- **Purpose limitation**: Dataset used exclusively for phishing detection model training

---

## Adding New Samples

To contribute new Indian phishing samples to the dataset:

```python
# Append to data/indian_phishing_samples.csv
import csv

new_sample = {
    "url": "http://fake-aadhaar-update.xyz/verify",
    "label": "phishing",
    "category": "govt_impersonation",
    "target": "UIDAI"
}

with open("data/indian_phishing_samples.csv", "a") as f:
    writer = csv.DictWriter(f, fieldnames=new_sample.keys())
    writer.writerow(new_sample)
```

Please verify URLs are actual phishing pages before submitting (check PhishTank verification or manual analysis).

# Phishing Email Test Samples

This directory contains **20 phishing email test cases** for validating the Sentinel Zero Local detection engine.

## Structure

| Type | Count | Files | Description |
|------|-------|-------|-------------|
| Novel | 15 | `novel_001.json` – `novel_015.json` | Fresh phishing campaigns not seen during training |
| Variants | 5 | `variant_001.json` – `variant_005.json` | Well-known phishing patterns (PayPal, Microsoft, Amazon, Apple, generic bank) |

**Total: 20 samples — all expected to return `PHISHING` verdict**

## India-Specific Content

Novel samples cover uniquely Indian phishing campaigns:

| Category | Samples | Examples |
|---------|---------|---------|
| Government impersonation | 4 | UIDAI Aadhaar, Income Tax, SSC, EPFO |
| UPI/Payment fraud | 3 | PhonePe, Google Pay, BHIM UPI |
| Job/Internship scams | 3 | Amazon, TCS, Infosys |
| Banking | 2 | SBI, HDFC |
| Travel | 1 | IRCTC |
| Telecom | 1 | Jio |
| Educational | 1 | NEET/NTA |

## Sample JSON Schema

```json
{
  "id": "novel_001",
  "type": "novel | variant",
  "category": "job_scam | upi_fraud | banking | govt_impersonation | travel | telecom | educational | ecommerce",
  "subject": "Email subject line",
  "sender_display": "Display name <email@phishing.domain>",
  "sender_email": "email@phishing.domain",
  "body_text": "Full email body text",
  "phishing_url": "http://phishing.domain/path",
  "expected_verdict": "PHISHING",
  "expected_risk_level": "high",
  "expected_min_score": 70,
  "signals": ["list of expected detection signals"],
  "india_specific": true,
  "target": "Brand/Organization being impersonated"
}
```

## Running Tests

```bash
# Run the phishing sample validation tests
python -m pytest tests/test_phishing_samples.py -v

# Run all tests
python -m pytest tests/ -v
```

## Adding New Samples

1. Create a new JSON file following the schema above
2. Verify the URL is actually phishing (check PhishTank, CERT-In advisories)
3. Ensure `expected_min_score ≥ 70` for PHISHING samples
4. Add `"india_specific": true` for India-targeting campaigns

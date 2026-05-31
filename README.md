# Email Security with IA

AI-powered email threat detection using the Anthropic Claude API. Classifies emails as safe, suspicious, or malicious and highlights specific threat indicators (phishing, spam, BEC, lookalike domains, urgency tactics).

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env           # then add your ANTHROPIC_API_KEY
```

## Usage

```bash
python -m src.main --input samples/email.eml
```

Example output:

```
Threat Level:  MALICIOUS
Confidence:    98%
Summary:       Phishing email impersonating PayPal with lookalike domain.
Indicators:
  - mismatched sender domain (paypa1.com)
  - suspicious Reply-To address
  - urgency tactics
  - lookalike URL in body
```

## Run Tests

```bash
pytest tests/
```

## Project Structure

```
Email-security-with-IA/
├── src/
│   ├── analysis/
│   │   └── email_analyzer.py   # Core threat analysis via Claude API
│   └── main.py                 # CLI entry point
├── tests/
│   └── test_email_analyzer.py
├── requirements.txt
└── .env.example
```

## Security Notes

- Never commit real email data. Use anonymized or synthetic samples only.
- Never commit `.env` — it is gitignored. Use `.env.example` for the template.
- All raw email content is validated before passing to the AI model.

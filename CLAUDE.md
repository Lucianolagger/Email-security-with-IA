# CLAUDE.md — Email-security-with-IA

## Repository Purpose

This repository is for **email security tooling and analysis powered by AI (Inteligência Artificial)**. Based on the repository name, expected scope includes:

- Email threat detection: phishing, spam, BEC (Business Email Compromise), malware attachments
- AI/ML-powered classification and triage of suspicious emails
- Integration with email platforms, threat intelligence feeds, or security APIs
- Automated alerting or reporting workflows

## Current State

The repository is **empty** — no commits or code exist yet. This CLAUDE.md is the initial scaffold for conventions when development begins.

## Expected Project Structure

```
Email-security-with-IA/
├── CLAUDE.md              # This file
├── README.md              # Project overview, architecture, and setup guide
├── src/
│   ├── models/            # AI/ML model definitions or API integrations
│   ├── analysis/          # Email parsing and threat analysis logic
│   └── integrations/      # Connectors (email providers, threat intel APIs)
├── data/                  # Anonymized/synthetic samples for testing only
├── tests/                 # Unit and integration tests
├── requirements.txt       # Python dependencies (if Python project)
└── .env.example           # Environment variable template (never commit .env)
```

## Development Workflow

Once code exists, expected commands (Python-based project):

```bash
# Setup
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run tests
pytest tests/

# Run analysis on a sample email
python src/main.py --input samples/email.eml
```

## AI/ML Integration Notes

- Prefer the **Anthropic Claude API** (`anthropic` Python SDK or `@anthropic-ai/sdk` for Node.js) for LLM-powered email analysis, classification, and explanation.
- For email parsing, use Python's built-in `email` / `mailbox` stdlib or `mailparser` (Node.js).
- Use prompt caching for repeated classification tasks against large batches of emails.

## Security Conventions

- **Never commit real email data** — use anonymized or synthetic samples only.
- **Never commit secrets** — use `.env` files (gitignored) for API keys and credentials. Provide `.env.example` with placeholder values.
- Validate all external inputs (raw email content) before passing to AI models to prevent prompt injection attacks.
- Model outputs may contain sensitive data extracted from email content — handle, log, and store with care.

## AI Assistant Notes

- The repo is **empty** — when asked to implement a feature, start with `README.md` and a minimal project scaffold before writing application code.
- Follow the owner's conventions visible in `lucianolagger/cloud-security`: flat, practical, no over-engineering.
- Do not add dependencies that aren't needed for the current task. Start minimal.
- Do not store real email samples in the repository under any circumstances.
- When integrating Claude AI, reference the current model IDs: `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`.

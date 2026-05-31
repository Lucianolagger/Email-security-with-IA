import email
import email.policy
import json
from dataclasses import dataclass, field
from enum import Enum

from anthropic import Anthropic


class ThreatLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class AnalysisResult:
    threat_level: ThreatLevel
    confidence: float
    summary: str
    indicators: list[str] = field(default_factory=list)


# Cached at the prefix level so repeated batch calls don't re-tokenize the prompt.
SYSTEM_PROMPT = """You are an email security analyst specializing in detecting phishing, spam,
BEC (Business Email Compromise), and malware attachments.

Analyze the email provided by the user and respond with a JSON object containing exactly these keys:
  threat_level  - one of: "safe", "suspicious", "malicious"
  confidence    - float 0.0–1.0
  summary       - one sentence describing the finding
  indicators    - list of specific threat signals found (empty list when safe)

Respond ONLY with valid JSON. No markdown fences, no extra text."""


class EmailAnalyzer:
    def __init__(self, api_key: str | None = None):
        self.client = Anthropic(api_key=api_key)

    def parse_email(self, raw_email: str) -> dict:
        msg = email.message_from_string(raw_email, policy=email.policy.default)
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="replace")
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="replace")

        return {
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "subject": msg.get("Subject", ""),
            "reply_to": msg.get("Reply-To", ""),
            "return_path": msg.get("Return-Path", ""),
            "body": body[:4000],  # guard against oversized payloads
        }

    def analyze(self, raw_email: str) -> AnalysisResult:
        parsed = self.parse_email(raw_email)
        email_text = (
            f"From: {parsed['from']}\n"
            f"To: {parsed['to']}\n"
            f"Subject: {parsed['subject']}\n"
            f"Reply-To: {parsed['reply_to']}\n"
            f"Return-Path: {parsed['return_path']}\n\n"
            f"Body:\n{parsed['body']}"
        )

        response = self.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": email_text}],
        )

        result = json.loads(response.content[0].text)
        return AnalysisResult(
            threat_level=ThreatLevel(result["threat_level"]),
            confidence=float(result["confidence"]),
            summary=result["summary"],
            indicators=result.get("indicators", []),
        )

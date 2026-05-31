from unittest.mock import MagicMock, patch

from src.analysis.email_analyzer import AnalysisResult, EmailAnalyzer, ThreatLevel

SAFE_EMAIL = """From: newsletter@example.com
To: user@example.com
Subject: Monthly Newsletter

Hello, here is our monthly update. No suspicious content here.
"""

PHISHING_EMAIL = """From: security@paypa1.com
To: victim@example.com
Subject: Urgent: Verify your account immediately
Reply-To: attacker@evil.com

Dear customer, your account has been suspended. Click here immediately:
http://paypa1-security.evil.com/verify?token=abc123

Your account will be deleted in 24 hours if you don't act now.
"""


def test_parse_safe_email():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    parsed = analyzer.parse_email(SAFE_EMAIL)
    assert parsed["from"] == "newsletter@example.com"
    assert parsed["subject"] == "Monthly Newsletter"
    assert "monthly update" in parsed["body"]


def test_parse_phishing_email():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    parsed = analyzer.parse_email(PHISHING_EMAIL)
    assert "paypa1" in parsed["from"]
    assert parsed["reply_to"] == "attacker@evil.com"


@patch("src.analysis.email_analyzer.Anthropic")
def test_analyze_returns_safe(mock_anthropic_cls):
    mock_response = MagicMock()
    mock_response.content[0].text = (
        '{"threat_level": "safe", "confidence": 0.95,'
        ' "summary": "Legitimate newsletter.", "indicators": []}'
    )
    mock_anthropic_cls.return_value.messages.create.return_value = mock_response

    result = EmailAnalyzer(api_key="test-key").analyze(SAFE_EMAIL)

    assert result.threat_level == ThreatLevel.SAFE
    assert result.confidence == 0.95
    assert result.indicators == []


@patch("src.analysis.email_analyzer.Anthropic")
def test_analyze_returns_malicious(mock_anthropic_cls):
    mock_response = MagicMock()
    mock_response.content[0].text = (
        '{"threat_level": "malicious", "confidence": 0.98,'
        ' "summary": "Phishing email impersonating PayPal.",'
        ' "indicators": ["lookalike domain", "suspicious Reply-To", "urgency tactics"]}'
    )
    mock_anthropic_cls.return_value.messages.create.return_value = mock_response

    result = EmailAnalyzer(api_key="test-key").analyze(PHISHING_EMAIL)

    assert result.threat_level == ThreatLevel.MALICIOUS
    assert result.confidence == 0.98
    assert len(result.indicators) == 3
    assert "lookalike domain" in result.indicators


@patch("src.analysis.email_analyzer.Anthropic")
def test_analyze_calls_claude_with_cache_control(mock_anthropic_cls):
    mock_response = MagicMock()
    mock_response.content[0].text = (
        '{"threat_level": "safe", "confidence": 0.9, "summary": "Safe.", "indicators": []}'
    )
    mock_anthropic_cls.return_value.messages.create.return_value = mock_response

    EmailAnalyzer(api_key="test-key").analyze(SAFE_EMAIL)

    call_kwargs = mock_anthropic_cls.return_value.messages.create.call_args.kwargs
    system_block = call_kwargs["system"][0]
    assert system_block["cache_control"] == {"type": "ephemeral"}

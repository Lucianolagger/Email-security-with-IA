import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.analysis.batch_analyzer import BatchAnalyzer, BatchReport
from src.analysis.email_analyzer import AnalysisResult, ThreatLevel

SAFE_EML = """From: updates@example.com\nTo: me@example.com\nSubject: Weekly digest\n\nHere is your digest."""
PHISH_EML = """From: security@paypa1.com\nTo: me@example.com\nSubject: Urgent\nReply-To: evil@attacker.com\n\nClick here now."""


def _make_response(threat: str, confidence: float, summary: str, indicators: list[str]):
    mock = MagicMock()
    import json
    mock.content[0].text = json.dumps(
        {"threat_level": threat, "confidence": confidence, "summary": summary, "indicators": indicators}
    )
    return mock


@patch("src.analysis.email_analyzer.Anthropic")
def test_analyze_directory(mock_anthropic_cls):
    responses = [
        _make_response("safe", 0.9, "Legitimate digest.", []),
        _make_response("malicious", 0.97, "Phishing attempt.", ["lookalike domain"]),
    ]
    mock_anthropic_cls.return_value.messages.create.side_effect = responses

    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.eml").write_text(SAFE_EML)
        Path(tmp, "b.eml").write_text(PHISH_EML)

        report = BatchAnalyzer(api_key="test").analyze_directory(tmp)

    assert report.total == 2
    assert report.counts[ThreatLevel.SAFE] == 1
    assert report.counts[ThreatLevel.MALICIOUS] == 1


@patch("src.analysis.email_analyzer.Anthropic")
def test_empty_directory_returns_empty_report(mock_anthropic_cls):
    with tempfile.TemporaryDirectory() as tmp:
        report = BatchAnalyzer(api_key="test").analyze_directory(tmp)
    assert report.total == 0
    mock_anthropic_cls.return_value.messages.create.assert_not_called()


def test_batch_report_flagged():
    safe = AnalysisResult(ThreatLevel.SAFE, 0.9, "ok", [])
    bad = AnalysisResult(ThreatLevel.MALICIOUS, 0.98, "phish", ["x"])
    report = BatchReport(results=[("a.eml", safe), ("b.eml", bad)])

    flagged = report.flagged()
    assert len(flagged) == 1
    assert flagged[0][0] == "b.eml"

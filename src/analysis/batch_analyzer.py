import os
from dataclasses import dataclass, field
from pathlib import Path

from .email_analyzer import AnalysisResult, EmailAnalyzer, ThreatLevel


@dataclass
class BatchReport:
    results: list[tuple[str, AnalysisResult]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def counts(self) -> dict[ThreatLevel, int]:
        tally: dict[ThreatLevel, int] = {level: 0 for level in ThreatLevel}
        for _, result in self.results:
            tally[result.threat_level] += 1
        return tally

    def flagged(self) -> list[tuple[str, AnalysisResult]]:
        return [
            (name, r)
            for name, r in self.results
            if r.threat_level != ThreatLevel.SAFE
        ]


class BatchAnalyzer:
    """Analyze every .eml file in a directory, reusing the cached system prompt."""

    def __init__(self, api_key: str | None = None):
        self.analyzer = EmailAnalyzer(api_key=api_key)

    def analyze_directory(self, directory: str | Path) -> BatchReport:
        directory = Path(directory)
        eml_files = sorted(directory.glob("*.eml"))
        if not eml_files:
            return BatchReport()

        report = BatchReport()
        for path in eml_files:
            raw = path.read_text(encoding="utf-8", errors="replace")
            result = self.analyzer.analyze(raw)
            report.results.append((path.name, result))

        return report

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from src.analysis.batch_analyzer import BatchAnalyzer
from src.analysis.email_analyzer import EmailAnalyzer, ThreatLevel

_LEVEL_COLOR = {
    ThreatLevel.SAFE: "\033[32m",       # green
    ThreatLevel.SUSPICIOUS: "\033[33m", # yellow
    ThreatLevel.MALICIOUS: "\033[31m",  # red
}
_RESET = "\033[0m"


def _color(level: ThreatLevel, text: str) -> str:
    return f"{_LEVEL_COLOR[level]}{text}{_RESET}"


def _analyze_single(path: str, api_key: str) -> None:
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    result = EmailAnalyzer(api_key=api_key).analyze(raw)
    level_str = _color(result.threat_level, result.threat_level.value.upper())
    print(f"Threat Level:  {level_str}")
    print(f"Confidence:    {result.confidence:.0%}")
    print(f"Summary:       {result.summary}")
    if result.indicators:
        print("Indicators:")
        for indicator in result.indicators:
            print(f"  - {indicator}")


def _analyze_batch(directory: str, api_key: str) -> None:
    report = BatchAnalyzer(api_key=api_key).analyze_directory(directory)
    if report.total == 0:
        print(f"No .eml files found in {directory}")
        return

    col = 36
    print(f"\n{'File':<{col}} {'Threat':<12} {'Confidence':>10}  Summary")
    print("-" * 90)
    for name, result in report.results:
        level_str = _color(result.threat_level, f"{result.threat_level.value:<12}")
        print(f"{name:<{col}} {level_str} {result.confidence:>9.0%}  {result.summary}")

    counts = report.counts
    print("-" * 90)
    print(
        f"Total: {report.total}  |  "
        f"{_color(ThreatLevel.SAFE, 'safe')}: {counts[ThreatLevel.SAFE]}  |  "
        f"{_color(ThreatLevel.SUSPICIOUS, 'suspicious')}: {counts[ThreatLevel.SUSPICIOUS]}  |  "
        f"{_color(ThreatLevel.MALICIOUS, 'malicious')}: {counts[ThreatLevel.MALICIOUS]}"
    )

    flagged = report.flagged()
    if flagged:
        print(f"\n{len(flagged)} email(s) require attention:")
        for name, result in flagged:
            print(f"  {name}: {', '.join(result.indicators) or result.summary}")


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Email security analysis powered by Claude AI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", metavar="FILE", help="Analyse a single .eml file")
    group.add_argument("--batch", metavar="DIR", help="Analyse all .eml files in a directory")
    args = parser.parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    if args.input:
        _analyze_single(args.input, api_key)
    else:
        _analyze_batch(args.batch, api_key)


if __name__ == "__main__":
    main()

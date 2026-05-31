import argparse
import os
import sys

from dotenv import load_dotenv

from src.analysis.email_analyzer import EmailAnalyzer


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Analyze an email file for security threats")
    parser.add_argument("--input", required=True, help="Path to a .eml file")
    args = parser.parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
            raw_email = fh.read()
    except FileNotFoundError:
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    analyzer = EmailAnalyzer(api_key=api_key)
    result = analyzer.analyze(raw_email)

    print(f"Threat Level:  {result.threat_level.value.upper()}")
    print(f"Confidence:    {result.confidence:.0%}")
    print(f"Summary:       {result.summary}")
    if result.indicators:
        print("Indicators:")
        for indicator in result.indicators:
            print(f"  - {indicator}")


if __name__ == "__main__":
    main()

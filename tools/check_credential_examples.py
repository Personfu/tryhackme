"""Reject provider credential material in published notes; never print values."""
from pathlib import Path
import re
import sys

RULES = {
    "aws_access_key_id": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
}


def scan(root):
    findings = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".py", ".ps1", ".json", ".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        for line, content in enumerate(text.splitlines(), 1):
            for kind, pattern in RULES.items():
                if pattern.search(content):
                    findings.append((str(path.relative_to(root)), line, kind))
    return findings


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "rooms"
    findings = scan(root)
    for path, line, kind in findings:
        print(f"{path}:{line}: {kind} must use an inert placeholder")
    print(f"Credential example check: {len(findings)} findings; values omitted")
    raise SystemExit(bool(findings))

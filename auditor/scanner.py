"""Cross-platform directory scanner for vibe-to-production security auditing."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from auditor.rules import RULES

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "__pycache__", ".venv", "venv"}
PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    file: str
    line: int
    description: str
    remediation: str


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan_directory(target: Path) -> dict:
    target = target.resolve()
    findings: list[Finding] = []
    scanned_files = 0

    for file_path in iter_candidate_files(target):
        scanned_files += 1
        rel_path = file_path.relative_to(target).as_posix()
        suffix = file_path.suffix.lower()

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        for rule in RULES:
            if suffix and suffix not in rule.extensions:
                continue
            for line_no, line in enumerate(lines, start=1):
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            file=rel_path,
                            line=line_no,
                            description=rule.description,
                            remediation=rule.remediation,
                        )
                    )

    total_penalty = sum(PENALTIES.get(item.severity, 5) for item in findings)
    score = max(0, 100 - total_penalty)

    return {
        "target": str(target),
        "scanned_files": scanned_files,
        "score": score,
        "passed": len(findings) == 0,
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }

"""Static security & production-readiness rules for AI-generated ('vibe-coded') apps."""

from dataclasses import dataclass
import re
from typing import Pattern


@dataclass(frozen=True)
class AuditRule:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    category: str
    description: str
    remediation: str
    pattern: Pattern[str]
    extensions: tuple[str, ...]


RULES: tuple[AuditRule, ...] = (
    AuditRule(
        rule_id="VIBE-001",
        severity="CRITICAL",
        category="Client Secret Exposure",
        description="Server-only secret variable prefixed with public client bundle prefix.",
        remediation="Move secret usage strictly to server actions/API routes and strip NEXT_PUBLIC_/VITE_ prefix.",
        pattern=re.compile(r"(NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE_KEY|TOKEN)"),
        extensions=(".ts", ".tsx", ".js", ".jsx", ".env", ".local"),
    ),
    AuditRule(
        rule_id="VIBE-002",
        severity="CRITICAL",
        category="Hardcoded Credentials",
        description="Likely hardcoded API key prefix detected in source code.",
        remediation="Replace literal keys with environment variable lookups and rotate exposed credentials.",
        pattern=re.compile(r"""(["'])(sk_live_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,})\1"""),
        extensions=(".py", ".ts", ".tsx", ".js", ".jsx", ".json"),
    ),
    AuditRule(
        rule_id="VIBE-003",
        severity="HIGH",
        category="Supabase RLS Bypass",
        description="SQL statement disables Row-Level Security or defines unrestricted write access.",
        remediation="Enable RLS on every tenant table and scope policies with auth.uid() membership checks.",
        pattern=re.compile(r"(DISABLE\s+ROW\s+LEVEL\s+SECURITY|FOR\s+ALL\s+USING\s*\(\s*true\s*\))", re.IGNORECASE),
        extensions=(".sql",),
    ),
    AuditRule(
        rule_id="VIBE-004",
        severity="HIGH",
        category="TLS Verification Disabled",
        description="HTTP/SSL certificate verification disabled explicitly.",
        remediation="Enable strict TLS certificate verification on every production HTTP client.",
        pattern=re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false)"),
        extensions=(".py", ".ts", ".js"),
    ),
    AuditRule(
        rule_id="VIBE-005",
        severity="MEDIUM",
        category="Dynamic Code / XSS Sink",
        description="Unsafe dynamic evaluation or raw HTML injection sink detected.",
        remediation="Eliminate eval/exec and sanitize untrusted HTML before rendering.",
        pattern=re.compile(r"(\bdangerouslySetInnerHTML\b|\bsubprocess\.[a-z]+\([^)]*shell\s*=\s*True)"),
        extensions=(".py", ".ts", ".tsx", ".js", ".jsx"),
    ),
)

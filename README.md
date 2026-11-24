# Vibe-to-Production Audit & Hardening Kit

[![CI](https://img.shields.io/badge/CI-unittest-10b981?style=flat-square)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](vibe_audit.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

> **Turn AI-generated prototypes (Lovable, Bolt.new, v0, Replit) into secure, scalable, revenue-ready production software in 5-10 days.**

Benchmarked on production Supabase & Vibe-Coding security auditing frameworks (`supashield`, `vibe-security-checker`), this toolkit pairs a zero-dependency **Python static audit CLI** (`vibe_audit.py`) with **read-only PostgreSQL RLS diagnostics** and a **35-point production readiness checklist**.

---

## Automated Security Rules Covered (`vibe_audit.py`)

| Rule ID | Severity | Check |
| :--- | :--- | :--- |
| `VIBE-001` | CRITICAL | Client-bundle exposed server secrets (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`) |
| `VIBE-002` | CRITICAL | Hardcoded live Stripe, GitHub, or cloud API keys |
| `VIBE-003` | HIGH | Disabled Supabase Row-Level Security (`DISABLE ROW LEVEL SECURITY`) or permissive `USING (true)` writes |
| `VIBE-004` | HIGH | Disabled TLS verification (`verify=False`, `rejectUnauthorized: false`) |
| `VIBE-005` | MEDIUM | Raw HTML / shell injection sinks (`dangerouslySetInnerHTML`, `shell=True`) |

---

## Quick Usage

```bash
# 1. Run cross-platform Python audit CLI (0-100 score + JSON report option)
python3 vibe_audit.py /path/to/your-vibe-app --fail-under 90
python3 vibe_audit.py /path/to/your-vibe-app --json

# 2. Run the audit toolkit self-tests
python3 -m unittest discover -s tests -v

# 3. Inspect live Supabase/PostgreSQL RLS policies (read-only)
psql "$DATABASE_URL" -f sql/rls_audit_queries.sql
```

---

## Toolkit Structure

```text
vibe-to-production-audit-kit/
├── .github/workflows/ci.yml
├── auditor/
│   ├── __init__.py
│   ├── rules.py                         # Configurable static security rule engine
│   └── scanner.py                       # Recursive scanner + weighted 0-100 risk score
├── checklists/production-readiness-checklist.md
├── scripts/scan_frontend_secrets.sh     # Lightweight bash scanner for CI hooks
├── sql/rls_audit_queries.sql            # Read-only PostgreSQL/Supabase RLS inspection
├── tests/test_audit.py                  # Unittest suite verifying rule coverage
└── vibe_audit.py                        # Main CLI entrypoint
```

---

## Need a 5-10 Day Production Rescue Sprint (`USD 3,000 - 8,000`)?
- **LinkedIn:** [Golden Nodalix Studio](https://www.linkedin.com/in/agency-golden-nodalix-880598438/)
- **Profile Hub:** [agenciaiaonline-wq](https://github.com/agenciaiaonline-wq)
- **Email:** `studio@example.com`

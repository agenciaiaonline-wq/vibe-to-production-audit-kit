#!/usr/bin/env bash
# Scan frontend/client folders for accidentally exposed server secrets
set -euo pipefail

TARGET_DIR="${1:-./src}"
echo "[*] Scanning $TARGET_DIR for common leaked secret patterns..."

PATTERN='(SERVICE_ROLE|SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|sk_live_|sk_test_|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY)'

if grep -rnE "$PATTERN" "$TARGET_DIR" --exclude-dir=node_modules --exclude-dir=.git; then
    echo "[FAIL] Potential server secret reference detected in client path!"
    exit 1
else
    echo "[PASS] No matching server secret patterns found in $TARGET_DIR."
fi

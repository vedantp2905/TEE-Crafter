#!/bin/bash
set -e

# Always install tee-crafter from the mounted /workspace so the CLI is available.
# Dependencies are pre-installed in the image so this is fast (~2s).
pip3 install --quiet --no-deps -e /workspace 2>/dev/null \
    || pip3 install --quiet --no-deps /workspace

echo "=== SGX Dev Environment Ready ==="
echo "  gramine-sgx-sign: $(which gramine-sgx-sign 2>/dev/null || echo 'NOT FOUND')"
echo "  gramine-manifest: $(which gramine-manifest 2>/dev/null || echo 'NOT FOUND')"
echo "  terraform:        $(terraform version -json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["terraform_version"])' 2>/dev/null || echo 'NOT FOUND')"
echo "  tee-crafter:      $(which tee-crafter 2>/dev/null || echo 'NOT FOUND')"
echo "  python:           $(python3 --version 2>/dev/null)"
echo ""
echo "Run:  tee-crafter deploy --tee-platform sgx-azure --source ./examples/fintech_fraud_detection --batch --input-dir ./examples/fintech_fraud_detection/input ..."
echo ""

exec "$@"

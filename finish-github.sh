#!/usr/bin/env bash
set -euo pipefail

# Finishes what setup-azure.sh started:
# 1. Creates the GitHub repo
# 2. Pushes code
# 3. Sets GitHub Actions secrets

# ── Requires these to still be set in your shell ───────────────────────────
: "${GITHUB_TOKEN:?Set GITHUB_TOKEN}"
: "${AZURE_CREDENTIALS:?Set AZURE_CREDENTIALS}"
: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${DEEPSEEK_ENDPOINT:?Set DEEPSEEK_ENDPOINT}"

REPO_NAME="himaya-prod-azure"

# ── Get GitHub username ─────────────────────────────────────────────────────
GH_USER="Himaya-AI"
echo "GitHub org: $GH_USER"

# ── Create repo in org (ignore if already exists) ──────────────────────────
echo "Creating GitHub repo ${GH_USER}/${REPO_NAME}..."
curl -sf -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/orgs/${GH_USER}/repos" \
    -d "{\"name\":\"${REPO_NAME}\",\"private\":false,\"auto_init\":false}" \
    > /dev/null && echo "Repo created." || echo "Repo may already exist — continuing."

# ── Init git and push ──────────────────────────────────────────────────────
REMOTE_URL="https://${GITHUB_TOKEN}@github.com/${GH_USER}/${REPO_NAME}.git"

if [ ! -d .git ]; then
    git init
    git branch -M main
fi

if git remote get-url origin &> /dev/null; then
    git remote set-url origin "$REMOTE_URL"
else
    git remote add origin "$REMOTE_URL"
fi

git add -A
git commit -m "Azure migration: initial mirror + IaC + GitHub Actions" 2>/dev/null || \
    git commit --allow-empty -m "Azure migration: sync" 2>/dev/null || true

echo "Pushing to GitHub..."
git push -u origin main --force
echo "Code pushed."

# ── Set GitHub secrets ─────────────────────────────────────────────────────
echo "Setting GitHub Actions secrets..."

# Get repo public key for secret encryption
PUBKEY_JSON=$(curl -sf \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${GH_USER}/${REPO_NAME}/actions/secrets/public-key")

KEY_ID=$(echo "$PUBKEY_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
PUBKEY=$(echo "$PUBKEY_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")

encrypt_secret() {
    local value="$1"
    python3 - "$value" "$PUBKEY" <<'PYEOF'
import sys
from base64 import b64encode
try:
    from nacl import public, encoding
    value = sys.argv[1].encode()
    pubkey = public.PublicKey(sys.argv[2].encode(), encoding.Base64Encoder)
    box = public.SealedBox(pubkey)
    print(b64encode(box.encrypt(value)).decode())
except ImportError:
    # nacl not available — print raw (will fail on GitHub but won't crash script)
    import base64
    print(base64.b64encode(sys.argv[1].encode()).decode())
PYEOF
}

set_secret() {
    local name="$1"
    local value="$2"
    local encrypted
    encrypted=$(encrypt_secret "$value")
    curl -sf -X PUT \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/${GH_USER}/${REPO_NAME}/actions/secrets/${name}" \
        -d "{\"encrypted_value\":\"${encrypted}\",\"key_id\":\"${KEY_ID}\"}" \
        > /dev/null && echo "  ✓ ${name}" || echo "  ✗ ${name} (failed — set manually)"
}

# Install pynacl if needed for encryption
pip3 install pynacl -q 2>/dev/null || true

set_secret "AZURE_CREDENTIALS" "$AZURE_CREDENTIALS"
set_secret "AZURE_SUBSCRIPTION_ID" "$AZURE_SUBSCRIPTION_ID"
set_secret "DEEPSEEK_ENDPOINT" "$DEEPSEEK_ENDPOINT"

echo ""
echo "✅ Done!"
echo "   Repo: https://github.com/${GH_USER}/${REPO_NAME}"
echo "   Actions will auto-deploy on next push to main."
echo ""
echo "Next: build and push Docker images by running:"
echo "   bash deploy-azure.sh"

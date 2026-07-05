#!/usr/bin/env bash
set -euo pipefail

# One-click setup script for himaya-prod-azure on Azure + GitHub.
# This script does everything it can locally; it requires your Azure
# credentials (you already ran `az login`) and a GitHub personal access token.
#
# Usage:
#   export GITHUB_TOKEN=ghp_xxx
#   export POSTGRES_ADMIN_PASSWORD=...
#   export DEEPSEEK_ENDPOINT=https://...
#   bash setup-azure.sh

# ── Configuration ───────────────────────────────────────────────────────────
LOCATION="uaenorth"
RG="rg-himaya-prod"
BASE_NAME="himaya"
ENV_NAME="prod"
ACR_NAME="himayaprodacr"
BACKEND_APP="himaya-prod-backend"
FRONTEND_APP="himaya-prod-frontend"
API_URL="https://app.himaya.ai"
REPO_NAME="himaya-prod-azure"
POSTGRES_ADMIN_USER="himayaadmin"

# ── Prompt for missing values ───────────────────────────────────────────────
prompt() {
    local var_name="$1"
    local message="$2"
    local is_secret="${3:-}"
    if [ -z "${!var_name:-}" ]; then
        if [ -n "$is_secret" ]; then
            read -rsp "$message" val
            echo
        else
            read -rp "$message" val
        fi
        eval "export $var_name=\$val"
    fi
}

prompt GITHUB_TOKEN "GitHub personal access token (repo + secrets scope): " secret
prompt AZURE_SUBSCRIPTION_ID "Azure subscription ID: "
prompt AZURE_TENANT_ID "Azure tenant ID: "
prompt POSTGRES_ADMIN_PASSWORD "PostgreSQL admin password (hidden): " secret
prompt DEEPSEEK_ENDPOINT "DeepSeek AWS endpoint (e.g. https://1.2.3.4:8001): "
prompt ANTHROPIC_API_KEY "Anthropic API key (Claude LLM classification + fallback, hidden): " secret

# ── OAuth (M365 / Google Workspace onboarding) ──────────────────────────────
# Required so onboarding/callback redirect URIs resolve to https://app.himaya.ai
# instead of the localhost defaults. Leave blank to skip a provider.
prompt M365_CLIENT_ID "Microsoft 365 OAuth client (application) ID: "
prompt M365_CLIENT_SECRET "Microsoft 365 OAuth client secret (hidden): " secret
prompt M365_TENANT_ID "Microsoft 365 tenant ID (or 'common'): "
prompt GOOGLE_CLIENT_ID "Google Workspace OAuth client ID: "
prompt GOOGLE_CLIENT_SECRET "Google Workspace OAuth client secret (hidden): " secret
prompt SAAS_M365_CLIENT_ID "SaaS Security M365 OAuth client ID (optional): "
prompt SAAS_M365_CLIENT_SECRET "SaaS Security M365 OAuth client secret (optional, hidden): " secret

# ── Validate prerequisites ──────────────────────────────────────────────────
for cmd in az git docker; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: $cmd is not installed."
        exit 1
    fi
done

if ! az account show &> /dev/null; then
    echo "ERROR: Run 'az login' first."
    exit 1
fi

if ! az account set --subscription "$AZURE_SUBSCRIPTION_ID" &> /dev/null; then
    echo "ERROR: Could not set Azure subscription $AZURE_SUBSCRIPTION_ID"
    exit 1
fi

# ── Create or reuse service principal for GitHub Actions ──────────────────
if [ -n "${AZURE_CREDENTIALS:-}" ]; then
    echo "Using existing AZURE_CREDENTIALS from environment."
    SP_JSON="$AZURE_CREDENTIALS"
    AZURE_CLIENT_ID=$(echo "$SP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['clientId'])")
else
    echo "Creating / retrieving service principal for GitHub Actions..."
    SP_JSON=$(az ad sp create-for-rbac \
        --name "sp-himaya-prod-azure" \
        --role contributor \
        --scopes "/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RG}" \
        --sdk-auth 2>/dev/null || echo "")

    if [ -z "$SP_JSON" ]; then
        echo ""
        echo "⚠️  Could not auto-create a service principal (insufficient permissions)."
        echo "   Create one manually in the Azure Portal:"
        echo "   1. Go to Azure Portal → Azure Active Directory → App registrations → New registration"
        echo "   2. Name it: sp-himaya-prod-azure"
        echo "   3. After creation: Certificates & secrets → New client secret → copy the value"
        echo "   4. Go to your subscription → Access control (IAM) → Add role assignment → Contributor → assign to the app"
        echo "   5. Build the JSON:"
        echo '      {"clientId":"<appId>","clientSecret":"<secret>","subscriptionId":"'${AZURE_SUBSCRIPTION_ID}'","tenantId":"'${AZURE_TENANT_ID}'"}'
        echo "   6. Re-run with:"
        echo "      export AZURE_CREDENTIALS='<the JSON above>'"
        echo "      bash setup-azure.sh"
        echo ""
        exit 1
    fi

    AZURE_CLIENT_ID=$(echo "$SP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['clientId'])")
fi

# ── Provision Azure resources ───────────────────────────────────────────────
echo "Provisioning Azure resources..."
az group create --name "$RG" --location "$LOCATION" --tags environment="$ENV_NAME" project="himaya"

DEPLOYMENT_NAME="himaya-prod-$(date +%Y%m%d%H%M%S)"
az deployment group create \
    --resource-group "$RG" \
    --name "$DEPLOYMENT_NAME" \
    --template-file "infra/azure/main.bicep" \
    --parameters \
        location="$LOCATION" \
        baseName="$BASE_NAME" \
        environmentName="$ENV_NAME" \
        postgresAdminUser="$POSTGRES_ADMIN_USER" \
        postgresAdminPassword="$POSTGRES_ADMIN_PASSWORD" \
        deepseekEndpoint="$DEEPSEEK_ENDPOINT" \
        anthropicApiKey="${ANTHROPIC_API_KEY:-}" \
        m365ClientId="${M365_CLIENT_ID:-}" \
        m365ClientSecret="${M365_CLIENT_SECRET:-}" \
        m365TenantId="${M365_TENANT_ID:-common}" \
        googleClientId="${GOOGLE_CLIENT_ID:-}" \
        googleClientSecret="${GOOGLE_CLIENT_SECRET:-}" \
        saasM365ClientId="${SAAS_M365_CLIENT_ID:-}" \
        saasM365ClientSecret="${SAAS_M365_CLIENT_SECRET:-}"

# ── Capture outputs ────────────────────────────────────────────────────────
echo "Capturing deployment outputs..."
OUTPUTS=$(az deployment group show --resource-group "$RG" --name "$DEPLOYMENT_NAME" --query properties.outputs -o json)

# ── Create GitHub repository ───────────────────────────────────────────────
echo "Creating GitHub repository $REPO_NAME..."
if command -v gh &> /dev/null; then
    gh auth login --with-token <<< "$GITHUB_TOKEN"
    gh repo create "$REPO_NAME" --public --confirm || true
else
    curl -sf -X POST -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        https://api.github.com/user/repos \
        -d "{\"name\":\"$REPO_NAME\",\"private\":false}" || true
fi

# ── Initialize git and push code ───────────────────────────────────────────
if [ ! -d .git ]; then
    git init
    git branch -M main
fi

REMOTE_URL="https://$GITHUB_TOKEN@github.com/Himaya-AI/$REPO_NAME.git"
if git remote get-url origin &> /dev/null; then
    git remote set-url origin "$REMOTE_URL"
else
    git remote add origin "$REMOTE_URL"
fi

git add -A
git commit -m "Azure migration: initial mirror + IaC + GitHub Actions" || true
git push -u origin main || true

# ── Set GitHub secrets ─────────────────────────────────────────────────────
echo "Setting GitHub secrets..."
if command -v gh &> /dev/null; then
    gh secret set AZURE_CREDENTIALS -b"$SP_JSON" -R "$REPO_NAME"
    gh secret set AZURE_SUBSCRIPTION_ID -b"$AZURE_SUBSCRIPTION_ID" -R "$REPO_NAME"
    gh secret set DEEPSEEK_ENDPOINT -b"$DEEPSEEK_ENDPOINT" -R "$REPO_NAME"
else
    set_secret() {
        curl -sf -X PUT \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/$REPO_NAME/actions/secrets/$1" \
            -d "{\"encrypted_value\":\"$2\",\"key_id\":\"$(curl -sf -H \"Authorization: token $GITHUB_TOKEN\" https://api.github.com/repos/$REPO_NAME/actions/secrets/public-key | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"key_id\"])')\"}" &> /dev/null || echo "Warning: could not set secret $1"
    }
    set_secret AZURE_CREDENTIALS "$SP_JSON"
    set_secret AZURE_SUBSCRIPTION_ID "$AZURE_SUBSCRIPTION_ID"
    set_secret DEEPSEEK_ENDPOINT "$DEEPSEEK_ENDPOINT"
fi

# ── Local Docker build & push (optional) ───────────────────────────────────
read -rp "Build and push Docker images now? (y/N) " build_now
if [[ "$build_now" =~ ^[Yy]$ ]]; then
    bash deploy-azure.sh
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "✅ Azure setup complete!"
echo ""
echo "Deployment outputs:"
echo "$OUTPUTS" | python3 -m json.tool

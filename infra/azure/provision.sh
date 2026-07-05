#!/usr/bin/env bash
set -euo pipefail

# Provisions Azure resources for the himaya-prod-azure deployment.
# Run this after `az login` from a machine with Owner/Contributor access.

# ── Configuration (edit these before running) ───────────────────────────────
LOCATION="uaenorth"               # UAE region
BASE_NAME="himaya"                # Resource name prefix
ENV_NAME="prod"                   # Environment suffix
RG="rg-himaya-prod"               # Resource group name
POSTGRES_ADMIN_USER="himayaadmin" # PostgreSQL admin username
POSTGRES_ADMIN_PASSWORD=""        # Set this or pass as env var
DEEPSEEK_ENDPOINT=""              # Existing AWS DeepSeek FQDN
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"   # Enables Claude LLM classification + fallback

# ── OAuth (M365 / Google Workspace onboarding) — set these or pass as env vars ─
M365_CLIENT_ID="${M365_CLIENT_ID:-}"
M365_CLIENT_SECRET="${M365_CLIENT_SECRET:-}"
M365_TENANT_ID="${M365_TENANT_ID:-common}"
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}"
GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-}"
SAAS_M365_CLIENT_ID="${SAAS_M365_CLIENT_ID:-}"
SAAS_M365_CLIENT_SECRET="${SAAS_M365_CLIENT_SECRET:-}"

# ── Derived names ──────────────────────────────────────────────────────────
PREFIX="${BASE_NAME}-${ENV_NAME}"
DEPLOYMENT_NAME="himaya-prod-$(date +%Y%m%d%H%M%S)"

# ── Validate prerequisites ───────────────────────────────────────────────
if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI (az) is not installed."
    exit 1
fi

if ! az account show &> /dev/null; then
    echo "ERROR: Not logged in. Run: az login"
    exit 1
fi

if [ -z "${POSTGRES_ADMIN_PASSWORD}" ]; then
    echo "ERROR: Set POSTGRES_ADMIN_PASSWORD to a strong password."
    exit 1
fi

# ── Create resource group ──────────────────────────────────────────────────
echo "Creating resource group ${RG} in ${LOCATION}..."
az group create \
    --name "${RG}" \
    --location "${LOCATION}" \
    --tags environment="${ENV_NAME}" project="himaya"

# ── Deploy Bicep template ─────────────────────────────────────────────────
echo "Deploying Azure resources..."
az deployment group create \
    --resource-group "${RG}" \
    --name "${DEPLOYMENT_NAME}" \
    --template-file "$(dirname "$0")/main.bicep" \
    --parameters \
        location="${LOCATION}" \
        baseName="${BASE_NAME}" \
        environmentName="${ENV_NAME}" \
        postgresAdminUser="${POSTGRES_ADMIN_USER}" \
        postgresAdminPassword="${POSTGRES_ADMIN_PASSWORD}" \
        deepseekEndpoint="${DEEPSEEK_ENDPOINT}" \
        anthropicApiKey="${ANTHROPIC_API_KEY}" \
        m365ClientId="${M365_CLIENT_ID}" \
        m365ClientSecret="${M365_CLIENT_SECRET}" \
        m365TenantId="${M365_TENANT_ID}" \
        googleClientId="${GOOGLE_CLIENT_ID}" \
        googleClientSecret="${GOOGLE_CLIENT_SECRET}" \
        saasM365ClientId="${SAAS_M365_CLIENT_ID}" \
        saasM365ClientSecret="${SAAS_M365_CLIENT_SECRET}"

# ── Output important endpoints ─────────────────────────────────────────────
echo ""
echo "✅ Azure provisioning complete!"
echo "Run the following to capture outputs:"
echo ""
echo "az deployment group show --resource-group ${RG} --name ${DEPLOYMENT_NAME} --query properties.outputs"

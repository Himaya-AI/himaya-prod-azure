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
        deepseekEndpoint="${DEEPSEEK_ENDPOINT}"

# ── Output important endpoints ─────────────────────────────────────────────
echo ""
echo "✅ Azure provisioning complete!"
echo "Run the following to capture outputs:"
echo ""
echo "az deployment group show --resource-group ${RG} --name ${DEPLOYMENT_NAME} --query properties.outputs"

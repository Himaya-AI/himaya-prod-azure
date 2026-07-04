#!/usr/bin/env bash
set -euo pipefail

# Local deploy script for Azure Container Apps.
# Run after `az login` and after provisioning resources via infra/azure/provision.sh.

# ── Configuration ──────────────────────────────────────────────────────────
LOCATION="uaenorth"
RG="rg-himaya-prod"
ACR_NAME="himayaprodacr"
BACKEND_APP="himaya-prod-backend"
FRONTEND_APP="himaya-prod-frontend"
API_URL="https://app.himaya.ai"

# ── Validate ─────────────────────────────────────────────────────────────────
if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI not installed."
    exit 1
fi

if ! az account show &> /dev/null; then
    echo "ERROR: Run az login first."
    exit 1
fi

echo "Logging into ACR ${ACR_NAME}..."
az acr login --name "${ACR_NAME}"

# ── Backend ──────────────────────────────────────────────────────────────────
echo "Building backend image..."
docker buildx build \
    --platform linux/amd64 \
    --file Dockerfile \
    --tag "${ACR_NAME}.azurecr.io/himaya-backend:latest" \
    --tag "${ACR_NAME}.azurecr.io/himaya-backend:$(git rev-parse --short HEAD || echo latest)" \
    --push \
    .

# ── Frontend ─────────────────────────────────────────────────────────────────
echo "Building frontend image..."
docker buildx build \
    --platform linux/amd64 \
    --file frontend/Dockerfile \
    --tag "${ACR_NAME}.azurecr.io/himaya-frontend:latest" \
    --tag "${ACR_NAME}.azurecr.io/himaya-frontend:$(git rev-parse --short HEAD || echo latest)" \
    --build-arg NEXT_PUBLIC_API_URL="${API_URL}" \
    --push \
    ./frontend

# ── Deploy to Container Apps ─────────────────────────────────────────────────
echo "Deploying backend..."
az containerapp update \
    --name "${BACKEND_APP}" \
    --resource-group "${RG}" \
    --image "${ACR_NAME}.azurecr.io/himaya-backend:latest"

echo "Deploying frontend..."
az containerapp update \
    --name "${FRONTEND_APP}" \
    --resource-group "${RG}" \
    --image "${ACR_NAME}.azurecr.io/himaya-frontend:latest"

echo ""
echo "✅ Azure deploy complete!"
echo "   Frontend → ${API_URL}"
echo "   API      → ${API_URL}/docs"

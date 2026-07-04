#!/bin/bash
# Usage: ./new_org.sh "Org Name" domain.com admin@email.com "Contact Name" [Launch|Enterprise]
NAME="${1:-}"; DOMAIN="${2:-}"; EMAIL="${3:-}"; CONTACT="${4:-}"; TIER="${5:-Launch}"
API_URL="${HELIOS_API_URL:-https://app.himaya.ai}"
ADMIN_KEY="${HELIOS_ADMIN_KEY:?Set HELIOS_ADMIN_KEY env var}"
if [ -z "$NAME" ] || [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
  echo "Usage: $0 \"Org Name\" domain.com admin@email.com \"Contact Name\" [Launch|Enterprise]"; exit 1
fi
curl -s -X POST "$API_URL/api/admin/setup/new-org" \
  -H "X-Admin-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{\"name\":\"$NAME\",\"domain\":\"$DOMAIN\",\"contact_email\":\"$EMAIL\",\"contact_name\":\"$CONTACT\",\"tier\":\"$TIER\",\"send_activation\":true}" \
  | python3 -m json.tool

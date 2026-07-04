#!/usr/bin/env bash
# =============================================================================
# setup_dlp_gateway.sh — Launch a t3.medium EC2 with Postfix + FastAPI milter
#                         sidecar that intercepts outbound SMTP and calls
#                         the Helios DLP classify endpoint.
#
# Architecture:
#   [Exchange/Gmail] → SMTP:25 → [DLP Gateway (Postfix + milter)] → Internet
#                                        ↕ (milter API)
#                               [dlp_gateway.py FastAPI milter]
#                                        ↕ (HTTP)
#                               [Helios Backend /api/dlp/classify]
#
# Usage:
#   export HELIOS_API="https://app.himaya.ai"
#   export HELIOS_ORG_ID="your-org-uuid"
#   export DLP_WEBHOOK_SECRET="your-secret"
#   bash setup_dlp_gateway.sh [--vpc-id vpc-xxx] [--subnet-id subnet-xxx]
# =============================================================================
set -euo pipefail

REGION="uaenorth"
INSTANCE_TYPE="t3.medium"
# Amazon Linux 2023 AMI for uaenorth (lightweight, no GPU needed)
AMI_ID="${DLP_GATEWAY_AMI_ID:-ami-0b20a6f09484773af}"  # AL2023 uaenorth (update periodically)
KEY_NAME="${EC2_KEY_NAME:-helios-dlp-key}"
HELIOS_API="${HELIOS_API:-https://app.himaya.ai}"
HELIOS_ORG_ID="${HELIOS_ORG_ID:-}"
DLP_WEBHOOK_SECRET="${DLP_WEBHOOK_SECRET:-}"
VPC_ID="${VPC_ID:-}"
SUBNET_ID="${SUBNET_ID:-}"

if [[ -z "$HELIOS_ORG_ID" ]]; then
  echo "ERROR: HELIOS_ORG_ID is required"
  exit 1
fi

# ── Security group ────────────────────────────────────────────────────────────
echo "==> Creating DLP Gateway security group..."
SG_ARGS=(--group-name "helios-dlp-gateway" --description "Helios DLP Gateway SMTP + management" --region "$REGION")
[[ -n "$VPC_ID" ]] && SG_ARGS+=(--vpc-id "$VPC_ID")

GW_SG_ID=$(aws ec2 create-security-group "${SG_ARGS[@]}" --query 'GroupId' --output text 2>/dev/null || \
  aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=helios-dlp-gateway" \
    --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text)

echo "    SG: $GW_SG_ID"

# Allow inbound SMTP (25) from anywhere (Exchange/Gmail need to reach us)
aws ec2 authorize-security-group-ingress \
  --group-id "$GW_SG_ID" --protocol tcp --port 25 --cidr "0.0.0.0/0" \
  --region "$REGION" 2>/dev/null || true

# Allow SMTP submission (587) from M365/Gmail relay IPs
aws ec2 authorize-security-group-ingress \
  --group-id "$GW_SG_ID" --protocol tcp --port 587 --cidr "0.0.0.0/0" \
  --region "$REGION" 2>/dev/null || true

# Allow SSH from admin
MY_IP=$(curl -s https://api.ipify.org)/32
aws ec2 authorize-security-group-ingress \
  --group-id "$GW_SG_ID" --protocol tcp --port 22 --cidr "$MY_IP" \
  --region "$REGION" 2>/dev/null || true

# ── User data ─────────────────────────────────────────────────────────────────
USER_DATA=$(cat <<USERDATA_EOF
#!/bin/bash
set -e
exec > /var/log/dlp-gateway-setup.log 2>&1
echo "==> DLP Gateway setup started \$(date)"

# System deps
dnf update -y
dnf install -y postfix python3 python3-pip python3-devel gcc

# Python deps for milter
pip3 install fastapi uvicorn httpx python-multipart pymilter

# Write environment
cat > /etc/dlp-gateway.env << 'ENVEOF'
HELIOS_API=${HELIOS_API}
HELIOS_ORG_ID=${HELIOS_ORG_ID}
DLP_WEBHOOK_SECRET=${DLP_WEBHOOK_SECRET}
MILTER_SOCKET=/var/run/dlp-milter/milter.sock
ENVEOF

mkdir -p /var/run/dlp-milter
chown postfix:postfix /var/run/dlp-milter

# Configure Postfix as a DLP relay
postconf -e "myhostname = dlp-gateway.helios.internal"
postconf -e "mynetworks = 0.0.0.0/0"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination"
postconf -e "smtpd_milters = unix:/var/run/dlp-milter/milter.sock"
postconf -e "non_smtpd_milters = unix:/var/run/dlp-milter/milter.sock"
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "relayhost ="
postconf -e "inet_interfaces = all"

# Copy gateway app
cp /tmp/dlp_gateway.py /opt/dlp_gateway.py

# Systemd service for milter
cat > /etc/systemd/system/dlp-milter.service << 'SVCEOF'
[Unit]
Description=Helios DLP Milter Sidecar
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/dlp-gateway.env
ExecStart=/usr/bin/python3 /opt/dlp_gateway.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable postfix dlp-milter
systemctl restart postfix
systemctl start dlp-milter

echo "==> DLP Gateway setup complete"
USERDATA_EOF
)

USER_DATA_B64=$(echo "$USER_DATA" | base64 -w0)

# ── Launch instance ───────────────────────────────────────────────────────────
echo "==> Launching t3.medium DLP Gateway instance..."

LAUNCH_ARGS=(
  --image-id "$AMI_ID"
  --instance-type "$INSTANCE_TYPE"
  --key-name "$KEY_NAME"
  --security-group-ids "$GW_SG_ID"
  --user-data "$USER_DATA_B64"
  --tag-specifications '[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"helios-dlp-gateway"},{"Key":"Project","Value":"Helios"}]}]'
  --region "$REGION"
  --output json
)
[[ -n "$SUBNET_ID" ]] && LAUNCH_ARGS+=(--subnet-id "$SUBNET_ID")

RESULT=$(aws ec2 run-instances "${LAUNCH_ARGS[@]}")
INSTANCE_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['Instances'][0]['InstanceId'])")

echo "==> Instance launched: $INSTANCE_ID"
echo "==> Waiting for public IP (may take 30s)..."
sleep 30

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

PRIVATE_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ DLP Gateway Ready"
echo "     Instance ID:  $INSTANCE_ID"
echo "     Public IP:    $PUBLIC_IP"
echo "     Private IP:   $PRIVATE_IP"
echo "     SMTP Port:    25 / 587"
echo ""
echo "  Configure in your email provider:"
echo "     M365 Outbound Connector → SmartHost: $PUBLIC_IP"
echo "     Gmail SMTP Relay → Host: $PUBLIC_IP Port: 25"
echo ""
echo "  Set in DNS (recommended):"
echo "     dlp-gateway.app.himaya.ai → $PUBLIC_IP"
echo ""
echo "  Set in M365 Transport Rule:"
echo "     DLP_GATEWAY_FQDN=$PUBLIC_IP"
echo "     .\setup_m365_transport_rule.ps1 -HeliosOrg '$HELIOS_ORG_ID'"
echo "═══════════════════════════════════════════════════════"

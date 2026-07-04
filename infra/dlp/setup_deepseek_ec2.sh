#!/usr/bin/env bash
# =============================================================================
# setup_deepseek_ec2.sh — Launch DeepSeek-R1-Distill-Qwen-7B on a g4dn.xlarge
#                          spot instance for Helios DLP inference.
# Usage: bash setup_deepseek_ec2.sh [--ecs-sg-id sg-xxxxxx]
# =============================================================================
set -euo pipefail

REGION="us-west-2"
INSTANCE_TYPE="g4dn.xlarge"
# Deep Learning AMI GPU PyTorch (Amazon Linux 2) — us-west-2
# Update this AMI ID from AWS console if needed: ami-xxxxxxxxxxxxxxxxx
AMI_ID="${DEEPSEEK_AMI_ID:-ami-0d081196e3df05f4d}"  # DL AMI GPU PyTorch AL2 (override via env)
ECS_SG_ID="${ECS_SG_ID:-}"                           # ECS security group ID (required)
KEY_NAME="${EC2_KEY_NAME:-helios-dlp-key}"           # SSH key pair name (must exist)
SPOT_PRICE="0.60"                                    # Max bid above on-demand ~$0.526/hr

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --ecs-sg-id) ECS_SG_ID="$2"; shift 2 ;;
    --ami)       AMI_ID="$2";    shift 2 ;;
    --key)       KEY_NAME="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "$ECS_SG_ID" ]]; then
  echo "ERROR: --ecs-sg-id <sg-id> is required (ECS task security group that calls port 8001)"
  exit 1
fi

echo "==> Creating DLP security group..."
DLP_SG_ID=$(aws ec2 create-security-group \
  --group-name "helios-dlp-inference" \
  --description "Helios DLP DeepSeek inference — port 8001 from ECS only" \
  --region "$REGION" \
  --query 'GroupId' --output text 2>/dev/null || \
  aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=helios-dlp-inference" \
    --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text)

echo "    SG: $DLP_SG_ID"

# Allow inbound 8001 from ECS SG only
aws ec2 authorize-security-group-ingress \
  --group-id "$DLP_SG_ID" \
  --protocol tcp --port 8001 \
  --source-group "$ECS_SG_ID" \
  --region "$REGION" 2>/dev/null || echo "    (rule already exists)"

# Allow SSH from this machine (for debugging)
MY_IP=$(curl -s https://api.ipify.org)/32
aws ec2 authorize-security-group-ingress \
  --group-id "$DLP_SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP" \
  --region "$REGION" 2>/dev/null || true

# ── User data script ──────────────────────────────────────────────────────────
# Writes dlp_inference.py to the instance and starts uvicorn on port 8001.
# The script is base64-encoded and passed as --user-data.
USER_DATA=$(cat <<'USERDATA_EOF'
#!/bin/bash
set -e
exec > /var/log/dlp-setup.log 2>&1

echo "==> DLP inference setup started $(date)"

# Update pip + install deps
/usr/bin/pip3 install --upgrade pip
pip3 install vllm fastapi uvicorn httpx python-multipart

# Create DLP inference app directory
mkdir -p /home/ec2-user/dlp
chown ec2-user:ec2-user /home/ec2-user/dlp

# Write the inference server (dlp_inference.py)
cat > /home/ec2-user/dlp/dlp_inference.py << 'PYEOF'
"""
Helios DLP — DeepSeek-R1-Distill-Qwen-7B Inference Server
Port: 8001
"""
import re, os, json, logging
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Helios DLP Inference", version="1.0.0")
MODEL_ID = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
_llm = None  # Lazy-loaded on first request

# ── Regex fallback patterns ───────────────────────────────────────────────────
PATTERNS = {
    "ssn":          (r'\b\d{3}-\d{2}-\d{4}\b', "critical"),
    "credit_card":  (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', "critical"),
    "iban":         (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b', "high"),
    "passport":     (r'\b[A-Z]{1,2}\d{6,9}\b', "medium"),
    "swift":        (r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b', "high"),
    "routing_num":  (r'\b(?:0[0-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b', "high"),
    "api_key":      (r'(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})', "critical"),
    "private_key":  (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "critical"),
    "aws_key":      (r'AKIA[0-9A-Z]{16}', "critical"),
    "password_field": (r'(?i)password\s*[:=]\s*\S+', "high"),
    "itar_terms":   (r'(?i)\b(?:ITAR|EAR|ECCN|munitions|export.?controlled|defense.?article|technical.?data.?subject)\b', "high"),
    "bulk_recipient": (r'(?i)(?:bcc|to):\s*(?:[^,\n]+,\s*){19,}', "high"),  # 20+ recipients
}

def regex_classify(text: str) -> dict:
    categories, matched = [], []
    max_sev = "low"
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for name, (pattern, severity) in PATTERNS.items():
        if re.search(pattern, text):
            categories.append(name)
            matched.append(name)
            if sev_order[severity] > sev_order[max_sev]:
                max_sev = severity
    action_map = {"low": "ALLOW", "medium": "WARN", "high": "HOLD", "critical": "BLOCK"}
    return {
        "risk_level": max_sev,
        "action": action_map[max_sev],
        "categories": categories,
        "confidence": 0.75 if categories else 0.5,
        "matched_patterns": matched,
        "explanation": f"Regex scan detected: {', '.join(matched)}" if matched else "No sensitive patterns detected",
        "method": "regex",
    }

def get_llm():
    global _llm
    if _llm is None:
        try:
            from vllm import LLM, SamplingParams
            _llm = LLM(model=MODEL_ID, max_model_len=4096, gpu_memory_utilization=0.85)
            logger.info("DeepSeek model loaded")
        except Exception as e:
            logger.warning(f"vLLM load failed: {e}")
            _llm = "fallback"
    return _llm

class ClassifyRequest(BaseModel):
    email_body: str
    subject: str = ""
    attachments: list[str] = []
    recipient_domains: list[str] = []
    org_id: str = ""

DLP_PROMPT = """You are a Data Loss Prevention (DLP) classifier for enterprise email security.

Analyze the following email and detect if it contains sensitive information that should be blocked, held for review, or warned about.

Detect these categories:
- PII: SSN, passport numbers, national ID numbers, IBAN, credit card numbers, date of birth
- Financial: bank account numbers, SWIFT/BIC codes, routing numbers, wire transfer details
- Credentials: passwords, API keys, private keys, tokens, secrets
- ITAR/Export-controlled: ITAR, EAR, ECCN, munitions, defense articles, technical data subject to export control
- Bulk exfiltration: emails sent to 20+ external recipients, large data dumps

Email Subject: {subject}
Recipient Domains: {recipient_domains}
Email Body:
{body}

{attachments_section}

Respond ONLY with valid JSON (no other text):
{{
  "risk_level": "low|medium|high|critical",
  "action": "ALLOW|WARN|HOLD|BLOCK",
  "categories": ["list", "of", "detected", "categories"],
  "confidence": 0.0,
  "matched_patterns": ["specific patterns found"],
  "explanation": "brief explanation of findings"
}}

Rules:
- ALLOW: no sensitive content detected (confidence > 0.8)
- WARN: possibly sensitive, low confidence
- HOLD: likely contains sensitive data — needs human review
- BLOCK: clearly contains critical PII, credentials, or ITAR data
"""

@app.post("/classify")
async def classify(req: ClassifyRequest):
    body_text = f"Subject: {req.subject}\n\n{req.email_body}"
    if req.attachments:
        body_text += "\n\nAttachments: " + ", ".join(req.attachments)

    # Always run regex first (fast, deterministic)
    regex_result = regex_classify(body_text)

    # If regex found critical/high, return immediately (no need for LLM)
    if regex_result["risk_level"] in ("critical",) or (
        regex_result["risk_level"] == "high" and regex_result["confidence"] >= 0.9
    ):
        return regex_result

    # Try LLM for nuanced classification
    llm = get_llm()
    if llm == "fallback" or llm is None:
        return regex_result

    try:
        from vllm import SamplingParams
        prompt = DLP_PROMPT.format(
            subject=req.subject,
            recipient_domains=", ".join(req.recipient_domains) or "unknown",
            body=req.email_body[:3000],
            attachments_section=f"Attachment names: {', '.join(req.attachments)}" if req.attachments else "",
        )
        sampling = SamplingParams(temperature=0.1, max_tokens=512, stop=["```"])
        outputs = llm.generate([prompt], sampling)
        raw = outputs[0].outputs[0].text.strip()

        # Extract JSON from output
        import re as _re
        match = _re.search(r'\{.*\}', raw, _re.DOTALL)
        if match:
            result = json.loads(match.group())
            result["method"] = "deepseek"
            # Merge regex findings
            all_cats = list(set(result.get("categories", []) + regex_result["categories"]))
            all_patterns = list(set(result.get("matched_patterns", []) + regex_result["matched_patterns"]))
            result["categories"] = all_cats
            result["matched_patterns"] = all_patterns
            # Take the more severe action
            sev_order = {"ALLOW": 0, "WARN": 1, "HOLD": 2, "BLOCK": 3}
            if sev_order.get(regex_result["action"], 0) > sev_order.get(result.get("action", "ALLOW"), 0):
                result["action"] = regex_result["action"]
                result["risk_level"] = regex_result["risk_level"]
            return result
    except torch.cuda.OutOfMemoryError:
        logger.error("GPU OOM — falling back to regex")
        return regex_result
    except Exception as e:
        logger.error(f"LLM classification failed: {e}")
        return regex_result

    return regex_result

@app.get("/health")
async def health():
    llm_status = "not_loaded"
    try:
        llm = get_llm()
        llm_status = "fallback" if llm == "fallback" else "loaded"
    except Exception:
        pass
    return {"status": "ok", "model": MODEL_ID, "llm": llm_status}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
PYEOF

chown ec2-user:ec2-user /home/ec2-user/dlp/dlp_inference.py

# Pre-download the model (async, may take 10-20 min on first boot)
echo "==> Downloading DeepSeek-R1-Distill-Qwen-7B model..."
sudo -u ec2-user bash -c '
  pip3 install huggingface_hub
  python3 -c "from huggingface_hub import snapshot_download; snapshot_download(\"deepseek-ai/DeepSeek-R1-Distill-Qwen-7B\")"
' &

# Create systemd service for auto-restart
cat > /etc/systemd/system/dlp-inference.service << 'SVCEOF'
[Unit]
Description=Helios DLP Inference Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/dlp
ExecStart=/usr/bin/python3 /home/ec2-user/dlp/dlp_inference.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable dlp-inference
systemctl start dlp-inference

echo "==> DLP inference server started on port 8001"
echo "==> Model download running in background — server starts with regex-only until complete"
USERDATA_EOF
)

USER_DATA_B64=$(echo "$USER_DATA" | base64 -w0)

echo "==> Launching g4dn.xlarge spot instance..."
LAUNCH_RESULT=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$DLP_SG_ID" \
  --instance-market-options '{"MarketType":"spot","SpotOptions":{"MaxPrice":"'"$SPOT_PRICE"'","SpotInstanceType":"one-time"}}' \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
  --user-data "$USER_DATA_B64" \
  --tag-specifications '[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"helios-dlp-inference"},{"Key":"Project","Value":"Helios"},{"Key":"ManagedBy","Value":"Himaya"}]}]' \
  --region "$REGION" \
  --output json)

INSTANCE_ID=$(echo "$LAUNCH_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['Instances'][0]['InstanceId'])")
echo "==> Instance launched: $INSTANCE_ID"
echo "==> Waiting for instance to get a private IP..."

sleep 15
PRIVATE_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ DLP Inference Instance Ready"
echo "     Instance ID:  $INSTANCE_ID"
echo "     Private IP:   $PRIVATE_IP"
echo "     Endpoint:     http://$PRIVATE_IP:8001"
echo "     Security SG:  $DLP_SG_ID"
echo ""
echo "  Set in ECS task env:"
echo "     DEEPSEEK_ENDPOINT=http://$PRIVATE_IP:8001"
echo ""
echo "  Note: Model download takes ~15-20 min on first boot."
echo "        Server runs regex-only until GPU model is ready."
echo "═══════════════════════════════════════════════════════"

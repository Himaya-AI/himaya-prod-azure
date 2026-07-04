# Gmail DLP Routing Setup

Configure Google Workspace Admin Console to route all outbound email through the Helios DLP webhook for classification.

## Method 1: Content Compliance Rule (Recommended — no gateway needed)

This method uses Gmail's built-in content compliance routing to POST a copy of outbound messages to Helios DLP. Note: Gmail's content compliance does not natively block messages based on webhook response. For full BLOCK capability, use Method 2 (SMTP relay via DLP Gateway).

### Steps

1. **Go to Google Admin Console**
   - URL: [https://admin.google.com](https://admin.google.com)
   - Sign in as a Workspace Super Admin

2. **Navigate to Apps → Google Workspace → Gmail → Compliance**

3. **Add a Content Compliance Rule**
   - Click **CONFIGURE** under "Content compliance"
   - Name: `Helios DLP — Outbound Inspection`
   - **Email messages to affect:** Select **Outbound**
   - **Add expressions:** Leave blank (matches all messages) or add expression for "message body" to scan all content

4. **Under "If the above expressions match, do the following":**
   - Select: **Also deliver to** → **Add more recipients**
   - Click **Add** → Select **Webhook** (if available in your Google Workspace tier)
   - OR use: **Advanced options** → **Route** → Configure a SMTP relay

   > **Note:** Google Workspace **Enterprise Plus** or **Education Plus** tiers support webhook delivery via content compliance. Lower tiers require SMTP relay method.

5. **Configure Webhook Delivery:**
   - URL: `https://app.himaya.ai/api/dlp/webhook/google`
   - Add custom header: `X-DLP-Secret: <your-DLP_WEBHOOK_SECRET-value>`
   - Body format: Include full message content

6. **Save** and click **Enable**

---

## Method 2: SMTP Relay via DLP Gateway (Full BLOCK capability)

This routes all outbound SMTP through the Helios DLP milter gateway, which can actively block/hold messages.

### Prerequisites
- Deploy the DLP Gateway EC2 (see `setup_dlp_gateway.sh`)
- Note the gateway's public IP or FQDN

### Steps

1. **Google Admin Console → Apps → Google Workspace → Gmail → Hosts**
2. **Add SMTP relay host:**
   - Name: `Helios DLP Gateway`
   - Hostname: `<DLP_GATEWAY_FQDN_OR_IP>`
   - Port: `25` or `587`
   - Authentication: **No authentication** (restrict by IP instead)
   - Encryption: **Require TLS**

3. **Apps → Google Workspace → Gmail → Routing**
4. **Outbound gateway:**
   - Add a routing rule for all outbound messages
   - Route to: `Helios DLP Gateway` (defined above)
   - This sends all outbound mail through the Postfix milter which calls `/api/dlp/classify`

5. **Security Groups (GCP/AWS):**
   - Allow inbound TCP:25 from Google's SMTP relay IPs to the DLP Gateway
   - Google SMTP IPs: [https://support.google.com/a/answer/60764](https://support.google.com/a/answer/60764)

---

## Verifying the Setup

### Test with a safe email
Send an outbound email and check Helios DLP events:
```
GET https://app.himaya.ai/api/dlp/events
Authorization: Bearer <your-token>
```

### Test with PII (sandbox only!)
Use test SSN `123-45-6789` in email body — should create a `HOLD` or `BLOCK` event.

### Check webhook logs (ECS)
```bash
aws logs tail /ecs/himaya-backend --since 10m | grep dlp
```

---

## Environment Variables Required (Backend ECS Task)

| Variable | Description |
|---|---|
| `DLP_WEBHOOK_SECRET` | Shared secret in `X-DLP-Secret` header |
| `DEEPSEEK_ENDPOINT` | `http://<private-ip>:8001` (optional, enables LLM) |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Webhook returns 401 | Check `X-DLP-Secret` header matches `DLP_WEBHOOK_SECRET` |
| All emails ALLOW even with SSN | Verify `DEEPSEEK_ENDPOINT` is set (or check regex in `dlp_service.py`) |
| Google Admin missing Webhook option | Upgrade to Enterprise Plus or use SMTP relay |
| DLP Gateway connection refused | Check EC2 security group allows Google SMTP IPs on port 25 |

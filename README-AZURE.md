# Himaya Helios — Azure Deployment Guide

This is the Azure-native mirror of the Himaya Helios (`sentinel-mail`) repository. It targets **Azure Container Apps**, **Azure Database for PostgreSQL Flexible Server**, **Azure Cache for Redis**, **Azure Blob Storage**, **Azure Service Bus**, and **Azure Front Door** in the **UAE North (`uaenorth`)** region.

The self-hosted **DeepSeek GPU inference server remains on AWS** and is accessed via its FQDN from the Azure backend.

---

## Quick start (one script)

If you have `az` and `git` installed and a GitHub token, run:

```bash
export GITHUB_TOKEN=ghp_xxx
export POSTGRES_ADMIN_PASSWORD="<strong-password>"
export DEEPSEEK_ENDPOINT="https://your-deepseek-aws-fqdn:8001"
bash setup-azure.sh
```

This script will:
1. Create the `himaya-prod-azure` GitHub repo
2. Push the mirrored code
3. Create an Azure service principal and set GitHub secrets
4. Provision all Azure resources via Bicep
5. Optionally build and deploy Docker images

---

## 1. Repository layout

```
himaya-prod-azure/
├── .github/workflows/deploy-azure.yml   # GitHub Actions → Azure auto-deploy
├── infra/azure/
│   ├── main.bicep                       # Azure resource definitions
│   └── provision.sh                     # One-time resource provisioning
├── deploy-azure.sh                      # Local deploy script
├── backend/services/
│   ├── storage_client.py                # Azure Blob / S3 abstraction
│   └── queue_client.py                  # Azure Service Bus / SQS abstraction
├── backend/services/email_service.py    # Azure Communication Email + SES fallback
└── backend/config.py                    # Azure-aware settings
```

---

## 2. Prerequisites

- Azure CLI installed and logged in: `az login`
- Docker with `buildx` support
- GitHub repo created with name: `himaya-prod-azure`
- GitHub secrets configured (see section 5)

---

## 3. Provision Azure resources

Edit `infra/azure/provision.sh` and set:

```bash
POSTGRES_ADMIN_PASSWORD="<strong-password>"
DEEPSEEK_ENDPOINT="https://your-deepseek-aws-fqdn:8001"
```

Then run:

```bash
bash infra/azure/provision.sh
```

This creates:
- Resource group `rg-himaya-prod` in `uaenorth`
- Azure Container Registry `himayaprodacr`
- Azure Container Apps environment `himaya-prod-env`
- Container Apps `himaya-prod-backend` and `himaya-prod-frontend`
- PostgreSQL Flexible Server `himaya-prod-db`
- Azure Cache for Redis `himaya-prod-redis`
- Storage Account `himayaprodsa` with Blob containers
- Service Bus `himaya-prod-bus` with queues
- Azure Front Door `himaya-prod-fd`
- Managed Identity with ACR pull, Blob, and Service Bus roles

---

## 4. Database setup

After provisioning, restore the schema:

```bash
export PGPASSWORD="<your-password>"
psql -h himaya-prod-db.postgres.database.azure.com -U himayaadmin -d postgres -f backend/db/init.sql
```

For migration from AWS RDS:

```bash
pg_dump -h sentinel-mail-db.cr86m0gaa8qb.us-west-2.rds.amazonaws.com -U sentinel sentinel_mail > himaya_backup.sql
psql -h himaya-prod-db.postgres.database.azure.com -U himayaadmin -d himaya < himaya_backup.sql
```

---

## 5. GitHub Actions secrets

In the `himaya-prod-azure` repo, add these secrets:

| Secret | Value |
|---|---|
| `AZURE_CREDENTIALS` | Full JSON from `az ad sp create-for-rbac` |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `DEEPSEEK_ENDPOINT` | `https://your-deepseek-aws-fqdn:8001` |
| `DOCKER_BUILDKIT` | `1` |

The `setup-azure.sh` script creates the service principal and sets these secrets automatically.

---

## 6. First deploy

### From your local machine:

```bash
bash deploy-azure.sh
```

### From GitHub Actions:

Push to the `main` branch. The workflow will:
1. Build frontend/backend for `linux/amd64`
2. Push to ACR
3. Update Container Apps
4. Run a health check against `https://app.himaya.ai/health`

---

## 7. DNS

Point `app.himaya.ai` (or your chosen domain) to the Azure Front Door endpoint shown in the provisioning output.

You can also keep `helios.himaya.ai` and CNAME it to the same Front Door endpoint for a zero-downtime cutover.

---

## 8. What changed from the AWS repo

### Added
- Azure Container Apps deployment
- Azure Blob Storage abstraction (`backend/services/storage_client.py`)
- Azure Service Bus abstraction (`backend/services/queue_client.py`)
- Azure Communication Email support with SES fallback
- Azure Bicep infrastructure templates

### Modified
- `backend/config.py` — added Azure settings
- `backend/services/url_detonation.py` — uses Blob Storage for screenshots
- `backend/services/report_generator.py` — uses Blob Storage for PDFs
- `backend/services/google_workspace_service.py` — uses Service Bus for email queue
- `backend/services/email_service.py` — Azure Communication Email + SES fallback
- `sandbox/entrypoint.sh` — fetches email HTML from Azure Blob first
- `frontend/next.config.ts` — points to `https://app.himaya.ai`
- `.env.example` — Azure-first env vars

### Unchanged
- `backend/services/aws_security_service.py` — still scans customer AWS accounts
- `backend/services/cspm/collectors/aws.py` — CSPM AWS collector
- DeepSeek inference endpoint — remains on AWS, called via FQDN

---

## 9. Validation checklist

- [ ] `https://app.himaya.ai/health` returns 200
- [ ] Frontend loads and API calls succeed
- [ ] Login and MFA work
- [ ] Gmail / M365 onboarding works
- [ ] Inbound email threat detection works
- [ ] DLP draft scan returns verdicts
- [ ] URL detonation captures screenshots in Blob Storage
- [ ] Compliance PDF reports generate and download
- [ ] Email notifications are delivered (Azure or SES)
- [ ] DeepSeek DLP classification works via the AWS FQDN

---

## 10. Troubleshooting

### Container Apps fails to pull image
- Verify the managed identity has `AcrPull` role on ACR.
- Ensure the Container App registry configuration uses `identity` not password.

### Database connection fails
- Confirm `DATABASE_URL` includes `sslmode=require`.
- Verify PostgreSQL firewall allows Azure services.

### Redis connection fails
- Use port `6380` and SSL.
- Format: `host:6380,password=...,ssl=True,abortConnect=False`.

### Service Bus messages not received
- Confirm the managed identity has `Azure Service Bus Data Owner` role.
- Check queue names match `AZURE_SERVICE_BUS_NAMESPACE`.

### DeepSeek unreachable
- Ensure the Azure backend VNet / NSG can reach the AWS DeepSeek EC2 on port 8001.
- Verify `DEEPSEEK_ENDPOINT` is set correctly.

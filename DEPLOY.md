# Sentinel Mail — Deploy Pipeline & AWS Infrastructure

> Run locally, deploy globally. Full reference for the CI/CD pipeline, AWS endpoints, and CloudFront setup.

---

## 🗺️ Architecture at a Glance

```
GitHub Repo (AdnanAhmed-repo)
        │
        │  git push → manual deploy script (for now)
        ▼
   Raspberry Pi (build host)
        │
        │  docker buildx (linux/arm64)
        ▼
   Amazon ECR
   ├── himaya-frontend:latest
   └── himaya-backend:latest
        │
        ▼
   Amazon ECS (Fargate) — Cluster: himaya
   ├── Service: himaya-frontend  → Task Def :4  → port 3000
   └── Service: himaya-backend   → Task Def :17 → port 8000
        │
        ▼
   Application Load Balancer
   app.himaya.ai
   ├── HTTPS :443
   │   ├── /api/*          → backend target group
   │   ├── /health, /docs  → backend target group
   │   └── (default)       → frontend target group
   └── HTTP :80            → redirect to HTTPS
        │
        ▼
   CloudFront CDN
   https://app.himaya.ai
   Origin: ALB (HTTP, port 80→443)
```

---

## 🔑 AWS Endpoints

| Resource | Value |
|---|---|
| **Region** | `uaenorth` |
| **Account ID** | `__AZURE_ACCT__` |
| **CloudFront URL** | `https://app.himaya.ai` |
| **ALB (API + Frontend)** | `http://app.himaya.ai` |
| **Frontend ECR** | `__AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com/himaya-frontend` |
| **Backend ECR** | `__AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com/himaya-backend` |
| **ECS Cluster** | `himaya` |
| **RDS (Postgres 15)** | `himaya-db.cr86m0gaa8qb.uaenorth.rds.amazonaws.com:5432` |
| **Redis (ElastiCache)** | `himaya-redis.yuvxb0.0001.usw2.cache.amazonaws.com:6379` |

### S3 Buckets

| Bucket | Purpose |
|---|---|
| `himaya-frontend-prod` | Static assets (if needed) |
| `himaya-models-prod` | ML model artifacts |
| `himaya-evidence` | Sandbox evidence |
| `himaya-reports` | Generated PDF reports |

### SQS Queues

| Queue | Purpose |
|---|---|
| `himaya-email-events` | Inbound email event stream |
| `himaya-email-events-dlq` | Dead-letter queue |
| `himaya-alerts` | Alert dispatch |
| `himaya-compliance` | Compliance assessment jobs |

---

## 🚀 Deploy Commands

### Prerequisites

```bash
# AWS CLI configured with your credentials
aws configure   # region: uaenorth

# Docker with buildx (multi-platform)
docker buildx ls   # should show a builder

# ECR login (valid for 12h)
aws ecr get-login-password --region uaenorth \
  | docker login --username AWS --password-stdin \
    __AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com
```

---

### Deploy Frontend

```bash
cd frontend/

# 1. Build for linux/arm64 (ECS Fargate ARM64 / Graviton) and push to ECR
docker buildx build \
  --builder cross-builder --platform linux/arm64 \
  --build-arg NEXT_PUBLIC_API_URL=http://app.himaya.ai \
  -t __AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com/himaya-frontend:latest \
  --push \
  .

# 2. Force new ECS deployment (picks up new :latest image)
aws ecs update-service \
  --cluster himaya \
  --service himaya-frontend \
  --force-new-deployment \
  --region uaenorth

# 3. Invalidate CloudFront cache (so browsers get new files immediately)
aws cloudfront create-invalidation \
  --distribution-id __AZURE_FD_PROFILE__ \
  --paths "/*"

# 4. Wait for deployment to stabilize (optional)
aws ecs wait services-stable \
  --cluster himaya \
  --services himaya-frontend \
  --region uaenorth

echo "✅ Frontend deployed"
```

---

### Deploy Backend

```bash
cd himaya/   # repo root

# 1. Build backend
docker buildx build \
  --builder cross-builder --platform linux/arm64 \
  -t __AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com/himaya-backend:latest \
  --push \
  .

# 2. Force new ECS deployment
aws ecs update-service \
  --cluster himaya \
  --service himaya-backend \
  --force-new-deployment \
  --region uaenorth

aws ecs wait services-stable \
  --cluster himaya \
  --services himaya-backend \
  --region uaenorth

echo "✅ Backend deployed"
```

---

### One-Shot Full Deploy Script

Save as `deploy.sh` in the repo root and `chmod +x deploy.sh`:

```bash
#!/bin/bash
set -e

REGION=uaenorth
ACCOUNT=__AZURE_ACCT__
ECR=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com
CLUSTER=himaya
CF_DIST=__AZURE_FD_PROFILE__
API_URL=http://app.himaya.ai

echo "🔐 ECR login..."
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ECR

TARGET=${1:-both}   # Usage: ./deploy.sh [frontend|backend|both]

if [ "$TARGET" = "frontend" ] || [ "$TARGET" = "both" ]; then
  echo "🏗️  Building frontend..."
  docker buildx build \
    --builder cross-builder --platform linux/arm64 \
    --build-arg NEXT_PUBLIC_API_URL=$API_URL \
    -t $ECR/himaya-frontend:latest \
    --push \
    ./frontend

  echo "🚀 Deploying frontend to ECS..."
  aws ecs update-service \
    --cluster $CLUSTER \
    --service himaya-frontend \
    --force-new-deployment \
    --region $REGION > /dev/null

  echo "🌐 Invalidating CloudFront cache..."
  aws cloudfront create-invalidation \
    --distribution-id $CF_DIST \
    --paths "/*" > /dev/null
fi

if [ "$TARGET" = "backend" ] || [ "$TARGET" = "both" ]; then
  echo "🏗️  Building backend..."
  docker buildx build \
    --builder cross-builder --platform linux/arm64 \
    -t $ECR/himaya-backend:latest \
    --push \
    .

  echo "🚀 Deploying backend to ECS..."
  aws ecs update-service \
    --cluster $CLUSTER \
    --service himaya-backend \
    --force-new-deployment \
    --region $REGION > /dev/null
fi

echo "⏳ Waiting for ECS to stabilize..."
aws ecs wait services-stable \
  --cluster $CLUSTER \
  --services himaya-frontend himaya-backend \
  --region $REGION

echo "✅ Deploy complete → https://app.himaya.ai"
```

---

## 💻 Run Locally

### Option 1 — Docker Compose (full stack, recommended)

```bash
git clone https://github.com/AdnanAhmed-repo/himaya.git
cd himaya

# Copy env template
cp backend/.env.example backend/.env
# Edit backend/.env with your keys (see Environment Variables below)

# Start Postgres + Redis + Neo4j
docker-compose up -d

# Run backend (in its own terminal)
pip install -r requirements.txt
cd backend && uvicorn main:app --reload --port 8000

# Run frontend (in another terminal)
cd frontend
npm install --legacy-peer-deps
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
# → opens http://localhost:3000
```

### Option 2 — Frontend only (point at prod API)

```bash
cd frontend
npm install --legacy-peer-deps
NEXT_PUBLIC_API_URL=http://app.himaya.ai npm run dev
```

### Option 3 — Docker build locally

```bash
# Frontend
docker build \
  --build-arg NEXT_PUBLIC_API_URL=http://localhost:8000 \
  -t sentinel-frontend \
  ./frontend
docker run -p 3000:3000 sentinel-frontend

# Backend
docker build -t sentinel-backend .
docker run -p 8000:8000 \
  --env-file backend/.env \
  sentinel-backend
```

---

## 🔧 Environment Variables

### Backend (`.env` or ECS task secrets)

```env
# Database
DATABASE_URL=postgresql+asyncpg://sentinel:<password>@localhost:5432/sentinel_mail

# Redis
REDIS_URL=redis://localhost:6379

# Auth
SECRET_KEY=<generate with: openssl rand -hex 32>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Microsoft 365
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_TENANT_ID=

# Google Workspace
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# AI/ML
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# AWS (for SQS, S3, SageMaker)
AWS_DEFAULT_REGION=uaenorth
# Use IAM role in production (ECS task role), env vars locally
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Email
SENDGRID_API_KEY=

# Frontend URL (for CORS + invite links)
FRONTEND_URL=https://app.himaya.ai
```

### Frontend

```env
NEXT_PUBLIC_API_URL=http://app.himaya.ai
# For local dev:
# NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 📊 Check Deploy Status

```bash
# ECS service health
aws ecs describe-services \
  --cluster himaya \
  --services himaya-frontend himaya-backend \
  --region uaenorth \
  --query 'services[*].{name:serviceName,running:runningCount,desired:desiredCount,rollout:deployments[0].rolloutState}'

# ALB target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:uaenorth:__AZURE_ACCT__:targetgroup/sentinel-frontend-tg/e0ac4434e23547a8 \
  --region uaenorth

# Recent ECS task logs (frontend)
aws logs tail /ecs/himaya-frontend --since 30m --follow --region uaenorth

# Recent ECS task logs (backend)
aws logs tail /ecs/himaya-backend --since 30m --follow --region uaenorth
```

---

## 🌐 CloudFront Distribution

| Setting | Value |
|---|---|
| Distribution ID | `__AZURE_FD_PROFILE__` |
| Domain | `https://app.himaya.ai` |
| Origin | `app.himaya.ai` |
| Status | `Deployed` |

**Force cache bust after deploy:**
```bash
aws cloudfront create-invalidation \
  --distribution-id __AZURE_FD_PROFILE__ \
  --paths "/*"
```

---

## 🏗️ Infrastructure (VPC / Networking)

| Resource | ID |
|---|---|
| VPC | `vpc-0679d4e8fe13575a5` |
| Public Subnets | `subnet-083b821328a41fef9`, `subnet-0885e4bb6dff4a03a` |
| Private Subnets | `subnet-021389faf2633153b`, `subnet-0599d2a7ee409a0f3` |
| App SG | `sg-07e91ce759c0a9cf6` |
| RDS SG | `sg-00a8d62b9020b5c4c` |
| Redis SG | `sg-0a03010059508ea88` |

---

## 🐳 Sandbox (URL Detonation)

| Resource | Value |
|---|---|
| Sandbox VPC | `vpc-02002811377182171` |
| AMI | `ami-03caad32a158f72db` |
| Instance Profile | `helios-sandbox-profile` |
| Jobs Queue | `himaya-sandbox-jobs` |
| Results Queue | `himaya-sandbox-results` |
| Key Pair | `himaya-sandbox-key` |

---

## 🔁 Deploy Flow Summary

```
1. Edit code locally
2. git add . && git commit -m "feat: ..."
3. git push origin master
4. ./deploy.sh frontend    ← rebuilds, pushes ECR, forces ECS redeploy, busts CF cache
5. aws ecs wait services-stable ...
6. Visit https://app.himaya.ai
```

> ⚠️  **Always** run `./deploy.sh` after committing — ECS pulls `:latest` only on new deployments. Committed code without a deploy = nothing changes in prod.

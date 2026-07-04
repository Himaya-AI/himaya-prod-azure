#!/bin/bash
# Sentinel Mail — Deploy Script
# Usage: ./deploy.sh [frontend|backend|both]
# Default: both
set -e

REGION=uaenorth
ACCOUNT=__AZURE_ACCT__
ECR=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com
CLUSTER=himaya
CF_DIST=__AZURE_FD_PROFILE__
API_URL=https://app.himaya.ai   # Must be HTTPS — browser blocks HTTP calls from HTTPS pages (mixed content)

TARGET=${1:-both}

echo "🔐 ECR login..."
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ECR

if [ "$TARGET" = "frontend" ] || [ "$TARGET" = "both" ]; then
  echo ""
  echo "🏗️  Building frontend (linux/arm64)..."
  docker buildx build \
    --builder cross-builder \
    --platform linux/arm64 \
    --build-arg NEXT_PUBLIC_API_URL=$API_URL \
    --build-arg BUILD_TS=$(date +%s) \
    -t $ECR/himaya-frontend:latest \
    --push \
    ./frontend

  echo "🚀 Deploying frontend to ECS..."
  aws ecs update-service \
    --cluster $CLUSTER \
    --service himaya-frontend \
    --force-new-deployment \
    --region $REGION > /dev/null
  echo "   ✓ ECS deploy triggered"

  echo "🌐 Invalidating CloudFront cache..."
  aws cloudfront create-invalidation \
    --distribution-id $CF_DIST \
    --paths "/*" > /dev/null
  echo "   ✓ Cache invalidated"
fi

if [ "$TARGET" = "backend" ] || [ "$TARGET" = "both" ]; then
  echo ""
  echo "🏗️  Building backend (linux/arm64)..."
  docker buildx build \
    --builder cross-builder \
    --platform linux/arm64 \
    -t $ECR/himaya-backend:latest \
    --push \
    .

  echo "🚀 Registering new task definition rev and deploying backend..."
  # Register new task def revision to force ECS to pull latest :latest image
  TD_JSON=$(aws ecs describe-task-definition --task-definition himaya-backend \
    --region $REGION --query "taskDefinition" --output json)
  CLEAN_TD=$(echo "$TD_JSON" | python3 -c "
import json,sys,time
td=json.load(sys.stdin)
for e in td['containerDefinitions'][0]['environment']:
    if e['name']=='DEPLOY_TS': e['value']=str(int(time.time()))
for f in ['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt']:
    td.pop(f,None)
# Ensure container healthCheck has a generous startPeriod — backend
# startup hits DDL lock contention on rolling deploys and can take
# 90-180s before /health is responsive. Without startPeriod, Docker
# starts probing immediately and ECS kills the task before it boots.
#
# 2026-06-17: bumped CPU/mem to 2048/4096 and loosened HC timing so
# concurrent background work (M365 baseline ingestion, Gmail draft
# scans, SharePoint/Teams, Databricks, Claude DLP) cannot briefly
# starve the event loop and trip the 10s curl /health probe.
td['cpu'] = '2048'
td['memory'] = '4096'
for c in td.get('containerDefinitions', []):
    if c.get('name') == 'sentinel-backend':
        c['healthCheck'] = {
            'command': ['CMD-SHELL', 'curl -f http://localhost:8000/health || exit 1'],
            'interval': 45,       # was 30
            'timeout': 15,        # was 10
            'retries': 6,         # 6x45s = 4.5 min of failures before kill
            'startPeriod': 300,   # 5 min grace for startup
        }
print(json.dumps(td))
")
  echo "$CLEAN_TD" > /tmp/_td_deploy.json
  NEW_REV=$(aws ecs register-task-definition --region $REGION \
    --cli-input-json file:///tmp/_td_deploy.json \
    --query "taskDefinition.revision" --output text 2>/dev/null)
  aws ecs update-service \
    --cluster $CLUSTER \
    --service himaya-backend \
    --task-definition "himaya-backend:$NEW_REV" \
    --force-new-deployment \
    --region $REGION > /dev/null
  echo "   ✓ ECS deploy triggered (rev $NEW_REV)"
fi

echo ""
echo "⏳ Waiting for ECS to stabilize (this takes ~2 min)..."
if [ "$TARGET" = "both" ]; then
  aws ecs wait services-stable \
    --cluster $CLUSTER \
    --services himaya-frontend himaya-backend \
    --region $REGION
elif [ "$TARGET" = "frontend" ]; then
  aws ecs wait services-stable \
    --cluster $CLUSTER \
    --services himaya-frontend \
    --region $REGION
else
  aws ecs wait services-stable \
    --cluster $CLUSTER \
    --services himaya-backend \
    --region $REGION
fi

echo ""
echo "✅ Deploy complete!"
echo "   Frontend → https://app.himaya.ai"
echo "   API      → $API_URL/docs"

# ── Run quality check ──────────────────────────────────────────────────────
echo ""
echo "⏳ Running post-deploy quality check..."
sleep 10  # Brief settle time
if bash "$(dirname "$0")/scripts/quality-check.sh"; then
  echo "🟢 Quality check passed — deploy validated"
else
  echo "🔴 Quality check found issues — review above before announcing deploy"
fi

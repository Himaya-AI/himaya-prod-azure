#!/bin/bash
set -e

# Set VNC password from env if provided (use Python since vncpasswd binary varies by distro)
if [ -n "$VNC_PASSWORD" ]; then
    VNC_PASSWORD="$VNC_PASSWORD" python3 /tmp/make_vnc_passwd.py
fi

# Write email HTML — prefer Azure Blob key, then S3 key, then inline b64
mkdir -p /sandbox/email
if [ -n "$EMAIL_BLOB_KEY" ] && [ -n "$AZURE_STORAGE_ACCOUNT" ]; then
    # Fetch from Azure Blob using managed identity or anonymous SAS URL
    python3 -c "
import os, sys
account=os.environ.get('AZURE_STORAGE_ACCOUNT','')
container=os.environ.get('AZURE_STORAGE_CONTAINER','himaya-evidence')
key=os.environ.get('EMAIL_BLOB_KEY','')
if account and key:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient
        creds = DefaultAzureCredential()
        client = BlobServiceClient(account_url=f'https://{account}.blob.core.windows.net', credential=creds)
        blob = client.get_blob_client(container=container, blob=key)
        with open('/sandbox/email/index.html', 'wb') as f:
            f.write(blob.download_blob().readall())
        print('Email HTML fetched from Azure Blob')
    except Exception as e:
        print(f'Azure Blob fetch failed: {e}', file=sys.stderr)
" 2>/dev/null || true
elif [ -n "$EMAIL_S3_KEY" ] && [ -n "$SANDBOX_BUCKET" ]; then
    # Fetch from S3 using instance metadata credentials (task role)
    AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
    S3_URL="https://${SANDBOX_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${EMAIL_S3_KEY}"
    # Get temp creds from ECS task credential endpoint
    CREDS_URI="${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}"
    if [ -n "$CREDS_URI" ]; then
        CREDS=$(curl -sf "http://169.254.170.2${CREDS_URI}")
        AWS_ACCESS_KEY_ID=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null)
        AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null)
        AWS_SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Token'])" 2>/dev/null)
        export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    fi
    python3 -c "
import os, sys
bucket=os.environ.get('SANDBOX_BUCKET','')
key=os.environ.get('EMAIL_S3_KEY','')
region=os.environ.get('AWS_DEFAULT_REGION','us-east-1')
if bucket and key:
    import boto3
    s3=boto3.client('s3',region_name=region)
    s3.download_file(bucket, key, '/sandbox/email/index.html')
    print('Email HTML fetched from S3')
" 2>/dev/null || curl -sf "$S3_URL" -o /sandbox/email/index.html 2>/dev/null || true
elif [ -n "$EMAIL_HTML_B64" ]; then
    echo "$EMAIL_HTML_B64" | base64 -d > /sandbox/email/index.html
fi

# Signal readiness to SSM Parameter Store (if configured)
INSTANCE_ID=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || \
              curl -s --max-time 2 http://169.254.170.2/v2/metadata 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('TaskARN','container'))" 2>/dev/null || \
              echo "container-$$")

# Start tcpdump for network logging (non-fatal)
mkdir -p /sandbox/logs
tcpdump -i any -w /sandbox/logs/network.pcap -G 1800 -W 1 2>/dev/null &

# Start supervisor (VNC + noVNC + openbox + Firefox)
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/sandbox.conf

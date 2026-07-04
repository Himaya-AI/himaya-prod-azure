# Helios Interactive Sandbox — AWS Setup Guide

## Overview
The interactive sandbox spins up an isolated EC2 instance per session,
streams the desktop via noVNC (WebSocket) to the analyst's browser, and
terminates the instance when the session ends.

## One-time Infrastructure Setup

### 1. Create a Sandbox VPC (isolated from prod)
```bash
# Create VPC
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.99.0.0/16 --query 'Vpc.VpcId' --output text --region uaenorth)
aws ec2 create-tags --resources $VPC_ID --tags Key=Name,Value=helios-sandbox-vpc --region uaenorth

# Create public subnet (sandbox instances need egress for package installs + a public IP for noVNC access)
SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.99.1.0/24 \
  --availability-zone uaenortha --query 'Subnet.SubnetId' --output text --region uaenorth)
aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch

# Internet gateway
IGW_ID=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text --region uaenorth)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID

# Route table
RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --query 'RouteTable.RouteTableId' --output text --region uaenorth)
aws ec2 create-route --route-table-id $RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
aws ec2 associate-route-table --route-table-id $RT_ID --subnet-id $SUBNET_ID
```

### 2. Create Security Group
```bash
SG_ID=$(aws ec2 create-security-group \
  --group-name helios-sandbox-sg \
  --description "Helios sandbox instances - noVNC access" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text --region uaenorth)

# Allow inbound noVNC (port 6080) from backend only (or 0.0.0.0/0 for simplicity)
# TODO: restrict to the ECS task's security group for production
aws ec2 authorize-security-group-ingress --group-id $SG_ID \
  --protocol tcp --port 6080 --cidr 0.0.0.0/0 --region uaenorth

# Allow SSH for debugging (optional, disable in prod)
aws ec2 authorize-security-group-ingress --group-id $SG_ID \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region uaenorth

echo "Security Group: $SG_ID"
```

### 3. Create IAM Instance Profile
```bash
# Policy: allow SSM parameter writes (for ready signal) + S3 log upload + self-terminate
cat > /tmp/sandbox-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:PutParameter", "ssm:GetParameter"],
      "Resource": "arn:aws:ssm:uaenorth:*:parameter/helios/sandbox/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::YOUR_SANDBOX_BUCKET/sandbox-sessions/*"
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:TerminateInstances"],
      "Resource": "*",
      "Condition": {"StringEquals": {"ec2:ResourceTag/helios:auto-terminate": "true"}}
    }
  ]
}
EOF

aws iam create-role --role-name helios-sandbox-ec2-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam put-role-policy --role-name helios-sandbox-ec2-role \
  --policy-name sandbox-policy --policy-document file:///tmp/sandbox-policy.json

aws iam attach-role-policy --role-name helios-sandbox-ec2-role \
  --policy-arn arn:aws:policy/AmazonSSMManagedInstanceCore

INSTANCE_PROFILE=$(aws iam create-instance-profile \
  --instance-profile-name helios-sandbox-profile \
  --query 'InstanceProfile.Arn' --output text)

aws iam add-role-to-instance-profile \
  --instance-profile-name helios-sandbox-profile \
  --role-name helios-sandbox-ec2-role
```

### 4. (Optional) Pre-build a Custom AMI for Faster Boot
Without a pre-built AMI, the user-data script installs packages on every boot (~3-4 min).
To pre-build:
```bash
# Launch a base instance
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id ami-0735c191cf914754d \
  --instance-type t3.medium \
  --subnet-id $SUBNET_ID \
  --security-group-ids $SG_ID \
  --query 'Instances[0].InstanceId' --output text)

# Connect via SSM and pre-install packages, then create AMI
aws ec2 create-image --instance-id $INSTANCE_ID \
  --name "helios-sandbox-ami-v1" \
  --query 'ImageId' --output text
# This gives you SANDBOX_AMI_ID
```

### 5. Set ECS Task Environment Variables
Add these to the `himaya-backend` ECS task definition:
```
SANDBOX_AMI_ID=ami-XXXXXXXXXXXXXXXXX   # Pre-built AMI (or leave blank for dynamic install)
SANDBOX_SG_ID=sg-XXXXXXXXXXXXXXXXX     # Security group from step 2
SANDBOX_SUBNET_ID=subnet-XXXXXXXXX     # Subnet from step 1
SANDBOX_INSTANCE_PROFILE=arn:aws:iam::ACCOUNT:instance-profile/helios-sandbox-profile
SANDBOX_S3_BUCKET=helios-sandbox-logs  # S3 bucket for activity logs
SANDBOX_INSTANCE_TYPE=t3.medium        # t3.medium = ~$0.04/hr
SANDBOX_SESSION_TIMEOUT_MINUTES=30
```

## Cost Estimate
- t3.medium: ~$0.0416/hour
- 30-minute session: ~$0.02 per session
- + EBS root volume: ~$0.001 per session
- **Total: ~$0.03-0.05 per session**

## Roadmap: Windows + Outlook Sandbox
For full Outlook/macro detonation:
1. Create a Windows Server 2022 AMI with Microsoft Office + Sysmon + WireShark installed
2. Use NICE DCV instead of noVNC for better Windows streaming
3. Inject the email via MAPI or .eml file opened in Outlook
4. Set SANDBOX_AMI_ID to the Windows AMI ID

"""
Helios AWS Security Service — scans AWS resources for data inventory and security issues.
Supports: S3, EFS, EBS, RDS
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AWSResource:
    """Represents an AWS resource in the data inventory."""
    resource_type: str  # s3_bucket, s3_object, efs_filesystem, ebs_volume, ebs_snapshot, rds_instance
    resource_id: str
    resource_arn: str
    name: str
    region: str
    size_bytes: Optional[int] = None
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    encryption_enabled: bool = False
    encryption_type: Optional[str] = None
    public_access: bool = False
    tags: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class SecurityFinding:
    """Security finding/alert for an AWS resource."""
    finding_id: str
    severity: str  # critical, high, medium, low, info
    category: str  # encryption, public_access, misconfiguration, compliance
    resource_type: str
    resource_id: str
    resource_arn: str
    title: str
    description: str
    recommendation: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)


class AWSSecurityService:
    """
    AWS Security Scanner for Helios.
    Scans S3, EFS, EBS, and RDS for data inventory and security issues.
    """

    def __init__(self, access_key_id: str, secret_access_key: str, region: str = "us-east-1"):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.default_region = region
        self._clients: dict = {}

    def _get_client(self, service: str, region: Optional[str] = None):
        """Get or create a boto3 client for a service."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed. Run: pip install boto3")
            raise ImportError("boto3 is required for AWS scanning")

        region = region or self.default_region
        cache_key = f"{service}:{region}"
        
        if cache_key not in self._clients:
            self._clients[cache_key] = boto3.client(
                service,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=region,
            )
        return self._clients[cache_key]

    async def test_connection(self) -> dict:
        """Test AWS credentials by calling STS GetCallerIdentity."""
        try:
            import boto3
            sts = boto3.client(
                "sts",
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.default_region,
            )
            loop = asyncio.get_event_loop()
            identity = await loop.run_in_executor(None, sts.get_caller_identity)
            return {
                "success": True,
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn"),
                "user_id": identity.get("UserId"),
            }
        except Exception as e:
            logger.error(f"AWS connection test failed: {e}")
            return {"success": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────────────────────
    # S3 Scanning
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_s3_buckets(self) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """Scan all S3 buckets for data inventory and security issues."""
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []

        try:
            s3 = self._get_client("s3")
            loop = asyncio.get_event_loop()
            
            # List all buckets
            response = await loop.run_in_executor(None, s3.list_buckets)
            buckets = response.get("Buckets", [])
            
            for bucket in buckets:
                bucket_name = bucket["Name"]
                created = bucket.get("CreationDate")
                
                # Get bucket location
                try:
                    loc_resp = await loop.run_in_executor(
                        None, lambda: s3.get_bucket_location(Bucket=bucket_name)
                    )
                    region = loc_resp.get("LocationConstraint") or "us-east-1"
                except Exception:
                    region = "us-east-1"

                # Check encryption
                encryption_enabled = False
                encryption_type = None
                try:
                    enc_resp = await loop.run_in_executor(
                        None, lambda: s3.get_bucket_encryption(Bucket=bucket_name)
                    )
                    rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        encryption_enabled = True
                        encryption_type = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                except s3.exceptions.ClientError:
                    pass  # No encryption configured

                # Check public access
                public_access = False
                try:
                    acl_resp = await loop.run_in_executor(
                        None, lambda: s3.get_bucket_acl(Bucket=bucket_name)
                    )
                    for grant in acl_resp.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") in (
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        ):
                            public_access = True
                            break
                except Exception:
                    pass

                # Check block public access
                try:
                    block_resp = await loop.run_in_executor(
                        None, lambda: s3.get_public_access_block(Bucket=bucket_name)
                    )
                    config = block_resp.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        config.get("BlockPublicAcls"),
                        config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("RestrictPublicBuckets"),
                    ]):
                        public_access = True
                except Exception:
                    public_access = True  # Assume public if we can't check

                # Try to find bucket creator from CloudTrail (best effort)
                created_by = None
                try:
                    ct = self._get_client("cloudtrail", region)
                    from datetime import timedelta
                    if created:
                        # Look for CreateBucket event around creation time
                        ct_resp = await loop.run_in_executor(
                            None, lambda: ct.lookup_events(
                                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": bucket_name}],
                                StartTime=created - timedelta(hours=1),
                                EndTime=created + timedelta(hours=1),
                                MaxResults=5,
                            )
                        )
                        for event in ct_resp.get("Events", []):
                            if event.get("EventName") == "CreateBucket":
                                created_by = event.get("Username")
                                break
                except Exception:
                    pass  # CloudTrail lookup failed, continue without owner

                resource = AWSResource(
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    name=bucket_name,
                    region=region,
                    created_at=created,
                    encryption_enabled=encryption_enabled,
                    encryption_type=encryption_type,
                    public_access=public_access,
                    metadata={"created_by": created_by} if created_by else None,
                )
                resources.append(resource)

                # Generate security findings
                if not encryption_enabled:
                    findings.append(SecurityFinding(
                        finding_id=f"s3-encryption-{bucket_name}",
                        severity="high",
                        category="encryption",
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        title="S3 Bucket Not Encrypted",
                        description=f"S3 bucket '{bucket_name}' does not have server-side encryption enabled.",
                        recommendation="Enable default encryption using AES-256 or AWS KMS.",
                    ))

                if public_access:
                    findings.append(SecurityFinding(
                        finding_id=f"s3-public-{bucket_name}",
                        severity="critical",
                        category="public_access",
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        title="S3 Bucket Has Public Access",
                        description=f"S3 bucket '{bucket_name}' allows public access.",
                        recommendation="Enable S3 Block Public Access and review bucket policies.",
                    ))

        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {e}")

        return resources, findings

    # ─────────────────────────────────────────────────────────────────────────
    # EFS Scanning
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_efs_filesystems(self, regions: list[str] = None) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """Scan EFS filesystems for data inventory and security issues."""
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        regions = regions or [self.default_region]

        for region in regions:
            try:
                efs = self._get_client("efs", region)
                loop = asyncio.get_event_loop()
                
                response = await loop.run_in_executor(None, efs.describe_file_systems)
                filesystems = response.get("FileSystems", [])
                
                for fs in filesystems:
                    fs_id = fs["FileSystemId"]
                    name = fs.get("Name") or fs_id
                    encrypted = fs.get("Encrypted", False)
                    
                    resource = AWSResource(
                        resource_type="efs_filesystem",
                        resource_id=fs_id,
                        resource_arn=fs.get("FileSystemArn", f"arn:aws:elasticfilesystem:{region}::file-system/{fs_id}"),
                        name=name,
                        region=region,
                        size_bytes=fs.get("SizeInBytes", {}).get("Value"),
                        created_at=fs.get("CreationTime"),
                        encryption_enabled=encrypted,
                        encryption_type="aws:kms" if encrypted else None,
                        tags={t["Key"]: t["Value"] for t in fs.get("Tags", [])},
                        metadata={
                            "lifecycle_state": fs.get("LifeCycleState"),
                            "performance_mode": fs.get("PerformanceMode"),
                            "throughput_mode": fs.get("ThroughputMode"),
                        },
                    )
                    resources.append(resource)

                    if not encrypted:
                        findings.append(SecurityFinding(
                            finding_id=f"efs-encryption-{fs_id}",
                            severity="high",
                            category="encryption",
                            resource_type="efs_filesystem",
                            resource_id=fs_id,
                            resource_arn=resource.resource_arn,
                            title="EFS Filesystem Not Encrypted",
                            description=f"EFS filesystem '{name}' ({fs_id}) is not encrypted at rest.",
                            recommendation="Create a new encrypted EFS filesystem and migrate data.",
                        ))

            except Exception as e:
                logger.error(f"Error scanning EFS in {region}: {e}")

        return resources, findings

    # ─────────────────────────────────────────────────────────────────────────
    # EBS Scanning
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_ebs_volumes(self, regions: list[str] = None) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """Scan EBS volumes and snapshots for data inventory and security issues."""
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        regions = regions or [self.default_region]

        for region in regions:
            try:
                ec2 = self._get_client("ec2", region)
                loop = asyncio.get_event_loop()
                
                # Scan volumes
                vol_response = await loop.run_in_executor(None, ec2.describe_volumes)
                volumes = vol_response.get("Volumes", [])
                
                for vol in volumes:
                    vol_id = vol["VolumeId"]
                    encrypted = vol.get("Encrypted", False)
                    name = vol_id
                    for tag in vol.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break
                    
                    resource = AWSResource(
                        resource_type="ebs_volume",
                        resource_id=vol_id,
                        resource_arn=f"arn:aws:ec2:{region}::volume/{vol_id}",
                        name=name,
                        region=region,
                        size_bytes=vol.get("Size", 0) * 1024 * 1024 * 1024,  # GB to bytes
                        created_at=vol.get("CreateTime"),
                        encryption_enabled=encrypted,
                        encryption_type="aws:kms" if encrypted else None,
                        tags={t["Key"]: t["Value"] for t in vol.get("Tags", [])},
                        metadata={
                            "volume_type": vol.get("VolumeType"),
                            "state": vol.get("State"),
                            "iops": vol.get("Iops"),
                            "availability_zone": vol.get("AvailabilityZone"),
                        },
                    )
                    resources.append(resource)

                    if not encrypted:
                        findings.append(SecurityFinding(
                            finding_id=f"ebs-encryption-{vol_id}",
                            severity="medium",
                            category="encryption",
                            resource_type="ebs_volume",
                            resource_id=vol_id,
                            resource_arn=resource.resource_arn,
                            title="EBS Volume Not Encrypted",
                            description=f"EBS volume '{name}' ({vol_id}) is not encrypted.",
                            recommendation="Create an encrypted snapshot and restore to a new encrypted volume.",
                        ))

                # Scan snapshots
                snap_response = await loop.run_in_executor(
                    None, lambda: ec2.describe_snapshots(OwnerIds=["self"])
                )
                snapshots = snap_response.get("Snapshots", [])
                
                for snap in snapshots:
                    snap_id = snap["SnapshotId"]
                    encrypted = snap.get("Encrypted", False)
                    name = snap.get("Description") or snap_id
                    
                    # Check if snapshot is public
                    public_access = False
                    try:
                        attr_resp = await loop.run_in_executor(
                            None, lambda: ec2.describe_snapshot_attribute(
                                SnapshotId=snap_id, Attribute="createVolumePermission"
                            )
                        )
                        for perm in attr_resp.get("CreateVolumePermissions", []):
                            if perm.get("Group") == "all":
                                public_access = True
                                break
                    except Exception:
                        pass
                    
                    resource = AWSResource(
                        resource_type="ebs_snapshot",
                        resource_id=snap_id,
                        resource_arn=f"arn:aws:ec2:{region}::snapshot/{snap_id}",
                        name=name,
                        region=region,
                        size_bytes=snap.get("VolumeSize", 0) * 1024 * 1024 * 1024,
                        created_at=snap.get("StartTime"),
                        encryption_enabled=encrypted,
                        encryption_type="aws:kms" if encrypted else None,
                        public_access=public_access,
                        tags={t["Key"]: t["Value"] for t in snap.get("Tags", [])},
                        metadata={
                            "state": snap.get("State"),
                            "volume_id": snap.get("VolumeId"),
                            "progress": snap.get("Progress"),
                        },
                    )
                    resources.append(resource)

                    if public_access:
                        findings.append(SecurityFinding(
                            finding_id=f"ebs-snapshot-public-{snap_id}",
                            severity="critical",
                            category="public_access",
                            resource_type="ebs_snapshot",
                            resource_id=snap_id,
                            resource_arn=resource.resource_arn,
                            title="EBS Snapshot Is Public",
                            description=f"EBS snapshot '{snap_id}' is publicly accessible.",
                            recommendation="Remove public access permissions from the snapshot.",
                        ))

            except Exception as e:
                logger.error(f"Error scanning EBS in {region}: {e}")

        return resources, findings

    # ─────────────────────────────────────────────────────────────────────────
    # RDS Scanning
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_rds_instances(self, regions: list[str] = None) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """Scan RDS instances for data inventory and security issues."""
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        regions = regions or [self.default_region]

        for region in regions:
            try:
                rds = self._get_client("rds", region)
                loop = asyncio.get_event_loop()
                
                response = await loop.run_in_executor(None, rds.describe_db_instances)
                instances = response.get("DBInstances", [])
                
                for db in instances:
                    db_id = db["DBInstanceIdentifier"]
                    encrypted = db.get("StorageEncrypted", False)
                    public_access = db.get("PubliclyAccessible", False)
                    
                    resource = AWSResource(
                        resource_type="rds_instance",
                        resource_id=db_id,
                        resource_arn=db.get("DBInstanceArn", f"arn:aws:rds:{region}::db:{db_id}"),
                        name=db_id,
                        region=region,
                        size_bytes=db.get("AllocatedStorage", 0) * 1024 * 1024 * 1024,
                        created_at=db.get("InstanceCreateTime"),
                        encryption_enabled=encrypted,
                        encryption_type="aws:kms" if encrypted else None,
                        public_access=public_access,
                        tags={},  # RDS requires separate call for tags
                        metadata={
                            "engine": db.get("Engine"),
                            "engine_version": db.get("EngineVersion"),
                            "instance_class": db.get("DBInstanceClass"),
                            "status": db.get("DBInstanceStatus"),
                            "multi_az": db.get("MultiAZ"),
                            "endpoint": db.get("Endpoint", {}).get("Address"),
                        },
                    )
                    resources.append(resource)

                    if not encrypted:
                        findings.append(SecurityFinding(
                            finding_id=f"rds-encryption-{db_id}",
                            severity="high",
                            category="encryption",
                            resource_type="rds_instance",
                            resource_id=db_id,
                            resource_arn=resource.resource_arn,
                            title="RDS Instance Not Encrypted",
                            description=f"RDS instance '{db_id}' is not encrypted at rest.",
                            recommendation="Create an encrypted snapshot and restore to a new encrypted instance.",
                        ))

                    if public_access:
                        findings.append(SecurityFinding(
                            finding_id=f"rds-public-{db_id}",
                            severity="critical",
                            category="public_access",
                            resource_type="rds_instance",
                            resource_id=db_id,
                            resource_arn=resource.resource_arn,
                            title="RDS Instance Is Publicly Accessible",
                            description=f"RDS instance '{db_id}' is publicly accessible.",
                            recommendation="Disable public accessibility and use VPC security groups.",
                        ))

            except Exception as e:
                logger.error(f"Error scanning RDS in {region}: {e}")

        return resources, findings

    # ─────────────────────────────────────────────────────────────────────────
    # Full Scan
    # ─────────────────────────────────────────────────────────────────────────

    async def scan_all(self, regions: list[str] = None) -> dict:
        """
        Run a full scan of all supported AWS services.
        Returns aggregated resources and findings.
        """
        all_resources: list[AWSResource] = []
        all_findings: list[SecurityFinding] = []

        # S3 (global service)
        s3_resources, s3_findings = await self.scan_s3_buckets()
        all_resources.extend(s3_resources)
        all_findings.extend(s3_findings)

        # Regional services
        efs_resources, efs_findings = await self.scan_efs_filesystems(regions)
        all_resources.extend(efs_resources)
        all_findings.extend(efs_findings)

        ebs_resources, ebs_findings = await self.scan_ebs_volumes(regions)
        all_resources.extend(ebs_resources)
        all_findings.extend(ebs_findings)

        rds_resources, rds_findings = await self.scan_rds_instances(regions)
        all_resources.extend(rds_resources)
        all_findings.extend(rds_findings)

        # CloudTrail for admin activity detection
        cloudtrail_findings = await self.scan_cloudtrail_events(regions)
        all_findings.extend(cloudtrail_findings)

        # IAM Users (global service)
        iam_resources, iam_findings = await self.scan_iam_users()
        all_resources.extend(iam_resources)
        all_findings.extend(iam_findings)

        # IAM Roles (global service)
        role_resources, role_findings = await self.scan_iam_roles()
        all_resources.extend(role_resources)
        all_findings.extend(role_findings)

        # EC2 Instances (regional)
        ec2_resources, ec2_findings = await self.scan_ec2_instances(regions)
        all_resources.extend(ec2_resources)
        all_findings.extend(ec2_findings)

        # Aggregate stats
        stats = {
            "total_resources": len(all_resources),
            "total_findings": len(all_findings),
            "critical_findings": len([f for f in all_findings if f.severity == "critical"]),
            "high_findings": len([f for f in all_findings if f.severity == "high"]),
            "medium_findings": len([f for f in all_findings if f.severity == "medium"]),
            "by_resource_type": {},
            "by_finding_category": {},
        }

        for r in all_resources:
            stats["by_resource_type"][r.resource_type] = stats["by_resource_type"].get(r.resource_type, 0) + 1

        for f in all_findings:
            stats["by_finding_category"][f.category] = stats["by_finding_category"].get(f.category, 0) + 1

        return {
            "resources": [self._resource_to_dict(r) for r in all_resources],
            "findings": [self._finding_to_dict(f) for f in all_findings],
            "stats": stats,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _resource_to_dict(self, r: AWSResource) -> dict:
        return {
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "resource_arn": r.resource_arn,
            "name": r.name,
            "region": r.region,
            "size_bytes": r.size_bytes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_modified": r.last_modified.isoformat() if r.last_modified else None,
            "encryption_enabled": r.encryption_enabled,
            "encryption_type": r.encryption_type,
            "public_access": r.public_access,
            "tags": r.tags,
            "metadata": r.metadata,
        }

    def _finding_to_dict(self, f: SecurityFinding) -> dict:
        return {
            "finding_id": f.finding_id,
            "severity": f.severity,
            "category": f.category,
            "resource_type": f.resource_type,
            "resource_id": f.resource_id,
            "resource_arn": f.resource_arn,
            "title": f.title,
            "description": f.description,
            "recommendation": f.recommendation,
            "detected_at": f.detected_at.isoformat(),
            "metadata": f.metadata,
        }

    async def scan_cloudtrail_events(self, regions: list[str]) -> list[SecurityFinding]:
        """
        Scan CloudTrail for sensitive admin actions.
        Detects: IAM changes, security group changes, KMS operations, etc.
        """
        findings: list[SecurityFinding] = []
        
        SENSITIVE_EVENTS = {
            # IAM events (critical)
            "CreateUser": ("critical", "New IAM user created"),
            "DeleteUser": ("high", "IAM user deleted"),
            "CreateAccessKey": ("critical", "New access key created"),
            "DeleteAccessKey": ("medium", "Access key deleted"),
            "AttachUserPolicy": ("high", "Policy attached to user"),
            "AttachRolePolicy": ("high", "Policy attached to role"),
            "CreateRole": ("high", "New IAM role created"),
            "DeleteRole": ("medium", "IAM role deleted"),
            "PutUserPolicy": ("high", "Inline policy added to user"),
            "PutRolePolicy": ("high", "Inline policy added to role"),
            "CreatePolicyVersion": ("medium", "IAM policy version created"),
            "UpdateAssumeRolePolicy": ("high", "Role trust policy updated"),
            # Security Groups
            "AuthorizeSecurityGroupIngress": ("high", "Inbound rule added to security group"),
            "AuthorizeSecurityGroupEgress": ("medium", "Outbound rule added to security group"),
            "RevokeSecurityGroupIngress": ("medium", "Inbound rule removed from security group"),
            # KMS
            "DisableKey": ("critical", "KMS key disabled"),
            "ScheduleKeyDeletion": ("critical", "KMS key scheduled for deletion"),
            "PutKeyPolicy": ("high", "KMS key policy changed"),
            # CloudTrail
            "StopLogging": ("critical", "CloudTrail logging stopped"),
            "DeleteTrail": ("critical", "CloudTrail trail deleted"),
            "UpdateTrail": ("medium", "CloudTrail configuration changed"),
            # Config
            "StopConfigurationRecorder": ("critical", "AWS Config recording stopped"),
            "DeleteConfigurationRecorder": ("critical", "AWS Config recorder deleted"),
            # S3
            "PutBucketPolicy": ("high", "S3 bucket policy changed"),
            "PutBucketAcl": ("high", "S3 bucket ACL changed"),
            "DeleteBucketPolicy": ("medium", "S3 bucket policy deleted"),
            # EC2
            "RunInstances": ("low", "EC2 instance launched"),
            "TerminateInstances": ("medium", "EC2 instance terminated"),
            "ModifyInstanceAttribute": ("medium", "EC2 instance attribute changed"),
            # Lambda
            "CreateFunction": ("medium", "Lambda function created"),
            "UpdateFunctionCode": ("medium", "Lambda function code updated"),
            "AddPermission": ("high", "Lambda permission added"),
        }

        for region in regions[:3]:  # Limit regions to avoid rate limits
            try:
                client = self._get_client("cloudtrail", region)
                
                # Look up events from the last 24 hours
                from datetime import timedelta
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(hours=24)
                
                paginator = client.get_paginator("lookup_events")
                
                for event_name, (severity, description) in SENSITIVE_EVENTS.items():
                    try:
                        pages = paginator.paginate(
                            LookupAttributes=[
                                {"AttributeKey": "EventName", "AttributeValue": event_name}
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            MaxResults=10,
                        )
                        
                        for page in pages:
                            for event in page.get("Events", []):
                                event_id = event.get("EventId", "unknown")
                                username = event.get("Username", "unknown")
                                event_time = event.get("EventTime", datetime.now(timezone.utc))
                                
                                # Parse CloudTrailEvent JSON for details
                                import json
                                cloud_event = json.loads(event.get("CloudTrailEvent", "{}"))
                                source_ip = cloud_event.get("sourceIPAddress", "unknown")
                                user_agent = cloud_event.get("userAgent", "")
                                resources = cloud_event.get("resources", [])
                                resource_arn = resources[0].get("ARN", "") if resources else ""
                                
                                findings.append(SecurityFinding(
                                    finding_id=f"cloudtrail-{event_id}",
                                    severity=severity,
                                    category="admin_action",
                                    resource_type="cloudtrail_event",
                                    resource_id=event_name,
                                    resource_arn=resource_arn or f"arn:aws:cloudtrail:{region}:event:{event_id}",
                                    title=f"Admin Action: {description}",
                                    description=(
                                        f"{description} by {username} from {source_ip}. "
                                        f"Event: {event_name} in {region}."
                                    ),
                                    recommendation="Review this action to ensure it was authorized and expected.",
                                    detected_at=event_time if isinstance(event_time, datetime) else datetime.now(timezone.utc),
                                    metadata={
                                        "event_name": event_name,
                                        "username": username,
                                        "source_ip": source_ip,
                                        "user_agent": user_agent[:100] if user_agent else None,
                                        "region": region,
                                    },
                                ))
                    except Exception as e:
                        # Some events may not exist or access denied
                        logger.debug(f"CloudTrail lookup for {event_name}: {e}")
                        continue
                        
            except Exception as e:
                logger.warning(f"CloudTrail scan failed for {region}: {e}")
                continue

        return findings

    async def scan_iam_users(self) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """
        Scan IAM users for security issues.
        Checks: MFA status, access key age, console access, inactive users.
        """
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        
        try:
            iam_client = self._get_client("iam")
            paginator = iam_client.get_paginator("list_users")
            
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]
                    user_id = user["UserId"]
                    created = user.get("CreateDate")
                    password_last_used = user.get("PasswordLastUsed")
                    
                    # Get MFA devices
                    mfa_enabled = False
                    try:
                        mfa_resp = iam_client.list_mfa_devices(UserName=user_name)
                        mfa_enabled = len(mfa_resp.get("MFADevices", [])) > 0
                    except Exception:
                        pass
                    
                    # Get access keys with last used info
                    access_keys = []
                    access_key_count = 0
                    old_key_found = False
                    last_key_used_at = None
                    try:
                        keys_resp = iam_client.list_access_keys(UserName=user_name)
                        raw_keys = keys_resp.get("AccessKeyMetadata", [])
                        access_key_count = len(raw_keys)
                        for key in raw_keys:
                            key_id = key.get("AccessKeyId")
                            key_created = key.get("CreateDate")
                            key_status = key.get("Status")
                            
                            # Check if key is old
                            if key_created and (datetime.now(timezone.utc) - key_created.replace(tzinfo=timezone.utc)).days > 90:
                                old_key_found = True
                            
                            # Get last used info for each key
                            key_last_used = None
                            key_last_used_region = None
                            key_last_used_service = None
                            try:
                                last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                                last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
                                key_last_used = last_used_info.get("LastUsedDate")
                                key_last_used_region = last_used_info.get("Region")
                                key_last_used_service = last_used_info.get("ServiceName")
                                if key_last_used:
                                    if last_key_used_at is None or key_last_used > last_key_used_at:
                                        last_key_used_at = key_last_used
                            except Exception:
                                pass
                            
                            access_keys.append({
                                "AccessKeyId": key_id,
                                "Status": key_status,
                                "CreateDate": key_created.isoformat() if key_created else None,
                                "LastUsedDate": key_last_used.isoformat() if key_last_used else None,
                                "LastUsedRegion": key_last_used_region,
                                "LastUsedService": key_last_used_service,
                            })
                    except Exception:
                        pass
                    
                    # Check console access (has login profile)
                    console_access = False
                    try:
                        iam_client.get_login_profile(UserName=user_name)
                        console_access = True
                    except iam_client.exceptions.NoSuchEntityException:
                        console_access = False
                    except Exception:
                        pass
                    
                    # Get attached managed policies
                    attached_policies = []
                    try:
                        pol_resp = iam_client.list_attached_user_policies(UserName=user_name)
                        attached_policies = [
                            {"PolicyName": p["PolicyName"], "PolicyArn": p["PolicyArn"]}
                            for p in pol_resp.get("AttachedPolicies", [])
                        ]
                    except Exception:
                        pass
                    
                    # Get inline policies
                    inline_policies = []
                    try:
                        inline_resp = iam_client.list_user_policies(UserName=user_name)
                        inline_policies = inline_resp.get("PolicyNames", [])
                    except Exception:
                        pass
                    
                    # Get user groups
                    groups = []
                    try:
                        groups_resp = iam_client.list_groups_for_user(UserName=user_name)
                        groups = [g["GroupName"] for g in groups_resp.get("Groups", [])]
                    except Exception:
                        pass
                    
                    # Build resource
                    resources.append(AWSResource(
                        resource_type="iam_user",
                        resource_id=user_id,
                        resource_arn=user_arn,
                        name=user_name,
                        region="global",
                        size_bytes=0,
                        encryption_enabled=True,  # N/A
                        public_access=False,
                        metadata={
                            "user_name": user_name,
                            "mfa_enabled": mfa_enabled,
                            "access_key_count": access_key_count,
                            "access_keys": access_keys,
                            "console_access": console_access,
                            "create_date": created.isoformat() if created else None,
                            "password_last_used": password_last_used.isoformat() if password_last_used else None,
                            "last_key_used_at": last_key_used_at.isoformat() if last_key_used_at else None,
                            "attached_policies": attached_policies,
                            "inline_policies": inline_policies,
                            "groups": groups,
                        },
                    ))
                    
                    # Generate findings
                    if console_access and not mfa_enabled:
                        findings.append(SecurityFinding(
                            finding_id=f"iam-no-mfa-{user_id}",
                            severity="high",
                            category="iam",
                            resource_type="iam_user",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            title=f"IAM user {user_name} has console access without MFA",
                            description=f"User {user_name} can log into the AWS console but does not have MFA enabled. This is a security risk.",
                            recommendation="Enable MFA for this user immediately.",
                            detected_at=datetime.now(timezone.utc),
                            metadata={"user_name": user_name, "console_access": True, "mfa_enabled": False},
                        ))
                    
                    if old_key_found:
                        findings.append(SecurityFinding(
                            finding_id=f"iam-old-key-{user_id}",
                            severity="medium",
                            category="iam",
                            resource_type="iam_user",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            title=f"IAM user {user_name} has access key older than 90 days",
                            description=f"User {user_name} has an access key that is older than 90 days. Old keys increase security risk.",
                            recommendation="Rotate access keys regularly (at least every 90 days).",
                            detected_at=datetime.now(timezone.utc),
                            metadata={"user_name": user_name, "access_key_count": access_key_count},
                        ))
                    
                    if access_key_count > 1:
                        findings.append(SecurityFinding(
                            finding_id=f"iam-multi-key-{user_id}",
                            severity="low",
                            category="iam",
                            resource_type="iam_user",
                            resource_id=user_name,
                            resource_arn=user_arn,
                            title=f"IAM user {user_name} has multiple access keys",
                            description=f"User {user_name} has {access_key_count} access keys. Having multiple keys can make it harder to track key usage.",
                            recommendation="Consider reducing to a single active access key per user.",
                            detected_at=datetime.now(timezone.utc),
                            metadata={"user_name": user_name, "access_key_count": access_key_count},
                        ))
            
            logger.info(f"IAM scan complete: {len(resources)} users, {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"IAM user scan failed: {e}")
        
        return resources, findings

    async def scan_iam_roles(self) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """
        Scan IAM roles for security issues and last used info.
        Checks: Role last used, trust policy, attached policies.
        """
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        
        try:
            iam_client = self._get_client("iam")
            paginator = iam_client.get_paginator("list_roles")
            
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_id = role["RoleId"]
                    created = role.get("CreateDate")
                    assume_role_policy = role.get("AssumeRolePolicyDocument", {})
                    
                    # Get role last used info
                    role_last_used = None
                    role_last_used_region = None
                    try:
                        role_resp = iam_client.get_role(RoleName=role_name)
                        role_details = role_resp.get("Role", {})
                        last_used_info = role_details.get("RoleLastUsed", {})
                        role_last_used = last_used_info.get("LastUsedDate")
                        role_last_used_region = last_used_info.get("Region")
                    except Exception:
                        pass
                    
                    # Get attached managed policies
                    attached_policies = []
                    try:
                        pol_resp = iam_client.list_attached_role_policies(RoleName=role_name)
                        attached_policies = [
                            {"PolicyName": p["PolicyName"], "PolicyArn": p["PolicyArn"]}
                            for p in pol_resp.get("AttachedPolicies", [])
                        ]
                    except Exception:
                        pass
                    
                    # Get inline policies
                    inline_policies = []
                    try:
                        inline_resp = iam_client.list_role_policies(RoleName=role_name)
                        inline_policies = inline_resp.get("PolicyNames", [])
                    except Exception:
                        pass
                    
                    # Skip AWS service-linked roles for cleaner inventory
                    is_service_linked = "/aws-service-role/" in role_arn
                    
                    resources.append(AWSResource(
                        resource_type="iam_role",
                        resource_id=role_id,
                        resource_arn=role_arn,
                        name=role_name,
                        region="global",
                        size_bytes=0,
                        created_at=created.replace(tzinfo=timezone.utc) if created else None,
                        encryption_enabled=True,  # N/A
                        public_access=False,
                        metadata={
                            "role_name": role_name,
                            "role_last_used": role_last_used.isoformat() if role_last_used else None,
                            "role_last_used_region": role_last_used_region,
                            "create_date": created.isoformat() if created else None,
                            "attached_policies": attached_policies,
                            "inline_policies": inline_policies,
                            "is_service_linked": is_service_linked,
                            "assume_role_policy": assume_role_policy,
                        },
                    ))
                    
                    # Finding: Role not used in 90+ days
                    if role_last_used:
                        days_since_used = (datetime.now(timezone.utc) - role_last_used.replace(tzinfo=timezone.utc)).days
                        if days_since_used > 90 and not is_service_linked:
                            findings.append(SecurityFinding(
                                finding_id=f"iam-stale-role-{role_id}",
                                severity="low",
                                category="iam",
                                resource_type="iam_role",
                                resource_id=role_name,
                                resource_arn=role_arn,
                                title=f"IAM role {role_name} not used in {days_since_used} days",
                                description=f"Role {role_name} has not been assumed in over 90 days. Stale roles increase attack surface.",
                                recommendation="Consider deleting or reviewing unused roles.",
                                detected_at=datetime.now(timezone.utc),
                                metadata={"role_name": role_name, "days_since_used": days_since_used},
                            ))
            
            logger.info(f"IAM roles scan complete: {len(resources)} roles, {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"IAM role scan failed: {e}")
        
        return resources, findings

    async def scan_ec2_instances(self, regions: list[str]) -> tuple[list[AWSResource], list[SecurityFinding]]:
        """
        Scan EC2 instances with launch info from CloudTrail.
        Tracks: who launched the instance, when, and current state.
        """
        resources: list[AWSResource] = []
        findings: list[SecurityFinding] = []
        
        for region in regions:
            try:
                ec2 = self._get_client("ec2", region)
                loop = asyncio.get_event_loop()
                
                paginator = ec2.get_paginator("describe_instances")
                page_iterator = paginator.paginate()
                
                for page in page_iterator:
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            instance_id = instance["InstanceId"]
                            instance_type = instance.get("InstanceType", "unknown")
                            state = instance.get("State", {}).get("Name", "unknown")
                            launch_time = instance.get("LaunchTime")
                            
                            # Get tags
                            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                            name = tags.get("Name", instance_id)
                            
                            # Get launched_by from CloudTrail (best effort)
                            launched_by = None
                            try:
                                cloudtrail = self._get_client("cloudtrail", region)
                                from datetime import timedelta
                                # Look for RunInstances event within 24h of launch
                                if launch_time:
                                    start_time = launch_time - timedelta(minutes=5)
                                    end_time = launch_time + timedelta(hours=1)
                                    ct_resp = cloudtrail.lookup_events(
                                        LookupAttributes=[
                                            {"AttributeKey": "ResourceName", "AttributeValue": instance_id}
                                        ],
                                        StartTime=start_time,
                                        EndTime=end_time,
                                        MaxResults=5,
                                    )
                                    for event in ct_resp.get("Events", []):
                                        if event.get("EventName") == "RunInstances":
                                            launched_by = event.get("Username")
                                            break
                            except Exception:
                                pass
                            
                            # Security: public IP
                            public_ip = instance.get("PublicIpAddress")
                            has_public_ip = public_ip is not None
                            
                            # Security: IMDSv2
                            metadata_options = instance.get("MetadataOptions", {})
                            imdsv2_required = metadata_options.get("HttpTokens") == "required"
                            
                            resources.append(AWSResource(
                                resource_type="ec2_instance",
                                resource_id=instance_id,
                                resource_arn=f"arn:aws:ec2:{region}::instance/{instance_id}",
                                name=name,
                                region=region,
                                created_at=launch_time.replace(tzinfo=timezone.utc) if launch_time else None,
                                encryption_enabled=True,  # Check EBS volumes separately
                                public_access=has_public_ip,
                                tags=tags,
                                metadata={
                                    "instance_type": instance_type,
                                    "state": state,
                                    "launched_by": launched_by,
                                    "launch_time": launch_time.isoformat() if launch_time else None,
                                    "public_ip": public_ip,
                                    "private_ip": instance.get("PrivateIpAddress"),
                                    "imdsv2_required": imdsv2_required,
                                    "vpc_id": instance.get("VpcId"),
                                    "subnet_id": instance.get("SubnetId"),
                                },
                            ))
                            
                            # Finding: IMDSv2 not required
                            if not imdsv2_required and state == "running":
                                findings.append(SecurityFinding(
                                    finding_id=f"ec2-imdsv2-{instance_id}",
                                    severity="medium",
                                    category="misconfiguration",
                                    resource_type="ec2_instance",
                                    resource_id=instance_id,
                                    resource_arn=f"arn:aws:ec2:{region}::instance/{instance_id}",
                                    title=f"EC2 instance {name} does not require IMDSv2",
                                    description="Instance allows IMDSv1 which is vulnerable to SSRF attacks.",
                                    recommendation="Require IMDSv2 by setting HttpTokens to 'required'.",
                                    detected_at=datetime.now(timezone.utc),
                                    metadata={"instance_id": instance_id, "imdsv2_required": False},
                                ))
                
                logger.info(f"EC2 scan complete for {region}: {sum(1 for r in resources if r.region == region)} instances")
                
            except Exception as e:
                logger.warning(f"EC2 scan failed for {region}: {e}")
        
        return resources, findings

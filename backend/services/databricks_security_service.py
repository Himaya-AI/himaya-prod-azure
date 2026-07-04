"""
Databricks Security Service — scans Databricks workspaces for security issues.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class DatabricksSecurityService:
    """Service for scanning Databricks workspaces for security issues."""

    def __init__(self, workspace_url: str, access_token: str):
        self.workspace_url = workspace_url.rstrip('/')
        self.access_token = access_token
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    async def _api_call(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make an API call to Databricks."""
        url = f"{self.workspace_url}/api/2.0/{endpoint}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(method, url, headers=self._headers, **kwargs)
            response.raise_for_status()
            return response.json()

    async def test_connection(self) -> dict[str, Any]:
        """Test the Databricks connection by getting current user."""
        try:
            # Get current user to validate token
            result = await self._api_call("GET", "preview/scim/v2/Me")
            
            return {
                "success": True,
                "user_name": result.get("userName"),
                "display_name": result.get("displayName"),
                "workspace_id": result.get("id"),
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"success": False, "error": "Invalid access token"}
            elif e.response.status_code == 403:
                return {"success": False, "error": "Access denied - check token permissions"}
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text}"}
        except httpx.ConnectError:
            return {"success": False, "error": "Could not connect to workspace URL"}
        except Exception as e:
            logger.error(f"Databricks connection test failed: {e}")
            return {"success": False, "error": str(e)}

    async def scan_all(self) -> dict[str, Any]:
        """
        Scan all Databricks resources for security issues.
        Returns resources and findings.
        """
        resources = []
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        try:
            # Scan notebooks
            notebook_resources, notebook_findings = await self._scan_notebooks()
            resources.extend(notebook_resources)
            findings.extend(notebook_findings)

            # Scan clusters
            cluster_resources, cluster_findings = await self._scan_clusters()
            resources.extend(cluster_resources)
            findings.extend(cluster_findings)

            # Scan secrets
            secret_resources, secret_findings = await self._scan_secrets()
            resources.extend(secret_resources)
            findings.extend(secret_findings)

            stats = {
                "total_resources": len(resources),
                "total_findings": len(findings),
                "notebooks": sum(1 for r in resources if r.get("resource_type") == "notebook"),
                "clusters": sum(1 for r in resources if r.get("resource_type") == "cluster"),
                "secrets": sum(1 for r in resources if r.get("resource_type") == "secret"),
                "critical_findings": sum(1 for f in findings if f.get("severity") == "critical"),
                "high_findings": sum(1 for f in findings if f.get("severity") == "high"),
            }

            return {
                "resources": resources,
                "findings": findings,
                "stats": stats,
                "scanned_at": now,
            }

        except Exception as e:
            logger.error(f"Databricks scan failed: {e}")
            return {
                "resources": [],
                "findings": [],
                "stats": {"error": str(e)},
                "scanned_at": now,
            }

    # Secret detection patterns
    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'critical', 'AWS Access Key ID detected'),
        (r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', 'aws_secret_key', 'critical', 'AWS Secret Access Key detected'),
        (r'sk-[a-zA-Z0-9]{48}', 'openai_api_key', 'critical', 'OpenAI API Key detected'),
        (r'sk-proj-[a-zA-Z0-9]{48,}', 'openai_project_key', 'critical', 'OpenAI Project API Key detected'),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{8,})["\']', 'hardcoded_password', 'high', 'Hardcoded password detected'),
        (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})', 'api_key', 'high', 'API key detected'),
        (r'(?i)(token|secret|credential)\s*[=:]\s*["\']([^"\'\s]{16,})["\']', 'secret_token', 'high', 'Secret token or credential detected'),
        (r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'jwt_token', 'high', 'JWT token detected'),
        (r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+', 'azure_storage_key', 'critical', 'Azure Storage connection string detected'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn', 'critical', 'Social Security Number pattern detected'),
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', 'credit_card', 'critical', 'Credit card number pattern detected'),
        (r'(?i)(db_pass|database_password|mysql_password|postgres_password)\s*[=:]', 'db_credential', 'critical', 'Database credential detected'),
    ]

    async def _scan_notebooks(self) -> tuple[list, list]:
        """Scan notebooks for secrets and security issues."""
        import re
        import base64
        
        resources = []
        findings = []

        async def scan_directory(path: str):
            """Recursively scan a directory for notebooks."""
            try:
                result = await self._api_call("GET", "workspace/list", params={"path": path})
                
                for obj in result.get("objects", []):
                    obj_type = obj.get("object_type")
                    obj_path = obj.get("path", "")
                    
                    if obj_type == "DIRECTORY":
                        # Recursively scan subdirectories
                        await scan_directory(obj_path)
                        
                    elif obj_type == "NOTEBOOK":
                        notebook_id = str(obj.get("object_id"))
                        has_secrets = False
                        secret_types = []
                        
                        # Try to export and scan notebook content
                        try:
                            export_result = await self._api_call(
                                "GET", 
                                "workspace/export",
                                params={"path": obj_path, "format": "SOURCE"}
                            )
                            content_b64 = export_result.get("content", "")
                            content = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                            
                            # Scan for secrets
                            for pattern, secret_type, severity, description in self.SECRET_PATTERNS:
                                matches = re.findall(pattern, content)
                                if matches:
                                    has_secrets = True
                                    secret_types.append(secret_type)
                                    
                                    findings.append({
                                        "finding_id": f"databricks-notebook-secret-{notebook_id}-{secret_type}",
                                        "severity": severity,
                                        "category": "secrets_exposure",
                                        "resource_type": "notebook",
                                        "resource_id": notebook_id,
                                        "resource_path": obj_path,
                                        "title": f"{description} in notebook",
                                        "description": f"Notebook '{obj_path}' contains {description.lower()}. "
                                                       f"Hardcoded secrets in notebooks can be exposed through version history, "
                                                       f"collaboration, or accidental commits.",
                                        "recommendation": "Use Databricks Secrets or environment variables instead of hardcoding credentials. "
                                                          "Rotate any exposed credentials immediately.",
                                    })
                        except Exception as e:
                            logger.debug(f"Could not export notebook {obj_path}: {e}")
                        
                        resource = {
                            "resource_type": "notebook",
                            "resource_id": notebook_id,
                            "resource_path": obj_path,
                            "name": obj_path.split("/")[-1],
                            "language": obj.get("language"),
                            "created_at": None,
                            "last_modified": None,
                            "has_secrets": has_secrets,
                            "metadata": {"secret_types": secret_types} if secret_types else None,
                        }
                        resources.append(resource)
                        
            except Exception as e:
                logger.debug(f"Failed to scan directory {path}: {e}")

        # Start scanning from root and common paths
        for start_path in ["/", "/Shared", "/Users"]:
            try:
                await scan_directory(start_path)
            except Exception:
                pass

        return resources, findings

    async def _scan_clusters(self) -> tuple[list, list]:
        """Scan clusters for security configurations."""
        resources = []
        findings = []

        try:
            result = await self._api_call("GET", "clusters/list")
            
            for cluster in result.get("clusters", []):
                cluster_id = cluster.get("cluster_id")
                is_running = cluster.get("state") in ("RUNNING", "PENDING", "RESIZING")
                
                resource = {
                    "resource_type": "cluster",
                    "resource_id": cluster_id,
                    "resource_path": None,
                    "name": cluster.get("cluster_name"),
                    "created_by": cluster.get("creator_user_name"),
                    "cluster_id": cluster_id,
                    "is_running": is_running,
                    "has_secrets": False,
                    "metadata": {
                        "node_type": cluster.get("node_type_id"),
                        "num_workers": cluster.get("num_workers"),
                        "autotermination_minutes": cluster.get("autotermination_minutes"),
                    },
                }
                resources.append(resource)

                # Check for security issues
                if not cluster.get("autotermination_minutes"):
                    findings.append({
                        "finding_id": f"databricks-cluster-noautoterminate-{cluster_id}",
                        "severity": "medium",
                        "category": "cost_optimization",
                        "resource_type": "cluster",
                        "resource_id": cluster_id,
                        "resource_path": None,
                        "title": f"Cluster {cluster.get('cluster_name')} has no auto-termination",
                        "description": "Running clusters without auto-termination can incur unnecessary costs and increase attack surface.",
                        "recommendation": "Enable auto-termination after a period of inactivity.",
                    })

        except Exception as e:
            logger.warning(f"Failed to scan clusters: {e}")

        return resources, findings

    async def _scan_secrets(self) -> tuple[list, list]:
        """Scan secret scopes for access issues."""
        resources = []
        findings = []

        try:
            result = await self._api_call("GET", "secrets/scopes/list")
            
            for scope in result.get("scopes", []):
                scope_name = scope.get("name")
                
                resource = {
                    "resource_type": "secret_scope",
                    "resource_id": scope_name,
                    "resource_path": f"/secrets/{scope_name}",
                    "name": scope_name,
                    "has_secrets": True,
                    "metadata": {
                        "backend_type": scope.get("backend_type"),
                    },
                }
                resources.append(resource)

                # Check scope ACLs
                try:
                    acl_result = await self._api_call("GET", "secrets/acls/list", params={"scope": scope_name})
                    for acl in acl_result.get("items", []):
                        if acl.get("principal") == "users" and acl.get("permission") in ("READ", "WRITE", "MANAGE"):
                            findings.append({
                                "finding_id": f"databricks-secret-wide-access-{scope_name}",
                                "severity": "high",
                                "category": "access_control",
                                "resource_type": "secret_scope",
                                "resource_id": scope_name,
                                "resource_path": f"/secrets/{scope_name}",
                                "title": f"Secret scope {scope_name} has wide access",
                                "description": "Secret scope is accessible to all users, which may expose sensitive credentials.",
                                "recommendation": "Restrict secret scope access to specific users or groups.",
                            })
                except Exception:
                    pass  # ACL listing may require additional permissions

        except Exception as e:
            logger.warning(f"Failed to scan secrets: {e}")

        return resources, findings

    # ── Test Data Seeding ─────────────────────────────────────────────────────

    async def seed_test_resources(self) -> dict[str, Any]:
        """
        Create test resources in Databricks workspace for security scanning demos.
        Creates notebooks with embedded secrets, clusters with misconfigs, etc.
        """
        created = []
        errors = []

        # 1. Create test notebooks with security issues
        test_notebooks = [
            {
                "path": "/Shared/HeliosTest/data_pipeline_with_secrets",
                "language": "PYTHON",
                "content": '''# Databricks notebook source
# MAGIC %md
# MAGIC # Data Pipeline - Production
# MAGIC This notebook processes customer data from S3.

# COMMAND ----------

# Configuration (DO NOT COMMIT THESE VALUES)
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"  # fake example — do not use
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-abc123xyz789secretkey"

# COMMAND ----------

import boto3

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# COMMAND ----------

# Process customer PII data
customer_ssns = ["123-45-6789", "987-65-4321"]
credit_cards = ["4111-1111-1111-1111", "5500-0000-0000-0004"]
'''
            },
            {
                "path": "/Shared/HeliosTest/ml_model_training",
                "language": "PYTHON",
                "content": '''# Databricks notebook source
# MAGIC %md
# MAGIC # ML Model Training - Customer Churn Prediction

# COMMAND ----------

# Azure credentials embedded (security issue!)
AZURE_STORAGE_KEY = "DefaultEndpointsProtocol=https;AccountName=proddata;AccountKey=abc123longkeyhere=="
OPENAI_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# COMMAND ----------

from pyspark.ml import Pipeline
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import RandomForestClassifier

# Load sensitive customer data without encryption
df = spark.read.parquet("/mnt/customer-pii-unencrypted/")

# COMMAND ----------

# Model exports to public location
model.save("/dbfs/mnt/public-bucket/models/churn_v1")
'''
            },
            {
                "path": "/Shared/HeliosTest/admin_utils",
                "language": "PYTHON",
                "content": '''# Databricks notebook source
# MAGIC %md
# MAGIC # Admin Utilities - Internal Use Only
# MAGIC Contains privileged operations

# COMMAND ----------

# Database admin credentials
DB_HOST = "prod-db.internal.company.com"
DB_USER = "admin"
DB_PASS = "Pr0dAdm1n!2024"

# Service account token
SERVICE_ACCOUNT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.secret"

# COMMAND ----------

# Disable audit logging (compliance violation)
spark.conf.set("spark.databricks.audit.enabled", "false")

# Run as root
%sh
sudo rm -rf /var/log/audit/*
'''
            },
            {
                "path": "/Users/shared/financial_reports",
                "language": "SQL",
                "content": '''-- Databricks notebook source
-- Financial Report Generator
-- Contains sensitive financial queries

-- COMMAND ----------

-- Query all customer financial data (unmasked)
SELECT 
    customer_id,
    full_name,
    ssn,
    account_number,
    balance,
    credit_score
FROM prod.customer_financials
WHERE balance > 100000;

-- COMMAND ----------

-- Export to external location (data exfiltration risk)
COPY INTO 's3://external-bucket/exports/'
FROM prod.customer_financials
FILEFORMAT = CSV;
'''
            },
        ]

        # First, ensure the /Shared/HeliosTest directory exists
        try:
            await self._api_call(
                "POST",
                "workspace/mkdirs",
                json={"path": "/Shared/HeliosTest"}
            )
            logger.info("Created /Shared/HeliosTest directory")
        except Exception as e:
            if "RESOURCE_ALREADY_EXISTS" not in str(e):
                logger.warning(f"Failed to create directory: {e}")
        
        for nb in test_notebooks:
            try:
                import base64
                content_b64 = base64.b64encode(nb["content"].encode()).decode()
                
                await self._api_call(
                    "POST",
                    "workspace/import",
                    json={
                        "path": nb["path"],
                        "language": nb["language"],
                        "content": content_b64,
                        "overwrite": True,
                        "format": "SOURCE",
                    }
                )
                created.append({"type": "notebook", "path": nb["path"]})
                logger.info(f"Created test notebook: {nb['path']}")
            except Exception as e:
                errors.append({"type": "notebook", "path": nb["path"], "error": str(e)})
                logger.warning(f"Failed to create notebook {nb['path']}: {e}")

        # 2. Create a secret scope with test secrets (if permissions allow)
        try:
            await self._api_call(
                "POST",
                "secrets/scopes/create",
                json={"scope": "helios-test-scope", "initial_manage_principal": "users"}
            )
            created.append({"type": "secret_scope", "name": "helios-test-scope"})
            
            # Add some test secrets
            test_secrets = [
                ("db-password", "SuperSecretPassword123!"),
                ("api-key", "sk-test-123456789"),
                ("aws-secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"),
            ]
            for key, value in test_secrets:
                try:
                    await self._api_call(
                        "POST",
                        "secrets/put",
                        json={"scope": "helios-test-scope", "key": key, "string_value": value}
                    )
                    created.append({"type": "secret", "scope": "helios-test-scope", "key": key})
                except Exception as e:
                    errors.append({"type": "secret", "key": key, "error": str(e)})
        except Exception as e:
            if "RESOURCE_ALREADY_EXISTS" in str(e):
                created.append({"type": "secret_scope", "name": "helios-test-scope", "note": "already exists"})
            else:
                errors.append({"type": "secret_scope", "error": str(e)})

        # 3. Try to create a small test cluster (may fail due to permissions/quotas)
        try:
            cluster_result = await self._api_call(
                "POST",
                "clusters/create",
                json={
                    "cluster_name": "helios-security-test",
                    "spark_version": "13.3.x-scala2.12",
                    "node_type_id": "Standard_DS3_v2",  # Azure
                    "num_workers": 0,  # Single node
                    "autotermination_minutes": 10,
                    "spark_conf": {
                        # Insecure configurations for testing
                        "spark.databricks.cluster.profile": "singleNode",
                    },
                }
            )
            created.append({"type": "cluster", "cluster_id": cluster_result.get("cluster_id")})
        except Exception as e:
            # Clusters often fail due to quotas - that's fine
            errors.append({"type": "cluster", "error": str(e), "note": "clusters may require quota"})

        return {
            "success": len(errors) == 0 or len(created) > 0,
            "created": created,
            "errors": errors,
            "message": f"Created {len(created)} test resources" + (f" with {len(errors)} errors" if errors else ""),
        }

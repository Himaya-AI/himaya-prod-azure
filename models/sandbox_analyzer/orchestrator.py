"""
Himaya Helios Sandbox Analyzer — MODEL-005
Dynamically executes suspicious links/attachments in isolated EC2 instances
and uses Claude AI to analyze the observed behavior.
"""
import asyncio
import boto3
import json
import time
import logging
import base64
import uuid
from typing import Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# AWS clients
EC2 = boto3.client("ec2", region_name="uaenorth")
SQS = boto3.client("sqs", region_name="uaenorth")
SSM = boto3.client("ssm", region_name="uaenorth")

# Config — populated at startup from aws-resources.json
SANDBOX_SUBNET = "subnet-0132e933e2bb6b657"
SANDBOX_SG = "sg-0a1bf773021a2d2c1"
SANDBOX_AMI = "ami-0cf2b4e024cdb73ee"  # Ubuntu 22.04 uaenorth
SANDBOX_INSTANCE_TYPE = "t3.small"
SANDBOX_KEY_NAME = "himaya-sandbox-key"
MAX_ANALYSIS_SECONDS = 300  # 5 minutes max per job
S3_SAMPLES_BUCKET = "himaya-evidence"


@dataclass
class SandboxJob:
    job_id: str
    org_id: str
    threat_id: str
    job_type: str       # "url" or "attachment"
    target: str         # URL or S3 key of attachment
    file_name: Optional[str] = None
    file_type: Optional[str] = None


@dataclass
class SandboxObservation:
    network_connections: list   # [(src_ip, dst_ip, dst_port, protocol)]
    dns_queries: list           # [domain]
    processes_spawned: list     # [(pid, name, cmd)]
    files_created: list         # [path]
    files_modified: list        # [path]
    files_deleted: list         # [path]
    http_requests: list         # [(method, url, status)]
    error_output: str
    raw_logs: str


@dataclass
class SandboxReport:
    job_id: str
    threat_id: str
    verdict: str                        # MALICIOUS, SUSPICIOUS, CLEAN, ERROR
    confidence: float                   # 0.0-1.0
    risk_score: int                     # 0-100
    threat_categories: list             # [str]
    iocs: dict                          # {ips: [], domains: [], files: [], urls: []}
    behavior_summary_en: str
    behavior_summary_ar: str
    mitre_techniques: list              # ["T1566.001", ...]
    network_activity: bool
    persistence_attempted: bool
    data_exfiltration_attempted: bool
    observations: dict
    analysis_duration_seconds: float
    ec2_instance_id: str
    analyzed_at: str


class SandboxOrchestrator:
    """
    Orchestrates sandbox VM lifecycle and AI analysis.
    """

    def __init__(self):
        self._load_infra_config()

    def _load_infra_config(self):
        """Load sandbox infrastructure IDs from saved config"""
        try:
            with open("/home/adnan-ahmed/.openclaw/workspace/himaya/infra/aws-resources.json") as f:
                data = json.load(f)
            sandbox = data.get("sandbox", {})
            global SANDBOX_SUBNET, SANDBOX_SG
            if sandbox.get("subnet_id") and not sandbox["subnet_id"].startswith("$"):
                SANDBOX_SUBNET = sandbox["subnet_id"]
            if sandbox.get("sandbox_sg") and not sandbox["sandbox_sg"].startswith("$"):
                SANDBOX_SG = sandbox["sandbox_sg"]
        except Exception as e:
            logger.warning(f"Could not load infra config: {e}")

    async def analyze(self, job: SandboxJob) -> SandboxReport:
        """
        Main entry point. Spins up EC2, runs analysis, terminates, returns report.
        """
        start_time = time.time()
        instance_id = None

        try:
            logger.info(f"[Sandbox] Starting analysis for job {job.job_id}, target: {job.target[:80]}")

            # 1. Launch sandbox EC2
            instance_id = await self._launch_sandbox_instance(job)
            logger.info(f"[Sandbox] Instance {instance_id} launched")

            # 2. Wait for instance to be ready
            await self._wait_for_instance_ready(instance_id)

            # 3. Execute target in sandbox
            observations = await self._execute_and_observe(instance_id, job)

            # 4. AI analysis of observations
            report = await self._ai_analyze(job, observations, instance_id, time.time() - start_time)

            return report

        except Exception as e:
            logger.error(f"[Sandbox] Analysis failed for {job.job_id}: {e}")
            return SandboxReport(
                job_id=job.job_id,
                threat_id=job.threat_id,
                verdict="ERROR",
                confidence=0.0,
                risk_score=0,
                threat_categories=[],
                iocs={"ips": [], "domains": [], "files": [], "urls": []},
                behavior_summary_en=f"Sandbox analysis failed: {str(e)}",
                behavior_summary_ar="فشل تحليل الصندوق الرملي",
                mitre_techniques=[],
                network_activity=False,
                persistence_attempted=False,
                data_exfiltration_attempted=False,
                observations={},
                analysis_duration_seconds=time.time() - start_time,
                ec2_instance_id=instance_id or "none",
                analyzed_at=datetime.utcnow().isoformat()
            )
        finally:
            # ALWAYS terminate the sandbox instance
            if instance_id:
                await self._terminate_instance(instance_id)
                logger.info(f"[Sandbox] Instance {instance_id} terminated")

    async def _launch_sandbox_instance(self, job: SandboxJob) -> str:
        """Launch an isolated EC2 sandbox instance"""

        user_data_script = """#!/bin/bash
# Himaya Helios Sandbox Init Script
apt-get update -qq
apt-get install -y -qq tcpdump strace inotify-tools curl wget python3 python3-pip netcat-openbsd tshark 2>/dev/null

# Start network capture immediately
mkdir -p /sandbox/logs
tcpdump -i any -w /sandbox/logs/network.pcap &
echo $! > /sandbox/tcpdump.pid

# Start filesystem monitor
inotifywait -m -r --format '%T %w%f %e' --timefmt '%H:%M:%S' \
  /tmp /home /var/tmp /root \
  > /sandbox/logs/fs_changes.log 2>/dev/null &
echo $! > /sandbox/inotify.pid

# Create analysis script
cat > /sandbox/run_analysis.sh << 'ANALYSIS'
#!/bin/bash
TARGET="$1"
JOB_TYPE="$2"
LOG_DIR="/sandbox/logs"
mkdir -p $LOG_DIR

echo "=== Himaya Sandbox Analysis ===" > $LOG_DIR/analysis.log
echo "Target: $TARGET" >> $LOG_DIR/analysis.log
echo "Type: $JOB_TYPE" >> $LOG_DIR/analysis.log
echo "Started: $(date -u)" >> $LOG_DIR/analysis.log
echo "" >> $LOG_DIR/analysis.log

# Capture process tree before
ps auxf > $LOG_DIR/processes_before.txt

if [ "$JOB_TYPE" = "url" ]; then
    echo "=== URL ANALYSIS ===" >> $LOG_DIR/analysis.log

    # DNS resolution
    echo "--- DNS ---" >> $LOG_DIR/analysis.log
    host $(echo $TARGET | sed 's|https\\?://||' | cut -d'/' -f1) >> $LOG_DIR/analysis.log 2>&1

    # Fetch with full redirect chain + headers
    echo "--- HTTP Request ---" >> $LOG_DIR/analysis.log
    curl -L -v --max-time 30 --max-redirs 10 \
      -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -o /sandbox/logs/response_body.html \
      "$TARGET" >> $LOG_DIR/analysis.log 2>&1

    # Check for malicious patterns in response
    echo "--- Response Analysis ---" >> $LOG_DIR/analysis.log
    grep -i "powershell\\|cmd.exe\\|base64\\|eval(\\|document.write\\|fromCharCode\\|<script" \
      /sandbox/logs/response_body.html >> $LOG_DIR/analysis.log 2>&1 || true

    # Check downloaded content type
    file /sandbox/logs/response_body.html >> $LOG_DIR/analysis.log 2>&1

elif [ "$JOB_TYPE" = "attachment" ]; then
    echo "=== ATTACHMENT ANALYSIS ===" >> $LOG_DIR/analysis.log
    FILEPATH="$TARGET"

    # File metadata
    file "$FILEPATH" >> $LOG_DIR/analysis.log 2>&1
    xxd "$FILEPATH" | head -50 >> $LOG_DIR/analysis.log 2>&1

    # Check for macros in Office files
    if echo "$FILEPATH" | grep -qi "\\.doc\\|\\.xls\\|\\.ppt"; then
        strings "$FILEPATH" | grep -i "auto\\|macro\\|shell\\|powershell\\|cmd\\|exec" \
          >> $LOG_DIR/analysis.log 2>&1 || true
    fi

    # Check for embedded URLs in PDFs
    if echo "$FILEPATH" | grep -qi "\\.pdf"; then
        strings "$FILEPATH" | grep -i "http\\|https\\|javascript" \
          >> $LOG_DIR/analysis.log 2>&1 || true
    fi
fi

# Capture process tree after
ps auxf > $LOG_DIR/processes_after.txt
diff $LOG_DIR/processes_before.txt $LOG_DIR/processes_after.txt > $LOG_DIR/process_diff.txt 2>/dev/null || true

# Network connections made
netstat -an > $LOG_DIR/network_connections.txt 2>/dev/null || ss -an > $LOG_DIR/network_connections.txt 2>/dev/null

echo "Analysis complete: $(date -u)" >> $LOG_DIR/analysis.log
ANALYSIS
chmod +x /sandbox/run_analysis.sh
echo "SANDBOX_READY" > /tmp/sandbox_status
"""

        user_data = base64.b64encode(user_data_script.encode()).decode()

        response = EC2.run_instances(
            ImageId=SANDBOX_AMI,
            InstanceType=SANDBOX_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            KeyName=SANDBOX_KEY_NAME,
            SubnetId=SANDBOX_SUBNET,
            SecurityGroupIds=[SANDBOX_SG],
            UserData=user_data,
            InstanceInitiatedShutdownBehavior="terminate",
            IamInstanceProfile={"Name": "himaya-sandbox-ssm-profile"},
            BlockDeviceMappings=[{
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "VolumeSize": 8,
                    "VolumeType": "gp2",
                    "DeleteOnTermination": True,
                    "Encrypted": True
                }
            }],
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": f"himaya-sandbox-{job.job_id[:8]}"},
                    {"Key": "Project", "Value": "himaya-helios"},
                    {"Key": "Purpose", "Value": "sandbox-analysis"},
                    {"Key": "JobId", "Value": job.job_id},
                    {"Key": "AutoTerminate", "Value": "true"}
                ]
            }],
            MetadataOptions={
                "HttpTokens": "required",
                "HttpEndpoint": "enabled"
            }
        )

        return response["Instances"][0]["InstanceId"]

    async def _wait_for_instance_ready(self, instance_id: str, timeout: int = 120):
        """Wait for EC2 instance to pass status checks"""
        waiter = EC2.get_waiter("instance_status_ok")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 10, "MaxAttempts": 12}
            )
        )
        # Extra wait for user data script to complete
        await asyncio.sleep(30)

    async def _execute_and_observe(self, instance_id: str, job: SandboxJob) -> SandboxObservation:
        """Execute target in sandbox and collect observations via SSM Run Command"""

        commands = []

        if job.job_type == "url":
            commands = [
                f"bash /sandbox/run_analysis.sh '{job.target}' url",
                "sleep 15",  # Let network activity settle
                "cat /sandbox/logs/analysis.log",
                "cat /sandbox/logs/network_connections.txt 2>/dev/null || echo 'no network log'",
                "cat /sandbox/logs/fs_changes.log 2>/dev/null | head -100 || echo 'no fs log'",
                "cat /sandbox/logs/process_diff.txt 2>/dev/null | head -50 || echo 'no process diff'",
            ]
        elif job.job_type == "attachment":
            commands = [
                f"echo '{job.target}' | base64 -d > /sandbox/sample_file",
                "bash /sandbox/run_analysis.sh /sandbox/sample_file attachment",
                "cat /sandbox/logs/analysis.log",
                "cat /sandbox/logs/fs_changes.log 2>/dev/null | head -100 || echo 'no fs log'",
            ]

        loop = asyncio.get_event_loop()
        raw_output = []

        for cmd in commands:
            try:
                response = await loop.run_in_executor(None, lambda c=cmd: SSM.send_command(
                    InstanceIds=[instance_id],
                    DocumentName="AWS-RunShellScript",
                    Parameters={"commands": [c]},
                    TimeoutSeconds=60
                ))
                cmd_id = response["Command"]["CommandId"]

                await asyncio.sleep(5)

                for _ in range(12):
                    try:
                        result = await loop.run_in_executor(None, lambda cid=cmd_id: SSM.get_command_invocation(
                            CommandId=cid,
                            InstanceId=instance_id
                        ))
                        if result["Status"] in ("Success", "Failed", "TimedOut"):
                            raw_output.append(result.get("StandardOutputContent", ""))
                            raw_output.append(result.get("StandardErrorContent", ""))
                            break
                    except Exception:
                        pass
                    await asyncio.sleep(5)
            except Exception as e:
                logger.warning(f"[Sandbox] Command failed: {e}")
                raw_output.append(f"Command error: {e}")

        full_output = "\n".join(raw_output)
        return self._parse_observations(full_output)

    def _parse_observations(self, raw_output: str) -> SandboxObservation:
        """Parse raw log output into structured observations"""
        import re

        # Extract network connections
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)')
        connections = [(m.group(1), m.group(2)) for m in ip_pattern.finditer(raw_output)]

        # Extract DNS queries
        dns_pattern = re.compile(r'(?:host|nslookup|DNS)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
        dns_queries = list(set(m.group(1) for m in dns_pattern.finditer(raw_output)))

        # Extract HTTP URLs
        url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)
        urls = list(set(url_pattern.findall(raw_output)))

        # Extract processes
        proc_pattern = re.compile(r'(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)')
        processes = [(m.group(1), m.group(2)[:80]) for m in proc_pattern.finditer(raw_output)][:20]

        # File changes
        file_created = re.findall(r'(\S+)\s+CREATE', raw_output)
        file_modified = re.findall(r'(\S+)\s+MODIFY', raw_output)
        file_deleted = re.findall(r'(\S+)\s+DELETE', raw_output)

        return SandboxObservation(
            network_connections=[(c[0], c[1]) for c in connections[:20]],
            dns_queries=dns_queries[:20],
            processes_spawned=[(p[0], p[1], "") for p in processes],
            files_created=file_created[:20],
            files_modified=file_modified[:20],
            files_deleted=file_deleted[:20],
            http_requests=[(u, "observed") for u in urls[:10]],
            error_output="",
            raw_logs=raw_output[:5000]  # Truncate for AI context
        )

    async def _ai_analyze(self, job: SandboxJob, obs: SandboxObservation,
                          instance_id: str, duration: float) -> SandboxReport:
        """Use Claude to analyze sandbox observations and produce verdict"""
        import anthropic
        import os

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        prompt = f"""You are a malware analyst at Himaya Helios analyzing sandbox execution results from an isolated EC2 environment.

## Sandbox Job Details
- Job Type: {job.job_type}
- Target: {job.target[:200]}
- File Name: {job.file_name or 'N/A'}

## Observations from Sandbox Execution

### Network Connections Made:
{json.dumps(obs.network_connections[:15], indent=2)}

### DNS Queries:
{json.dumps(obs.dns_queries[:15], indent=2)}

### Processes Spawned:
{json.dumps(obs.processes_spawned[:15], indent=2)}

### Files Created:
{json.dumps(obs.files_created[:15], indent=2)}

### Files Modified:
{json.dumps(obs.files_modified[:10], indent=2)}

### HTTP Requests Made:
{json.dumps(obs.http_requests[:10], indent=2)}

### Raw Execution Log (truncated):
{obs.raw_logs[:3000]}

## Analysis Task

Based on these sandbox observations, provide a comprehensive threat analysis. Consider:
1. Did the URL/attachment attempt to download additional payloads?
2. Were there suspicious network connections (C2, unusual ports, geo-suspicious IPs)?
3. Did it attempt to create persistence (cron, startup files)?
4. Were there signs of data collection or exfiltration?
5. Did it spawn suspicious child processes?
6. Any signs of Gulf-region targeting (Arabic lures, local bank impersonation, government domains)?

Respond with ONLY valid JSON (no markdown, no explanation):
{{
  "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|INCONCLUSIVE",
  "confidence": 0.0,
  "risk_score": 0,
  "threat_categories": ["CLEAN"],
  "iocs": {{
    "ips": [],
    "domains": [],
    "files": [],
    "urls": []
  }},
  "behavior_summary_en": "Summary of observed behavior",
  "behavior_summary_ar": "ملخص السلوك المرصود",
  "mitre_techniques": [],
  "network_activity": false,
  "persistence_attempted": false,
  "data_exfiltration_attempted": false,
  "key_findings": []
}}"""

        try:
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1500,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )

            analysis = json.loads(response.content[0].text)

            return SandboxReport(
                job_id=job.job_id,
                threat_id=job.threat_id,
                verdict=analysis["verdict"],
                confidence=analysis["confidence"],
                risk_score=analysis["risk_score"],
                threat_categories=analysis["threat_categories"],
                iocs=analysis["iocs"],
                behavior_summary_en=analysis["behavior_summary_en"],
                behavior_summary_ar=analysis["behavior_summary_ar"],
                mitre_techniques=analysis["mitre_techniques"],
                network_activity=analysis["network_activity"],
                persistence_attempted=analysis["persistence_attempted"],
                data_exfiltration_attempted=analysis["data_exfiltration_attempted"],
                observations=asdict(obs),
                analysis_duration_seconds=duration,
                ec2_instance_id=instance_id,
                analyzed_at=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            # Rule-based fallback
            is_suspicious = bool(obs.network_connections) or bool(obs.files_created)
            return SandboxReport(
                job_id=job.job_id,
                threat_id=job.threat_id,
                verdict="SUSPICIOUS" if is_suspicious else "INCONCLUSIVE",
                confidence=0.4,
                risk_score=50 if is_suspicious else 20,
                threat_categories=["UNKNOWN"],
                iocs={
                    "ips": [c[0] for c in obs.network_connections],
                    "domains": obs.dns_queries,
                    "files": obs.files_created,
                    "urls": []
                },
                behavior_summary_en=f"Sandbox observed {len(obs.network_connections)} network connections and {len(obs.files_created)} file creations. AI analysis unavailable.",
                behavior_summary_ar="لاحظ الصندوق الرملي نشاطاً شبكياً. تحليل الذكاء الاصطناعي غير متاح.",
                mitre_techniques=[],
                network_activity=bool(obs.network_connections),
                persistence_attempted=False,
                data_exfiltration_attempted=False,
                observations=asdict(obs),
                analysis_duration_seconds=duration,
                ec2_instance_id=instance_id,
                analyzed_at=datetime.utcnow().isoformat()
            )

    async def _terminate_instance(self, instance_id: str):
        """Terminate sandbox EC2 instance — always called in finally block"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: EC2.terminate_instances(InstanceIds=[instance_id])
            )
        except Exception as e:
            logger.error(f"Failed to terminate {instance_id}: {e} — MANUAL CLEANUP REQUIRED")

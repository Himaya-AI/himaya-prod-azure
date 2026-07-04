"""
Neo4j management — SSH-based remote control from within ECS.
Admin-key protected. Uses paramiko to SSH into the Neo4j EC2 and run commands.
"""
import asyncio
import base64
import logging
import os
import tempfile
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from backend.routers.admin import verify_admin_key

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin/neo4j", tags=["neo4j-mgmt"])

NEO4J_HOST = os.environ.get("NEO4J_HOST", "10.0.3.166")
NEO4J_SSH_USER = os.environ.get("NEO4J_SSH_USER", "ec2-user")
NEO4J_SSH_KEY_B64 = os.environ.get("NEO4J_SSH_KEY_B64", "")


async def _ssh_run(cmd: str, timeout: int = 30) -> dict:
    """Run a command on the Neo4j EC2 via SSH using paramiko."""
    if not NEO4J_SSH_KEY_B64:
        return {"error": "NEO4J_SSH_KEY_B64 not set in env"}
    try:
        import paramiko, io
        key_bytes = base64.b64decode(NEO4J_SSH_KEY_B64)
        pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(key_bytes.decode()))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: client.connect(
            hostname=NEO4J_HOST,
            username=NEO4J_SSH_USER,
            pkey=pkey,
            timeout=15,
            banner_timeout=15,
        ))
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()
        return {"stdout": out, "stderr": err, "exit_code": exit_code}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@router.get("/status", dependencies=[Depends(verify_admin_key)])
async def neo4j_status():
    """Check Neo4j service status on EC2."""
    result = await _ssh_run(
        "sudo systemctl status neo4j --no-pager 2>&1 | head -20; "
        "echo '---'; ss -tlnp | grep -E '7687|7474' || echo 'BOLT NOT LISTENING'; "
        "echo '---'; sudo journalctl -u neo4j -n 15 --no-pager 2>/dev/null"
    )
    return result


@router.post("/start", dependencies=[Depends(verify_admin_key)])
async def neo4j_start():
    """Start Neo4j service on EC2."""
    result = await _ssh_run(
        "sudo chown -R neo4j:neo4j /var/lib/neo4j /var/log/neo4j 2>/dev/null; "
        "sudo systemctl start neo4j; "
        "sleep 20; "
        "sudo systemctl status neo4j --no-pager | head -15; "
        "ss -tlnp | grep 7687 && echo 'BOLT OK' || echo 'BOLT STILL DOWN'; "
        "sudo journalctl -u neo4j -n 20 --no-pager 2>/dev/null",
        timeout=60
    )
    return result


@router.post("/restart", dependencies=[Depends(verify_admin_key)])
async def neo4j_restart():
    """Restart Neo4j service."""
    result = await _ssh_run(
        "sudo systemctl restart neo4j; sleep 20; "
        "sudo systemctl status neo4j --no-pager | head -10; "
        "ss -tlnp | grep 7687 && echo 'BOLT OK' || echo 'BOLT STILL DOWN'",
        timeout=60
    )
    return result


@router.get("/logs", dependencies=[Depends(verify_admin_key)])
async def neo4j_logs():
    """Get neo4j service logs."""
    result = await _ssh_run("sudo journalctl -u neo4j -n 50 --no-pager 2>/dev/null", timeout=15)
    return result


@router.post("/reinit", dependencies=[Depends(verify_admin_key)])
async def neo4j_reinit():
    """Full neo4j reinstall/reinit if service is broken."""
    result = await _ssh_run(
        "sudo systemctl stop neo4j 2>/dev/null; "
        "sudo rm -rf /var/lib/neo4j/data/transactions /var/lib/neo4j/data/databases/system/neostore.transaction* 2>/dev/null; "
        "sudo chown -R neo4j:neo4j /var/lib/neo4j /var/log/neo4j; "
        "sudo systemctl start neo4j; sleep 25; "
        "sudo systemctl status neo4j --no-pager | head -10; "
        "ss -tlnp | grep 7687 && echo 'BOLT OK' || echo 'STILL DOWN'",
        timeout=90
    )
    return result


_install_log: list = []
_install_running: bool = False


async def _run_install_bg():
    """Run Neo4j install in background, storing output in _install_log."""
    global _install_running, _install_log
    _install_running = True
    _install_log = ["Starting Neo4j install..."]
    try:
        result = await _ssh_run(
            "sudo dnf install -y java-17-amazon-corretto 2>&1 | tail -3; "
            "sudo rpm --import https://debian.neo4j.com/neotechnology.gpg.key 2>/dev/null; "
            "sudo bash -c 'cat > /etc/yum.repos.d/neo4j.repo << EOF\n[neo4j]\nname=Neo4j RPM Repository\nbaseurl=https://yum.neo4j.com/stable/5\nenabled=1\ngpgcheck=1\nEOF'; "
            "sudo dnf install -y neo4j 2>&1 | tail -5; "
            "sudo sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo sed -i 's/#server.bolt.listen_address=:7687/server.bolt.listen_address=0.0.0.0:7687/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo sed -i 's/#server.http.listen_address=:7474/server.http.listen_address=0.0.0.0:7474/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo neo4j-admin dbms set-initial-password 'HeliosGraph2026!' 2>/dev/null || true; "
            "echo 'server.memory.heap.initial_size=1g' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "echo 'server.memory.heap.max_size=2g' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "echo 'server.memory.pagecache.size=512m' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "sudo systemctl enable neo4j; "
            "sudo systemctl start neo4j; "
            "sleep 30; "
            "sudo systemctl status neo4j --no-pager | head -10; "
            "ss -tlnp | grep 7687 && echo 'BOLT OK' || echo 'BOLT STILL DOWN'; "
            "sudo journalctl -u neo4j -n 20 --no-pager 2>/dev/null",
            timeout=240
        )
        _install_log = [result.get("stdout", ""), result.get("stderr", ""), f"exit={result.get('exit_code')}", result.get("error", "")]
    except Exception as e:
        _install_log = [f"Exception: {e}"]
    finally:
        _install_running = False


@router.post("/install", dependencies=[Depends(verify_admin_key)])
async def neo4j_install():
    """Install Neo4j on the EC2 (runs in background — poll /install-status)."""
    global _install_running
    if _install_running:
        return {"status": "already_running", "message": "Install already in progress, check /install-status"}
    asyncio.create_task(_run_install_bg())
    return {"status": "started", "message": "Install started in background. Poll /api/admin/neo4j/install-status for results."}


@router.get("/install-status", dependencies=[Depends(verify_admin_key)])
async def neo4j_install_status():
    """Check background install progress."""
    return {"running": _install_running, "log": _install_log}


@router.post("/install-step/{step}", dependencies=[Depends(verify_admin_key)])
async def neo4j_install_step(step: str):
    """Run a specific install step. Steps: java, repo, neo4j, configure, start, check"""
    cmds = {
        "ps": "ps aux | head -30; echo '---'; df -h; free -h",
        "internet": "curl -s --max-time 10 https://www.google.com -o /dev/null && echo 'INTERNET OK' || echo 'NO INTERNET'; curl -s --max-time 10 https://yum.neo4j.com/ -o /dev/null -w '%{http_code}' && echo ' NEO4J_REPO_OK' || echo ' NEO4J_REPO_FAIL'",
        "nohup-log": "cat /tmp/nohup.out 2>/dev/null | tail -20 || echo 'no nohup.out'; ls -la /tmp/*.log 2>/dev/null",
        "java-check": "java -version 2>&1 || echo 'java not installed'; which java 2>/dev/null || echo 'no java'",
        "java": "sudo dnf install -y java-17-amazon-corretto 2>&1; echo 'java done'",
        "repo": "sudo rpm --import https://debian.neo4j.com/neotechnology.gpg.key 2>/dev/null; sudo bash -c 'printf \"[neo4j]\nname=Neo4j RPM Repository\nbaseurl=https://yum.neo4j.com/stable/5\nenabled=1\ngpgcheck=1\n\" > /etc/yum.repos.d/neo4j.repo'; echo 'repo done'",
        "neo4j": "sudo dnf install -y neo4j 2>&1 | tail -10; echo 'neo4j done'",
        "configure": (
            "sudo sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo sed -i 's/#server.bolt.listen_address=:7687/server.bolt.listen_address=0.0.0.0:7687/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo sed -i 's/#server.http.listen_address=:7474/server.http.listen_address=0.0.0.0:7474/' /etc/neo4j/neo4j.conf 2>/dev/null; "
            "sudo neo4j-admin dbms set-initial-password 'HeliosGraph2026!' 2>/dev/null || true; "
            "sudo grep -q 'heap.initial' /etc/neo4j/neo4j.conf || echo 'server.memory.heap.initial_size=1g' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "sudo grep -q 'heap.max' /etc/neo4j/neo4j.conf || echo 'server.memory.heap.max_size=2g' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "sudo grep -q 'pagecache' /etc/neo4j/neo4j.conf || echo 'server.memory.pagecache.size=512m' | sudo tee -a /etc/neo4j/neo4j.conf > /dev/null; "
            "echo 'configure done'"
        ),
        "start": "sudo systemctl enable neo4j; sudo systemctl start neo4j; sleep 20; sudo systemctl status neo4j --no-pager | head -10",
        "check": "ss -tlnp | grep 7687 && echo 'BOLT OK' || echo 'BOLT NOT LISTENING'; sudo journalctl -u neo4j -n 10 --no-pager 2>/dev/null",
        "backfill-sender-props": (
            # Backfill email_count, threat_count, reputation_score from existing relationships
            "cypher-shell -u neo4j -p 'HeliosGraph2026!' --format plain "
            "'MATCH (s:Sender) "
            "OPTIONAL MATCH (s)-[:SENT_TO]->() "
            "WITH s, count(*) AS email_count "
            "OPTIONAL MATCH (s)-[:FLAGGED_AS]->() "
            "WITH s, email_count, count(*) AS threat_count "
            "SET s.email_count = email_count, "
            "    s.threat_count = threat_count, "
            "    s.reputation_score = CASE WHEN email_count = 0 THEN 0 "
            "        ELSE toInteger(100.0 * threat_count / email_count) END, "
            "    s.first_seen = coalesce(s.first_seen, datetime()), "
            "    s.last_seen  = coalesce(s.last_seen,  datetime()) "
            "RETURN s.email AS email, s.email_count AS emails, s.threat_count AS threats, s.reputation_score AS rep_score "
            "ORDER BY threats DESC;' 2>&1"
        ),
        "graph-stats": (
            "cypher-shell -u neo4j -p 'HeliosGraph2026!' --format plain "
            "'MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC;' 2>&1; "
            "echo '---'; "
            "cypher-shell -u neo4j -p 'HeliosGraph2026!' --format plain "
            "'MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS cnt ORDER BY cnt DESC;' 2>&1; "
            "echo '---'; "
            "cypher-shell -u neo4j -p 'HeliosGraph2026!' --format plain "
            "'MATCH (s:Sender) RETURN s.email, s.reputation_score, s.threat_count ORDER BY s.threat_count DESC LIMIT 15;' 2>&1"
        ),
        "nohup-install": (
            "nohup bash -c '"
            "sudo dnf install -y java-17-amazon-corretto > /tmp/neo4j-install.log 2>&1; "
            "sudo rpm --import https://debian.neo4j.com/neotechnology.gpg.key >> /tmp/neo4j-install.log 2>&1; "
            r'printf "[neo4j]\nname=Neo4j RPM Repository\nbaseurl=https://yum.neo4j.com/stable/5\nenabled=1\ngpgcheck=1\n" | sudo tee /etc/yum.repos.d/neo4j.repo >> /tmp/neo4j-install.log 2>&1; '
            "sudo dnf install -y neo4j >> /tmp/neo4j-install.log 2>&1; "
            "sudo sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' /etc/neo4j/neo4j.conf; "
            "sudo sed -i 's/#server.bolt.listen_address=:7687/server.bolt.listen_address=0.0.0.0:7687/' /etc/neo4j/neo4j.conf; "
            "sudo sed -i 's/#server.http.listen_address=:7474/server.http.listen_address=0.0.0.0:7474/' /etc/neo4j/neo4j.conf; "
            "sudo neo4j-admin dbms set-initial-password HeliosGraph2026! >> /tmp/neo4j-install.log 2>&1 || true; "
            "echo server.memory.heap.initial_size=1g | sudo tee -a /etc/neo4j/neo4j.conf; "
            "echo server.memory.heap.max_size=2g | sudo tee -a /etc/neo4j/neo4j.conf; "
            "echo server.memory.pagecache.size=512m | sudo tee -a /etc/neo4j/neo4j.conf; "
            "sudo systemctl enable neo4j; sudo systemctl start neo4j; "
            "echo INSTALL_DONE >> /tmp/neo4j-install.log"
            "' > /tmp/nohup.out 2>&1 &"
            "echo 'nohup install started, PID='$!; sleep 2; echo 'background running'"
        ),
        "install-log": "cat /tmp/neo4j-install.log 2>/dev/null | tail -30 || echo 'no log yet'",
    }
    if step not in cmds:
        raise HTTPException(status_code=400, detail=f"Unknown step. Valid: {list(cmds.keys())}")
    timeout = 120 if step in ("java", "neo4j", "nohup-install") else 40
    return await _ssh_run(cmds[step], timeout=timeout)


@router.post("/kill-dnf-locks", dependencies=[Depends(verify_admin_key)])
async def kill_dnf_locks():
    """Kill ALL blocking dnf/rpm processes and remove locks."""
    return await _ssh_run(
        "sudo pkill -9 -f 'dnf install' 2>/dev/null || true; "
        "sudo pkill -9 -f 'rpm' 2>/dev/null || true; "
        "sudo rm -f /var/run/dnf.pid /var/cache/dnf/metadata_lock.pid /var/lib/rpm/.rpm.lock 2>/dev/null; "
        "sleep 2; "
        "ps aux | grep -E 'dnf|rpm' | grep -v grep || echo 'no dnf/rpm running'; "
        "echo 'locks cleared'",
        timeout=20
    )


@router.get("/export", dependencies=[Depends(verify_admin_key)])
async def neo4j_export():
    """
    Export ALL Neo4j data (nodes + relationships) in JSON format.
    Returns complete graph data for offline analysis or Excel conversion.
    """
    from backend.services.graph_service import graph_service
    
    if not graph_service._driver:
        raise HTTPException(status_code=503, detail="Neo4j not connected")
    
    try:
        async with graph_service._driver.session() as session:
            # Get all node labels and their counts
            labels_result = await session.run("CALL db.labels()")
            labels = [r["label"] async for r in labels_result]
            
            export_data = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "stats": {},
                "nodes": {},
                "relationships": []
            }
            
            # Export all nodes by label
            for label in labels:
                query = f"""
                MATCH (n:{label})
                RETURN 
                    ID(n) as id,
                    labels(n) as labels,
                    properties(n) as props
                """
                result = await session.run(query)
                nodes = []
                async for record in result:
                    nodes.append({
                        "id": record["id"],
                        "labels": record["labels"],
                        "properties": dict(record["props"]) if record["props"] else {}
                    })
                export_data["nodes"][label] = nodes
                export_data["stats"][f"nodes_{label}"] = len(nodes)
            
            # Export all relationships
            rel_query = """
            MATCH (a)-[r]->(b)
            RETURN 
                ID(a) as source_id,
                labels(a) as source_labels,
                COALESCE(a.email, a.name, a.domain, a.type, toString(ID(a))) as source_name,
                type(r) as rel_type,
                properties(r) as rel_props,
                ID(b) as target_id,
                labels(b) as target_labels,
                COALESCE(b.email, b.name, b.domain, b.type, toString(ID(b))) as target_name
            """
            rel_result = await session.run(rel_query)
            rels = []
            async for record in rel_result:
                rels.append({
                    "source_id": record["source_id"],
                    "source_labels": record["source_labels"],
                    "source_name": record["source_name"],
                    "rel_type": record["rel_type"],
                    "rel_props": dict(record["rel_props"]) if record["rel_props"] else {},
                    "target_id": record["target_id"],
                    "target_labels": record["target_labels"],
                    "target_name": record["target_name"]
                })
            export_data["relationships"] = rels
            export_data["stats"]["total_relationships"] = len(rels)
            
            # Get relationship type counts
            rel_types_result = await session.run("CALL db.relationshipTypes()")
            async for record in rel_types_result:
                rel_type = record["relationshipType"]
                count_result = await session.run(
                    f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as cnt"
                )
                count_rec = await count_result.single()
                export_data["stats"][f"rels_{rel_type}"] = count_rec["cnt"] if count_rec else 0
            
            return export_data
            
    except Exception as e:
        logger.error(f"Neo4j export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {e}")

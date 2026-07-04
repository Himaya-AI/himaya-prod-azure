"""
AWS content sampler for the Himaya Data Posture agent.

Until 2026-06-23 the AWS classifier prompt only ever saw resource
metadata (encryption flags, tags, region, name). That made every S3 /
EBS / RDS classification a *naming heuristic at scale* — fine for
"backup-bucket" but useless for a bucket called "data-prod-2024" that
actually stores customer KYC PDFs.

This module reaches into the resource itself and pulls a small
representative sample so the LLM can reason about real content:

  - S3:    HEAD up to N objects, then GET the first ~8 KB of the first
           K text-ish ones (size cap, mime allowlist).
  - EBS:   describe-volume + describe-snapshots; pull tags + attached
           instance tags. (We don't mount EBS — that requires a worker
           node — but we sample its surrounding metadata heavily.)
  - RDS:   describe-db-instance + describe-db-parameters + tags.
  - DynamoDB / EFS: name + tag + size sample.

Returns a `content_sample` string suitable for inclusion in the
classifier prompt. Caller is responsible for caching / per-cycle limits.

Adnan 2026-06-23: also returns a `data_excerpts` list of (key, snippet)
so the UI can render "we looked at these 5 files in this bucket".
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Sampling caps — keep token bill bounded.
S3_MAX_KEYS = 25            # head_object up to 25 keys
S3_MAX_BODY_OBJECTS = 8     # actually download body for up to 8 keys
S3_MAX_BYTES_PER_OBJECT = 8 * 1024  # 8 KB per object
S3_MAX_TOTAL_SAMPLE = 32 * 1024     # 32 KB total prompt budget per resource

_TEXTISH_PREFIXES = (
    "text/", "application/json", "application/xml", "application/x-yaml",
    "application/x-ndjson", "application/csv", "application/x-www-form",
)

_TEXTISH_EXTS = (
    ".txt", ".log", ".csv", ".tsv", ".json", ".ndjson", ".jsonl",
    ".yml", ".yaml", ".xml", ".html", ".htm", ".md", ".sql", ".env",
    ".conf", ".ini", ".properties", ".tf", ".tfvars", ".py", ".js",
    ".ts", ".tsx", ".jsx", ".java", ".cs", ".go", ".rs", ".rb", ".php",
)


def _looks_textish(key: str, content_type: str | None) -> bool:
    if content_type:
        ct = content_type.lower()
        if any(ct.startswith(p) for p in _TEXTISH_PREFIXES):
            return True
    kl = (key or "").lower()
    return kl.endswith(_TEXTISH_EXTS)


def sample_s3_bucket(s3_client, bucket: str) -> dict[str, Any]:
    """Return a sample dict for one S3 bucket.

    Shape:
      {
        "object_count_seen": int,
        "total_size_seen_bytes": int,
        "extensions_seen": [".csv", ".json", ...],
        "content_types_seen": ["text/csv", ...],
        "data_excerpts": [{"key": "...", "snippet": "...", "bytes": N}],
        "content_sample": "<<KEY: foo.csv>>\\n<first 2KB>\\n\\n<<KEY: bar.json>>\\n..."
      }

    All Boto exceptions are swallowed — sampling is best-effort.
    Caller passes a boto3 s3 client already scoped to credentials/region.
    """
    out: dict[str, Any] = {
        "object_count_seen": 0,
        "total_size_seen_bytes": 0,
        "extensions_seen": [],
        "content_types_seen": [],
        "data_excerpts": [],
        "content_sample": "",
    }
    try:
        # 1. List up to S3_MAX_KEYS keys.
        resp = s3_client.list_objects_v2(Bucket=bucket, MaxKeys=S3_MAX_KEYS)
    except Exception as exc:
        logger.debug(f"aws_content_sampler: list_objects_v2 {bucket}: {exc}")
        return out

    contents = resp.get("Contents") or []
    out["object_count_seen"] = len(contents)
    out["total_size_seen_bytes"] = sum(int(o.get("Size") or 0) for o in contents)

    exts: set[str] = set()
    ctypes: set[str] = set()
    sample_parts: list[str] = []
    excerpts: list[dict[str, Any]] = []
    body_downloads = 0
    total_sampled = 0

    for obj in contents:
        key = obj.get("Key") or ""
        size = int(obj.get("Size") or 0)
        # cheap extension capture for every key
        if "." in key:
            ext = "." + key.rsplit(".", 1)[-1].lower()
            if len(ext) <= 8:
                exts.add(ext)
        # Skip empty / huge / clearly binary objects.
        if size == 0 or size > 5 * 1024 * 1024:
            continue
        # HEAD to get content type without paying for the body twice.
        ctype: str | None = None
        try:
            head = s3_client.head_object(Bucket=bucket, Key=key)
            ctype = (head.get("ContentType") or "").lower() or None
            if ctype:
                ctypes.add(ctype)
        except Exception:
            ctype = None
        if body_downloads >= S3_MAX_BODY_OBJECTS:
            continue
        if total_sampled >= S3_MAX_TOTAL_SAMPLE:
            continue
        if not _looks_textish(key, ctype):
            continue
        # Pull at most 8 KB of body via Range to keep egress trivial.
        try:
            byte_cap = min(S3_MAX_BYTES_PER_OBJECT,
                           S3_MAX_TOTAL_SAMPLE - total_sampled,
                           size - 1)
            get = s3_client.get_object(
                Bucket=bucket,
                Key=key,
                Range=f"bytes=0-{byte_cap}",
            )
            raw = get["Body"].read()
        except Exception as exc:
            logger.debug(f"aws_content_sampler: get_object {bucket}/{key}: {exc}")
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        snippet = text[:S3_MAX_BYTES_PER_OBJECT].strip()
        if not snippet:
            continue
        sample_parts.append(f"<<KEY: {key}>>\n{snippet}")
        excerpts.append({"key": key, "snippet": snippet[:512], "bytes": len(raw)})
        total_sampled += len(raw)
        body_downloads += 1

    out["extensions_seen"] = sorted(exts)
    out["content_types_seen"] = sorted(ctypes)
    out["data_excerpts"] = excerpts
    out["content_sample"] = "\n\n".join(sample_parts)[:S3_MAX_TOTAL_SAMPLE]
    return out


def sample_ebs_volume(ec2_client, volume_id: str) -> dict[str, Any]:
    """Return a sample dict for one EBS volume.

    We cannot mount EBS from the control plane — that requires a node
    with the volume attached. Instead we collect:
      - Volume tags
      - Snapshot tags (last 3 snapshots)
      - The attached instance's tags + instance role
    This is usually enough for the LLM to infer "this is the prod-db
    volume" vs "this is a CI runner scratch disk".
    """
    out: dict[str, Any] = {
        "volume_tags": {},
        "instance_tags": {},
        "snapshot_tags": [],
        "instance_id": None,
        "content_sample": "",
    }
    try:
        vol_resp = ec2_client.describe_volumes(VolumeIds=[volume_id])
        vols = vol_resp.get("Volumes") or []
        if not vols:
            return out
        vol = vols[0]
        out["volume_tags"] = {t["Key"]: t["Value"] for t in (vol.get("Tags") or [])}
        attachments = vol.get("Attachments") or []
        if attachments:
            inst_id = attachments[0].get("InstanceId")
            out["instance_id"] = inst_id
            if inst_id:
                try:
                    inst_resp = ec2_client.describe_instances(InstanceIds=[inst_id])
                    reservations = inst_resp.get("Reservations") or []
                    if reservations:
                        inst = (reservations[0].get("Instances") or [{}])[0]
                        out["instance_tags"] = {
                            t["Key"]: t["Value"] for t in (inst.get("Tags") or [])
                        }
                except Exception as exc:
                    logger.debug(f"aws_content_sampler: describe_instances {inst_id}: {exc}")
        try:
            snaps_resp = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [volume_id]}],
                OwnerIds=["self"],
                MaxResults=3,
            )
            for snap in (snaps_resp.get("Snapshots") or [])[:3]:
                out["snapshot_tags"].append(
                    {t["Key"]: t["Value"] for t in (snap.get("Tags") or [])}
                )
        except Exception as exc:
            logger.debug(f"aws_content_sampler: describe_snapshots {volume_id}: {exc}")
    except Exception as exc:
        logger.debug(f"aws_content_sampler: describe_volumes {volume_id}: {exc}")
        return out

    # Build a content_sample blob the prompt can consume directly.
    parts = []
    if out["volume_tags"]:
        parts.append("Volume tags: " + ", ".join(
            f"{k}={v}" for k, v in list(out["volume_tags"].items())[:15]
        ))
    if out["instance_tags"]:
        parts.append("Attached instance tags: " + ", ".join(
            f"{k}={v}" for k, v in list(out["instance_tags"].items())[:15]
        ))
    if out["snapshot_tags"]:
        for i, st in enumerate(out["snapshot_tags"]):
            if st:
                parts.append(f"Snapshot {i+1} tags: " + ", ".join(
                    f"{k}={v}" for k, v in list(st.items())[:10]
                ))
    out["content_sample"] = "\n".join(parts)
    return out

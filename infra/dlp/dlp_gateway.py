"""
Helios DLP Gateway — Postfix Milter Sidecar
Intercepts outbound SMTP messages and calls the Helios DLP classify endpoint.
If the verdict is HOLD or BLOCK, the message is rejected with a 5xx SMTP error.

Requires: pymilter (pip install pymilter)
Socket:   /var/run/dlp-milter/milter.sock (or DLP_MILTER_SOCKET env var)
"""
from __future__ import annotations

import base64
import email as _email_lib
import json
import logging
import os
import socket
import sys
from email import policy as _email_policy
from typing import Optional

import httpx

# pymilter (Milter package)
try:
    import Milter
    from Milter.utils import parse_addr
except ImportError:
    print("ERROR: pymilter not installed. Run: pip3 install pymilter", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dlp_gateway")

HELIOS_API = os.getenv("HELIOS_API", "https://app.himaya.ai")
HELIOS_ORG_ID = os.getenv("HELIOS_ORG_ID", "")  # fallback for single-tenant mode
DLP_WEBHOOK_SECRET = os.getenv("DLP_WEBHOOK_SECRET", "")
MILTER_SOCKET = os.getenv("MILTER_SOCKET", "/var/run/dlp-milter/milter.sock")
MILTER_TIMEOUT = int(os.getenv("MILTER_TIMEOUT_SEC", "30"))
MULTITENANT = os.getenv("MULTITENANT", "true").lower() == "true"
ORG_HEADER = "x-helios-org"  # SMTP header customers set to identify their org


# ── HTTP client (shared) ──────────────────────────────────────────────────────

def _call_helios_classify(email_data: dict, org_id: str = "") -> dict:
    """
    Synchronous HTTP call to Helios DLP classify webhook.
    Called from milter callbacks which are synchronous in pymilter.
    org_id: from X-Helios-Org header (multi-tenant) or HELIOS_ORG_ID env (single-tenant)
    """
    effective_org_id = org_id or HELIOS_ORG_ID
    if not effective_org_id:
        logger.warning("No org_id — cannot classify, failing open")
        return {"action": "ALLOW"}
    try:
        headers = {
            "X-DLP-Secret": DLP_WEBHOOK_SECRET,
            "Content-Type": "application/json",
        }
        payload = {
            "org_id": effective_org_id,
            "sender": email_data.get("sender", ""),
            "recipients": email_data.get("recipients", []),
            "subject": email_data.get("subject", ""),
            "body": email_data.get("body", "")[:4000],
            "attachments": email_data.get("attachments", []),
        }
        with httpx.Client(timeout=MILTER_TIMEOUT) as client:
            r = client.post(
                f"{HELIOS_API}/api/dlp/webhook/m365",
                json=payload,
                headers=headers,
            )
            if r.status_code in (200, 201):
                data = r.json()
                # Webhook returns {status: ok, action: ALLOW/WARN} on 200
                if "action" not in data:
                    data["action"] = "ALLOW"
                return data
            elif r.status_code == 550:
                data = r.json()
                # Webhook returns {error: DLP_BLOCK/DLP_HOLD, risk_level, ...} on 550
                error = data.get("error", "DLP_BLOCK")
                action = "BLOCK" if error == "DLP_BLOCK" else "HOLD"
                return {
                    "action": action,
                    "risk_level": data.get("risk_level", "critical"),
                    "categories": data.get("categories", []),
                    "explanation": data.get("explanation", "Sensitive content detected"),
                    "event_id": data.get("event_id", ""),
                }
            else:
                logger.warning(f"DLP API returned {r.status_code}")
                return {"action": "ALLOW"}  # fail open
    except Exception as exc:
        logger.error(f"DLP classify call failed (fail open): {exc}")
        return {"action": "ALLOW"}  # fail open — don't block mail on error


# ── Milter class ──────────────────────────────────────────────────────────────

class DLPMilter(Milter.Base):
    """Postfix milter that classifies outbound email via Helios DLP."""

    def __init__(self):
        self._sender: str = ""
        self._recipients: list[str] = []
        self._headers: dict[str, str] = {}
        self._body_chunks: list[bytes] = []
        self._attachments: list[str] = []

    @Milter.noreply
    def connect(self, IPname, family, hostaddr):
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *str):
        self._sender = mailfrom.strip("<>")
        self._recipients = []
        self._headers = {}
        self._body_chunks = []
        self._attachments = []
        self._org_id = ""  # resolved from X-Helios-Org header
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        self._recipients.append(to.strip("<>"))
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, hval):
        self._headers[name.lower()] = hval
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
        self._body_chunks.append(chunk)
        return Milter.CONTINUE

    def eom(self):
        """End of message — run DLP classification."""
        try:
            raw_body = b"".join(self._body_chunks)
            subject = self._headers.get("subject", "")
            body_text = ""
            attachments = []

            # Parse MIME to extract text + attachments
            try:
                header_bytes = "".join(
                    f"{k}: {v}\r\n" for k, v in self._headers.items()
                ).encode()
                full_msg_bytes = header_bytes + b"\r\n" + raw_body
                msg = _email_lib.message_from_bytes(full_msg_bytes, policy=_email_policy.default)
                if msg.is_multipart():
                    for part in msg.walk():
                        ct = part.get_content_type()
                        cd = part.get("Content-Disposition", "")
                        if ct == "text/plain" and "attachment" not in cd:
                            try:
                                body_text += part.get_content() or ""
                            except Exception:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body_text += payload.decode("utf-8", errors="replace")
                        elif "attachment" in cd or part.get_filename():
                            fname = part.get_filename() or "unnamed"
                            attachments.append(fname)
                else:
                    body_text = raw_body.decode("utf-8", errors="replace")
            except Exception as parse_exc:
                logger.debug(f"MIME parse failed: {parse_exc}")
                body_text = raw_body.decode("utf-8", errors="replace")

            email_data = {
                "sender": self._sender,
                "recipients": self._recipients,
                "subject": subject,
                "body": body_text[:4000],
                "attachments": attachments,
            }

            logger.info(
                f"DLP classify: from={self._sender} to={self._recipients[:3]} "
                f"subject={subject[:50]!r}"
            )

            # Multi-tenant: org_id from X-Helios-Org header, fallback to env
            org_id = self._headers.get(ORG_HEADER, "") or HELIOS_ORG_ID
            logger.info(f"DLP classify: org={org_id or '(none)'} from={self._sender}")
            verdict = _call_helios_classify(email_data, org_id)
            action = verdict.get("action", "ALLOW")
            logger.info(f"DLP verdict: action={action} risk={verdict.get('risk_level')}")

            if action == "BLOCK":
                self.setreply(
                    "550", "5.7.1",
                    f"Message blocked by Helios DLP: {verdict.get('explanation', 'Sensitive content detected')}",
                )
                return Milter.REJECT

            if action == "HOLD":
                self.setreply(
                    "550", "5.7.1",
                    f"Message held for security review by Helios DLP (event: {verdict.get('event_id', '')}). "
                    "Contact your security team to release.",
                )
                return Milter.REJECT

            if action == "WARN":
                # Add warning header and allow delivery
                self.addheader(
                    "X-DLP-Warning",
                    f"Sensitive content detected: {', '.join(verdict.get('categories', []))}",
                )

            return Milter.ACCEPT

        except Exception as exc:
            logger.error(f"DLP milter eom error (fail open): {exc}")
            return Milter.ACCEPT  # fail open


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not MULTITENANT and not HELIOS_ORG_ID:
        logger.error("HELIOS_ORG_ID is required in single-tenant mode")
        sys.exit(1)
    if MULTITENANT:
        logger.info("Multi-tenant mode: org_id resolved from X-Helios-Org SMTP header per message")

    socket_path = MILTER_SOCKET
    if socket_path.startswith("/"):
        socket_spec = f"unix:{socket_path}"
    else:
        socket_spec = socket_path

    logger.info(f"Starting Helios DLP milter on {socket_spec}")
    logger.info(f"Helios API: {HELIOS_API}")
    logger.info(f"Org ID: {HELIOS_ORG_ID}")

    Milter.factory = DLPMilter
    Milter.set_flags(
        Milter.ADDHDRS |     # Can add headers (for X-DLP-Warning)
        Milter.CHGHDRS       # Can change headers
    )
    Milter.runmilter("dlp_gateway", socket_spec, timeout=600)


if __name__ == "__main__":
    main()

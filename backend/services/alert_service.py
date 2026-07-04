"""
Alert service for Slack, WhatsApp, and email notifications.
In local dev, alerts are logged. In production, send to real channels.
"""
import logging
import os
from typing import Optional
from backend.services.email_service import send_threat_alert as ses_send_threat_alert, send_quarantine_notification as ses_send_qn

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(self):
        self.slack_webhook: Optional[str] = None
        self.whatsapp_token: Optional[str] = None
        self.alert_email: Optional[str] = None

    def configure(self, slack_webhook: str = None, whatsapp_token: str = None, alert_email: str = None):
        self.slack_webhook = slack_webhook
        self.whatsapp_token = whatsapp_token
        self.alert_email = alert_email

    async def send_threat_alert(self, threat: dict, org_name: str):
        """Send high-priority threat alert to configured channels."""
        message = (
            f"🚨 *Himaya Helios Alert* | {org_name}\n"
            f"Threat Type: {threat.get('threat_type', 'Unknown')}\n"
            f"Risk Score: {threat.get('risk_score', 0)}/100\n"
            f"Sender: {threat.get('sender', 'Unknown')}\n"
            f"Recipient: {threat.get('recipient_email', 'Unknown')}\n"
            f"Action: {threat.get('action_taken', 'PENDING')}\n"
            f"Status: {threat.get('status', 'open')}"
        )

        if self.slack_webhook:
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    await client.post(self.slack_webhook, json={"text": message})
                    logger.info(f"Slack alert sent for threat {threat.get('id')}")
            except Exception as e:
                logger.error(f"Slack alert failed: {e}")
        else:
            logger.info(f"[ALERT MOCK] {message}")

        # Send email alert via SES if configured
        if self.alert_email:
            ses_send_threat_alert(
                to_email=self.alert_email,
                org_name=org_name,
                threat_type=threat.get("threat_type", "Unknown"),
                risk_score=threat.get("risk_score", 0),
                recipient=threat.get("recipient_email", "Unknown"),
                action=threat.get("action_taken", "PENDING"),
            )

    async def send_compliance_alert(self, framework: str, control: str, org_name: str):
        message = (
            f"⚠️ *Compliance Alert* | {org_name}\n"
            f"Framework: {framework}\n"
            f"Control: {control}\n"
            f"Action Required: Review compliance evidence"
        )
        logger.info(f"[COMPLIANCE ALERT MOCK] {message}")


alert_service = AlertService()

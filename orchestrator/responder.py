"""Response engine: maps severity -> actions (quarantine, suspend flag, Slack)."""
import logging
import os
from email.utils import parseaddr
import requests

import orchestrator.postgresql.db as db

log = logging.getLogger("responder")


def slack_payload(message_id, email, severity, score, findings):
    urgent = severity == "high"
    head = (":rotating_light: *HIGH severity phishing email*" if urgent
            else ":warning: *Suspicious email (medium severity)*")
    detail = "\n".join(f"• {f}" for f in findings[:8]) or "• (no findings)"
    text = (f"{head}\n*From:* {email.get('sender', '?')}\n*Subject:* {email.get('subject', '')}\n"
            f"*Score:* {score}/100   *ID:* `{message_id}`\n{detail}")
    return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}


def send_slack(payload):
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        log.info("SLACK_WEBHOOK_URL not set - dry run, payload: %s", payload["text"])
        return
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()


def respond(message_id, email, severity, score, findings) -> str:
    """Run the actions for this severity. Returns a short description of what was done.
    Protective actions (quarantine/suspend) run BEFORE Slack so a Slack outage can't leave
    a dangerous email unhandled; the action taken so far is recorded either way."""
    if severity == "low":
        db.set_state(message_id, action_taken="logged")
        return "logged"

    actions = ["quarantined"]
    db.set_state(message_id, quarantined=True, action_taken="+".join(actions))

    if severity == "high":
        targets = [parseaddr(a)[1] or a for a in email.get("to", [])]
        db.suspend_accounts(targets, f"High-severity phishing email {message_id}")
        actions.append("account_suspended")
        db.set_state(message_id, action_taken="+".join(actions))

    actions.append("slack_urgent" if severity == "high" else "slack_alert")
    send_slack(slack_payload(message_id, email, severity, score, findings))
    return "+".join(actions)

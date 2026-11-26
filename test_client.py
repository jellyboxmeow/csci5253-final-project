#!/usr/bin/env python3
"""Test client / email replay script.

  python replay.py samples                          # send 3 built-in emails
  python replay.py eval --phish DIR --ham DIR       # label-based eval on .eml dirs or .mbox files
"""
import argparse
import mailbox
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

import gRPC.gRPC_api_pb2 as api
import gRPC.gRPC_api_pb2_grpc as api_grpc

SAMPLES = {
    "legit": dict(sender="Alice <alice@university.edu>", to=["bob@example.com"], subject="Lunch tomorrow?",
                  plain_text_body="Hey Bob, want to grab lunch tomorrow at noon? - Alice"),
    "phish_medium": dict(sender="IT Helpdesk <helpdesk@company-it.com>", to=["bob@example.com"],
                         subject="Urgent: password expires",
                         plain_text_body="Your password expires today. Update it here: http://bit.ly/3abcXYZ",
                         custom_headers={"Reply-To": "helpdesk.support@gmail.com"}),
    "phish_high": dict(sender="PayPal Support <service@paypa1-secure.com>", to=["bob@example.com"],
                       subject="Security alert: account suspended",
                       plain_text_body="Urgent! Verify your account immediately.",
                       html_body='<p>Please <a href="http://paypa1-secure.com/login">paypal.com/verify</a> now.</p>',
                       attachment_urls=["https://files.example.net/invoice.pdf.exe"],
                       custom_headers={"Reply-To": "payments@evil-mail.xyz",
                                       "Authentication-Results": "spf=fail dkim=fail dmarc=fail"}),
}


def message_to_proto(m) -> "api.email":
    msg = api.email(sender=str(m.get("From", "")), subject=str(m.get("Subject", "")))
    if m.get("To"):
        msg.to.append(str(m["To"]))
    for h in ("Reply-To", "Return-Path", "Authentication-Results", "Received-SPF"):
        if m.get(h):
            msg.custom_headers[h] = str(m[h])
    try:
        for part in m.walk():
            ctype, fname = part.get_content_type(), part.get_filename()
            if fname:
                msg.attachment_urls.append(fname)
            elif ctype == "text/plain" and not msg.plain_text_body:
                msg.plain_text_body = part.get_content()
            elif ctype == "text/html" and not msg.html_body:
                msg.html_body = part.get_content()
        ts = Timestamp()
        ts.FromDatetime(__import__("email.utils").utils.parsedate_to_datetime(str(m["Date"])).replace(tzinfo=None))
        msg.sent_at.CopyFrom(ts)
    except Exception:
        pass
    if not msg.plain_text_body and not msg.html_body:
        msg.plain_text_body = "(empty)"
    return msg


def load_messages(path):
    p = Path(path)
    if p.is_dir():
        for f in sorted(p.glob("*.eml")):
            yield BytesParser(policy=policy.default).parse(open(f, "rb"))
    else:
        yield from mailbox.mbox(str(p), factory=lambda f: BytesParser(policy=policy.default).parse(f))


def wait_for(stub, mid, timeout=60):
    t = time.time()
    while time.time() - t < timeout:
        sev = stub.getSeverity(api.severityMsg(message_id=mid)).severity
        if sev != "PENDING":
            return sev
        time.sleep(0.5)
    return "TIMEOUT"


def show_queue(stub):
    for e in stub.listEmails(api.listMsg(list_size=50)).emails[-10:]:
        print(f"{e.message_id[:8]}  {e.pipeline_state:<10} {e.severity or '-':<7} {e.score:>3}  {e.action_taken or '-':<45} {e.subject[:30]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["samples", "eval"])
    ap.add_argument("--phish"), ap.add_argument("--ham")
    ap.add_argument("--server", default="localhost:5000")
    a = ap.parse_args()
    stub = api_grpc.GRPCAPIStub(grpc.insecure_channel(a.server))

    if a.cmd == "samples":
        for name, kw in SAMPLES.items():
            reply = stub.analyzeEmail(api.analyzeMsg(email_to_analyze=api.email(**kw)))
            mid = reply.analyzed_email.message_id
            print(f"{name:<13} -> {wait_for(stub, mid)}")
        time.sleep(1)
        show_queue(stub)
        return

    tp = fp = fn = tn = 0
    for path, is_phish in ((a.phish, True), (a.ham, False)):
        for m in load_messages(path):
            mid = stub.analyzeEmail(api.analyzeMsg(email_to_analyze=message_to_proto(m))).analyzed_email.message_id
            flagged = wait_for(stub, mid) in ("medium", "high")
            tp += is_phish and flagged
            fn += is_phish and not flagged
            fp += (not is_phish) and flagged
            tn += (not is_phish) and not flagged
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")


if __name__ == "__main__":
    main()

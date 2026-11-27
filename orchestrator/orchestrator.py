"""Orchestrator: runs the sandbox, scores, and triggers responses. Core 'if this, then that' logic."""
import io
import json
import logging
import os
import sys
import tarfile
import docker

import orchestrator.postgresql.db as db
import orchestrator.responder as responder
from orchestrator.sandbox.analyze import analyze
log = logging.getLogger("orchestrator")

SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "docker")   # "docker" (real) or "local" (dev/tests only, NOT isolated)
SANDBOX_IMAGE = os.environ.get("PHISHGUARD_SANDBOX_IMAGE", "phishguard-sandbox")
SANDBOX_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "20"))


"""
    Score -> severity mapping 
    (the 'then that' threshold logic).
"""
def severity_for(score: int) -> str:
    if score < 25:
        return "low"
    if score < 60:
        return "medium"
    return "high"

def _tar_bytes(name, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), 0o644
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def run_sandbox(email: dict) -> dict:
    if SANDBOX_MODE == "local":
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox"))
        return analyze(email)

    client = docker.from_env()
    container = client.containers.create(
        SANDBOX_IMAGE,
        network_mode="none",            # no network at all
        mem_limit="128m", memswap_limit="128m",
        nano_cpus=500_000_000,          # 0.5 CPU
        pids_limit=64,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        labels={"phishguard": "sandbox"},
    )
    try:
        # Copy the email in (instead of a bind mount) so it works when the orchestrator is itself in a container.
        container.put_archive("/input", _tar_bytes("email.json", json.dumps(email).encode()))
        container.start()
        try:
            status = container.wait(timeout=SANDBOX_TIMEOUT)["StatusCode"]
        except Exception:
            container.kill()
            raise RuntimeError(f"sandbox timed out after {SANDBOX_TIMEOUT}s")
        out = container.logs(stdout=True, stderr=False).decode()
        if status != 0:
            err = container.logs(stdout=False, stderr=True).decode()[-500:]
            raise RuntimeError(f"sandbox exited {status}: {err}")
        return json.loads(out)
    finally:
        try:
            container.remove(force=True)   # sandbox is destroyed after every email
        except Exception:
            log.warning("could not remove sandbox container")


def process(message_id: str, email: dict):
    """Full pipeline for one email. Never raises; failures are recorded as FAILED."""
    tag = f"[{message_id}]"
    try:
        db.set_state(message_id, "ANALYZING")
        log.info("%s analyzing", tag)
        result = run_sandbox(email)
        score, findings = int(result["score"]), result["findings"]
        severity = severity_for(score)
        db.set_state(message_id, "SCORED", detail=f"score={score}", severity=severity, score=score, findings=findings)
        log.info("%s scored %d -> %s", tag, score, severity)

        action = responder.respond(message_id, email, severity, score, findings)
        db.set_state(message_id, "RESPONDED", detail=action, action_taken=action)
        log.info("%s responded: %s", tag, action)
    except Exception as e:
        log.exception("%s pipeline failed", tag)
        try:
            db.set_state(message_id, "FAILED", detail=str(e), error=str(e))
        except Exception:
            log.exception("%s could not record failure", tag)

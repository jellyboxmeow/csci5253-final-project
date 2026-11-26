import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sandbox"))

from orchestrator.sandbox.analyze import analyze, brand_misuse, norm  # noqa: E402
from orchestrator.orchestrator import severity_for  # noqa: E402


def test_legit_email_is_low():
    r = analyze({"sender": "Alice <alice@university.edu>", "plain_text_body": "Lunch at noon? Notes: https://docs.google.com/document/d/1"})
    assert r["score"] < 25 and severity_for(r["score"]) == "low"


def test_obvious_phish_is_high():
    r = analyze({
        "sender": "PayPal Support <service@paypa1-secure.com>",
        "plain_text_body": "Urgent! Verify your account immediately.",
        "html_body": '<a href="http://paypa1-secure.com/login">paypal.com/verify</a>',
        "attachment_urls": ["https://x.example.net/invoice.pdf.exe"],
        "custom_headers": {"Reply-To": "a@evil.xyz", "Authentication-Results": "spf=fail dkim=fail"},
    })
    assert severity_for(r["score"]) == "high"


def test_reply_to_mismatch_flagged():
    r = analyze({"sender": "a@corp.com", "plain_text_body": "hi", "custom_headers": {"Reply-To": "a@gmail.com"}})
    assert any("Reply-To" in f for f in r["findings"])


def test_lookalike_and_no_false_positive():
    assert brand_misuse("paypa1.com") == ("paypal", True)
    assert brand_misuse("paypal.com.evil.xyz") == ("paypal", False)
    assert brand_misuse("paypal.com") is None
    assert brand_misuse("pineapple.com") is None
    assert norm("rnicrosoft") == "microsoft"


def test_attachments():
    r = analyze({"sender": "a@b.com", "plain_text_body": "x", "attachment_urls": ["report.docm", "notes.txt"]})
    assert r["score"] == 30


def test_empty_fields_do_not_crash():
    assert analyze({})["score"] == 0


def test_severity_boundaries():
    assert [severity_for(s) for s in (0, 24, 25, 59, 60, 100)] == ["low", "low", "medium", "medium", "high", "high"]

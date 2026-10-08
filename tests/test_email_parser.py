from src.email_parser import parse_email


def test_parse_text_email():
    raw_email = """From: sender@example.com
To: user@example.com
Subject: Test email

Hello world.
"""

    result = parse_email(raw_email)

    assert result["from"] == "sender@example.com"
    assert result["to"] == "user@example.com"
    assert result["subject"] == "Test email"
    assert "Hello world." in result["body"]


def test_parse_eml_bytes():
    raw_email = b"""From: security@example.com
To: user@example.com
Subject: Security notification
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Your account security settings were updated.
"""

    result = parse_email(raw_email)

    assert result["from"] == "security@example.com"
    assert result["subject"] == "Security notification"

    assert (
        "spf=pass"
        in result["authentication_results"]
    )

    assert (
        "Your account security settings were updated."
        in result["body"]
    )
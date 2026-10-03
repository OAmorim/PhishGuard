from pathlib import Path

from streamlit.testing.v1 import AppTest

from src.header_analyzer import analyze_headers


def test_authentication_results_are_parsed():
    email_data = {
        "from": "security@example.com",
        "reply_to": "",
        "return_path": "",
        "authentication_results": (
            "mail.example.com; "
            "spf=fail; "
            "dkim=pass; "
            "dmarc=fail"
        ),
    }

    result = analyze_headers(
        email_data
    )

    authentication = result[
        "authentication_results"
    ]

    assert authentication["spf"] == "fail"
    assert authentication["dkim"] == "pass"
    assert authentication["dmarc"] == "fail"


def test_matching_sender_domains():
    email_data = {
        "from": "Security <security@example.com>",
        "reply_to": "support@example.com",
        "return_path": "bounce@example.com",
        "authentication_results": (
            "mail.example.com; "
            "spf=pass; "
            "dkim=pass; "
            "dmarc=pass"
        ),
    }

    result = analyze_headers(
        email_data
    )

    assert result["from_domain"] == "example.com"
    assert result["reply_to_domain"] == "example.com"
    assert result["return_path_domain"] == "example.com"

    authentication = result[
        "authentication_results"
    ]

    assert authentication["spf"] == "pass"
    assert authentication["dkim"] == "pass"
    assert authentication["dmarc"] == "pass"


def test_mismatched_sender_domains_create_indicators():
    email_data = {
        "from": "PayPal Security <security@paypal.com>",
        "reply_to": "verify@malicious-domain.xyz",
        "return_path": "bounce@malicious-domain.xyz",
        "authentication_results": "",
    }

    result = analyze_headers(
        email_data
    )

    assert result["from_domain"] == "paypal.com"

    assert (
        result["reply_to_domain"]
        == "malicious-domain.xyz"
    )

    assert (
        result["return_path_domain"]
        == "malicious-domain.xyz"
    )

    assert len(
        result["indicators"]
    ) >= 2


def test_streamlit_displays_authentication_results():
    app_path = (
        Path(__file__).resolve().parents[1]
        / "app.py"
    )

    app = AppTest.from_file(
        app_path
    ).run(
        timeout=20
    )

    app.text_area[0].input(
        "From: security@paypal.com\n"
        "Authentication-Results: test; "
        "spf=fail; dkim=pass; dmarc=fail\n\n"
        "Hello"
    )

    app.button[0].click().run(
        timeout=20
    )

    assert not app.exception

    markdown_text = " ".join(
        element.value
        for element in app.markdown
    )

    assert "SPF:" in markdown_text
    assert "FAIL" in markdown_text

    assert "DKIM:" in markdown_text
    assert "PASS" in markdown_text

    assert "DMARC:" in markdown_text
    assert "FAIL" in markdown_text
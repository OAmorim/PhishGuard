from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src.email_parser import parse_email
from src.header_analyzer import analyze_headers, parse_authentication_results


@pytest.mark.parametrize("header", [
    "Authentication-Results: test; spf=fail; dkim=pass; dmarc=fail",
    "authentication-results: test;\n spf=fail;\n dkim=pass;\n dmarc=fail",
])
def test_authentication_results_pipeline(header):
    email_data = parse_email(
        f"From: security@paypal.com\n"
        f"Reply-To: attacker@malicious.xyz\n{header}\n\nHello\n"
    )
    expected = {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
    assert parse_authentication_results(email_data["authentication_results"]) == expected
    result = analyze_headers(email_data)
    assert result["authentication_results"] == expected
    types = {indicator["type"] for indicator in result["indicators"]}
    assert {"reply_to_mismatch", "spf_failure", "dmarc_failure"} <= types
    assert "dkim_failure" not in types


def test_missing_authentication_results():
    email_data = parse_email("From: sender@example.com\n\nHello")
    assert email_data["authentication_results"] == ""
    assert analyze_headers(email_data)["authentication_results"] == {}


def test_streamlit_displays_authentication_results():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py").run()
    app.text_area[0].input(
        "From: security@paypal.com\n"
        "Authentication-Results: test; spf=fail; dkim=pass; dmarc=fail\n\nHello"
    )
    app.button[0].click().run()
    assert not app.exception
    displayed = {element.value for element in app.markdown}
    assert {"SPF: **FAIL**", "DKIM: **PASS**", "DMARC: **FAIL**"} <= displayed
    assert not any("No SPF, DKIM or DMARC" in element.value for element in app.info)

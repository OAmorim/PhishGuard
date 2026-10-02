from src.risk_engine import (
    calculate_risk_score,
    get_risk_level,
)


def test_risk_levels():
    assert get_risk_level(0) == "LOW"
    assert get_risk_level(29) == "LOW"

    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(59) == "MEDIUM"

    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(100) == "HIGH"


def test_empty_analysis_is_low_risk():
    result = calculate_risk_score(
        url_results=[],
        keyword_results=[],
        header_results={
            "indicators": []
        },
    )

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_high_risk_email():
    url_results = [
        {
            "url": "http://185.31.22.10/login",
            "indicators": [
                {
                    "type": "insecure_protocol",
                    "severity": "medium",
                    "message": "URL uses HTTP.",
                },
                {
                    "type": "ip_address_url",
                    "severity": "high",
                    "message": "URL uses an IP address.",
                },
            ],
        }
    ]

    keyword_results = [
        {
            "category": "urgency",
            "severity": "medium",
            "description": "Urgency detected.",
            "matches": ["urgent"],
        },
        {
            "category": "credential_request",
            "severity": "high",
            "description": "Credential request detected.",
            "matches": ["verify your identity"],
        },
    ]

    header_results = {
        "indicators": [
            {
                "type": "reply_to_mismatch",
                "severity": "medium",
                "message": "Reply-To mismatch.",
            },
        ]
    }

    result = calculate_risk_score(
        url_results,
        keyword_results,
        header_results,
    )

    assert result["score"] == 80
    assert result["level"] == "HIGH"


def test_duplicate_url_indicator_is_not_counted_twice():
    url_results = [
        {
            "url": "http://example1.com",
            "indicators": [
                {
                    "type": "insecure_protocol",
                    "severity": "medium",
                    "message": "HTTP detected.",
                }
            ],
        },
        {
            "url": "http://example2.com",
            "indicators": [
                {
                    "type": "insecure_protocol",
                    "severity": "medium",
                    "message": "HTTP detected.",
                }
            ],
        },
    ]

    result = calculate_risk_score(
        url_results,
        [],
        {"indicators": []},
    )

    assert result["score"] == 10


def test_score_is_capped_at_100():
    url_results = [
        {
            "url": "http://185.31.22.10",
            "indicators": [
                {
                    "type": indicator_type,
                    "severity": "high",
                    "message": "Test indicator",
                }
                for indicator_type in [
                    "insecure_protocol",
                    "ip_address_url",
                    "url_shortener",
                    "punycode_domain",
                    "suspicious_tld",
                ]
            ],
        }
    ]

    keyword_results = [
        {
            "category": category,
            "severity": "high",
            "description": "Test",
            "matches": [],
        }
        for category in [
            "urgency",
            "threat",
            "credential_request",
            "financial_request",
            "call_to_action",
        ]
    ]

    header_results = {
        "indicators": [
            {
                "type": "dmarc_failure",
                "severity": "high",
                "message": "DMARC failed.",
            }
        ]
    }

    result = calculate_risk_score(
        url_results,
        keyword_results,
        header_results,
    )

    assert result["raw_score"] > 100
    assert result["score"] == 100
    assert result["level"] == "HIGH"

def test_streamlit_displays_risk_assessment():
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    app_path = Path(__file__).resolve().parents[1] / "app.py"
    for raw_email, score, level in [
        ("From: sender@example.com\n\nHello", "0/100", "LOW"),
        (
            "From: sender@example.com\n"
            "Authentication-Results: test; spf=fail; dkim=fail; dmarc=fail\n"
            "Subject: urgent\n\nHello",
            "65/100",
            "HIGH",
        ),
    ]:
        app = AppTest.from_file(app_path).run()
        app.text_area[0].input(raw_email)
        app.button[0].click().run()
        assert not app.exception
        metrics = {metric.label: metric.value for metric in app.metric}
        assert metrics["Risk score"] == score
        assert metrics["Risk level"] == level

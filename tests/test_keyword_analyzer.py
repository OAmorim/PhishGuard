from src.keyword_analyzer import analyze_keywords


def get_categories(results):
    return [
        result["category"]
        for result in results
    ]


def test_urgency_detection():
    text = (
        "URGENT: You must verify your account "
        "within 24 hours."
    )

    results = analyze_keywords(text)
    categories = get_categories(results)

    assert "urgency" in categories


def test_threat_detection():
    text = (
        "Your account has been suspended. "
        "Failure to verify will result in termination."
    )

    results = analyze_keywords(text)
    categories = get_categories(results)

    assert "threat" in categories


def test_credential_request_detection():
    text = (
        "Please verify your identity and "
        "enter your password."
    )

    results = analyze_keywords(text)
    categories = get_categories(results)

    assert "credential_request" in categories


def test_financial_request_detection():
    text = (
        "Please provide your bank details "
        "to complete the payment."
    )

    results = analyze_keywords(text)
    categories = get_categories(results)

    assert "financial_request" in categories


def test_normal_email():
    text = (
        "Hi John, the project meeting has been moved "
        "to Tuesday afternoon. See you then."
    )

    results = analyze_keywords(text)

    assert results == []
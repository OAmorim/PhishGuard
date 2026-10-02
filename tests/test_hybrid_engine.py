from src.hybrid_engine import (
    calculate_hybrid_assessment,
)


def create_ml_result(
    label,
    probability,
):
    return {
        "label": label,
        "phishing_probability": probability,
        "prediction": (
            1 if label == "PHISHING" else 0
        ),
        "threshold": 0.50,
    }


def test_high_heuristic_and_ml_detect_phishing():
    risk_result = {
        "score": 85,
        "level": "HIGH",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "PHISHING",
        0.94,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "HIGH"
    assert result["agreement"] is True


def test_medium_heuristic_and_ml_detect_phishing():
    risk_result = {
        "score": 45,
        "level": "MEDIUM",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "PHISHING",
        0.82,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "HIGH"
    assert result["agreement"] is True


def test_both_consider_email_safe():
    risk_result = {
        "score": 10,
        "level": "LOW",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "LEGITIMATE",
        0.12,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "LOW"
    assert result["agreement"] is True


def test_ml_false_positive_scenario():
    risk_result = {
        "score": 5,
        "level": "LOW",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "PHISHING",
        0.99,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "REVIEW"
    assert result["agreement"] is False


def test_high_heuristic_ml_legitimate():
    risk_result = {
        "score": 80,
        "level": "HIGH",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "LEGITIMATE",
        0.35,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "REVIEW"
    assert result["agreement"] is False


def test_medium_heuristic_ml_legitimate():
    risk_result = {
        "score": 45,
        "level": "MEDIUM",
        "breakdown": [],
    }

    ml_result = create_ml_result(
        "LEGITIMATE",
        0.30,
    )

    result = calculate_hybrid_assessment(
        risk_result,
        ml_result,
    )

    assert result["level"] == "REVIEW"
    assert result["agreement"] is False
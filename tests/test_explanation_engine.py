from src.explanation_engine import (
    build_explanation,
)


def create_results(
    hybrid_level,
    heuristic_score,
    ml_probability,
    breakdown=None,
):
    if breakdown is None:
        breakdown = []

    risk_result = {
        "score": heuristic_score,
        "level": (
            "HIGH"
            if heuristic_score >= 60
            else "MEDIUM"
            if heuristic_score >= 30
            else "LOW"
        ),
        "breakdown": breakdown,
    }

    ml_result = {
        "phishing_probability": ml_probability,
        "prediction": (
            1
            if ml_probability >= 0.50
            else 0
        ),
        "label": (
            "PHISHING"
            if ml_probability >= 0.50
            else "LEGITIMATE"
        ),
        "threshold": 0.50,
    }

    hybrid_result = {
        "level": hybrid_level,
        "agreement": (
            hybrid_level != "REVIEW"
        ),
    }

    return (
        risk_result,
        ml_result,
        hybrid_result,
    )


def test_high_risk_explanation():
    risk_result, ml_result, hybrid_result = (
        create_results(
            "HIGH",
            85,
            0.94,
        )
    )

    result = build_explanation(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert result["level"] == "HIGH"
    assert "Strong phishing evidence" in result["summary"]
    assert len(result["actions"]) > 0


def test_review_explanation():
    risk_result, ml_result, hybrid_result = (
        create_results(
            "REVIEW",
            10,
            0.98,
        )
    )

    result = build_explanation(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert result["level"] == "REVIEW"
    assert "manual review" in result["summary"]


def test_low_result_contains_safety_warning():
    risk_result, ml_result, hybrid_result = (
        create_results(
            "LOW",
            5,
            0.10,
        )
    )

    result = build_explanation(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert result["level"] == "LOW"

    assert (
        "does not guarantee"
        in result["summary"]
    )


def test_heuristic_evidence_is_preserved():
    breakdown = [
        {
            "source": "Header",
            "indicator": "dmarc_failure",
            "points": 25,
            "message": "DMARC authentication failed.",
        }
    ]

    risk_result, ml_result, hybrid_result = (
        create_results(
            "HIGH",
            80,
            0.95,
            breakdown,
        )
    )

    result = build_explanation(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert len(result["evidence"]) == 1

    assert (
        result["evidence"][0]["message"]
        == "DMARC authentication failed."
    )

    assert (
        result["evidence"][0]["points"]
        == 25
    )
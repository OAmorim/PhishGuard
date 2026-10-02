def calculate_hybrid_assessment(
    risk_result,
    ml_result,
):
    """
    Combine heuristic and ML results into a final assessment.

    Strong or moderate heuristic evidence combined with an ML
    phishing prediction produces a high-risk result.

    A low heuristic result combined with an ML legitimate
    prediction produces a low-risk result.

    Conflicting results require manual review.
    """

    heuristic_level = risk_result["level"]
    heuristic_score = risk_result["score"]

    ml_label = ml_result["label"]
    ml_probability = ml_result[
        "phishing_probability"
    ]

    ml_suspicious = (
        ml_label == "PHISHING"
    )

    ml_safe = (
        ml_label == "LEGITIMATE"
    )

    # Both methods indicate suspicious activity
    if (
        heuristic_level in {"HIGH", "MEDIUM"}
        and ml_suspicious
    ):
        return {
            "level": "HIGH",
            "agreement": True,
            "reason": (
                "The heuristic engine detected suspicious "
                "indicators and the machine learning model "
                "also classified the email as phishing."
            ),
            "heuristic_score": heuristic_score,
            "ml_probability": ml_probability,
        }

    # Both methods indicate low phishing risk
    if (
        heuristic_level == "LOW"
        and ml_safe
    ):
        return {
            "level": "LOW",
            "agreement": True,
            "reason": (
                "Both the heuristic engine and the machine "
                "learning model indicate low phishing risk."
            ),
            "heuristic_score": heuristic_score,
            "ml_probability": ml_probability,
        }

    # Conflicting results require review
    return {
        "level": "REVIEW",
        "agreement": False,
        "reason": (
            "The heuristic and machine learning results do not "
            "provide enough agreement for a definitive assessment."
        ),
        "heuristic_score": heuristic_score,
        "ml_probability": ml_probability,
    }
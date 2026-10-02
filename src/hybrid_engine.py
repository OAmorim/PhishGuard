def calculate_hybrid_assessment(
    risk_result,
    ml_result,
):
    """
    Combine the heuristic and ML results into a final assessment.

    The two systems remain independent. Agreement produces
    a stronger conclusion, while disagreement requires review.
    """

    heuristic_level = risk_result["level"]
    heuristic_score = risk_result["score"]

    ml_label = ml_result["label"]
    ml_probability = ml_result["phishing_probability"]

    heuristic_suspicious = (
        heuristic_level == "HIGH"
    )

    heuristic_safe = (
        heuristic_level == "LOW"
    )

    ml_suspicious = (
        ml_label == "PHISHING"
    )

    ml_safe = (
        ml_label == "LEGITIMATE"
    )

    # Both systems independently detect strong phishing evidence
    if heuristic_suspicious and ml_suspicious:
        return {
            "level": "HIGH",
            "agreement": True,
            "reason": (
                "Both the heuristic engine and the machine "
                "learning model detected strong phishing evidence."
            ),
            "heuristic_score": heuristic_score,
            "ml_probability": ml_probability,
        }

    # Both systems independently consider the email low risk
    if heuristic_safe and ml_safe:
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

    # Medium heuristic scores or disagreement should be reviewed
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
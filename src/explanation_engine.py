def build_explanation(
    risk_result,
    ml_result,
    hybrid_result,
):
    """
    Build a human-readable explanation from the results
    already produced by the detection pipeline.

    This function does not change the classification.
    """

    heuristic_score = risk_result["score"]
    hybrid_level = hybrid_result["level"]

    ml_probability = (
        ml_result["phishing_probability"]
    )

    evidence = []

    # Keep the evidence detected by the heuristic engine
    for item in risk_result["breakdown"]:
        evidence.append({
            "source": item["source"],
            "message": item["message"],
            "points": item["points"],
        })

    if hybrid_level == "HIGH":
        summary = (
            "Strong phishing evidence was detected. "
            "The heuristic analysis found suspicious "
            "indicators and the machine learning model "
            "also classified the email as phishing."
        )

        actions = [
            "Do not click links or open unexpected attachments.",
            "Do not provide passwords, payment information or other sensitive data.",
            "Verify the sender using an independent and trusted communication channel.",
            "Report the email to the appropriate security team or email provider.",
        ]

    elif hybrid_level == "REVIEW":
        summary = (
            "The email requires manual review because the "
            "analysis methods do not provide enough agreement "
            "for an automatic conclusion."
        )

        actions = [
            "Verify the sender and the request before taking action.",
            "Inspect links carefully before opening them.",
            "Confirm unexpected account, payment or credential requests independently.",
            "Avoid providing sensitive information until the email has been verified.",
        ]

    else:
        summary = (
            "The automated analysis detected relatively little "
            "phishing evidence. This does not guarantee that the "
            "email is legitimate or safe."
        )

        actions = [
            "Remain cautious with unexpected requests.",
            "Check the sender and destination of links before interacting with the email.",
            "Verify sensitive requests independently when appropriate.",
        ]

    return {
        "level": hybrid_level,
        "summary": summary,
        "heuristic_score": heuristic_score,
        "ml_probability": ml_probability,
        "evidence": evidence,
        "actions": actions,
    }
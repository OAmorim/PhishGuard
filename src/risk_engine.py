URL_WEIGHTS = {
    "insecure_protocol": 10,
    "ip_address_url": 25,
    "url_shortener": 15,
    "punycode_domain": 25,
    "suspicious_tld": 10,
}


KEYWORD_WEIGHTS = {
    "urgency": 10,
    "threat": 10,
    "credential_request": 20,
    "financial_request": 20,
    "call_to_action": 5,
}


HEADER_WEIGHTS = {
    "missing_sender": 10,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 5,
    "spf_failure": 15,
    "dkim_failure": 15,
    "dmarc_failure": 25,
    "spf_inconclusive": 3,
    "dkim_inconclusive": 3,
    "dmarc_inconclusive": 3,
}


def get_risk_level(score):
    """
    Convert the numeric score into a risk level.
    """

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def calculate_risk_score(
    url_results,
    keyword_results,
    header_results,
):
    """
    Combine indicators from the different analyzers
    into one heuristic risk score.
    """

    raw_score = 0
    breakdown = []
    counted_indicators = set()

    # Add URL indicators without counting the same type more than once
    for result in url_results:
        for indicator in result["indicators"]:
            indicator_type = indicator["type"]

            key = ("url", indicator_type)

            if key in counted_indicators:
                continue

            weight = URL_WEIGHTS.get(
                indicator_type,
                0,
            )

            if weight:
                raw_score += weight

                breakdown.append({
                    "source": "URL",
                    "indicator": indicator_type,
                    "points": weight,
                    "message": indicator["message"],
                })

                counted_indicators.add(key)

    # Add social engineering indicators
    for indicator in keyword_results:
        category = indicator["category"]

        key = ("keyword", category)

        if key in counted_indicators:
            continue

        weight = KEYWORD_WEIGHTS.get(
            category,
            0,
        )

        if weight:
            raw_score += weight

            breakdown.append({
                "source": "Language",
                "indicator": category,
                "points": weight,
                "message": indicator["description"],
            })

            counted_indicators.add(key)

    # Add header and authentication indicators
    for indicator in header_results["indicators"]:
        indicator_type = indicator["type"]

        key = ("header", indicator_type)

        if key in counted_indicators:
            continue

        weight = HEADER_WEIGHTS.get(
            indicator_type,
            0,
        )

        if weight:
            raw_score += weight

            breakdown.append({
                "source": "Header",
                "indicator": indicator_type,
                "points": weight,
                "message": indicator["message"],
            })

            counted_indicators.add(key)

    score = min(raw_score, 100)

    return {
        "score": score,
        "raw_score": raw_score,
        "level": get_risk_level(score),
        "breakdown": breakdown,
    }
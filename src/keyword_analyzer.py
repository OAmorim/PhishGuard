import re


PHISHING_PATTERNS = {
    "urgency": {
        "severity": "medium",
        "description": "Urgency or time pressure detected.",
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bas soon as possible\b",
            r"\bwithin \d+ hours?\b",
            r"\bact now\b",
            r"\bexpires? today\b",
            r"\btime[- ]sensitive\b",
        ],
    },

    "threat": {
        "severity": "medium",
        "description": "Threatening or fear-inducing language detected.",
        "patterns": [
            r"\baccount (?:has been |is )?suspended\b",
            r"\baccount (?:will be |is )?terminated\b",
            r"\baccount (?:has been |is )?locked\b",
            r"\bunauthori[sz]ed (?:access|activity)\b",
            r"\bfailure to (?:verify|respond|confirm)\b",
            r"\bpermanent(?:ly)? (?:suspension|termination)\b",
        ],
    },

    "credential_request": {
        "severity": "high",
        "description": "Credential or identity verification request detected.",
        "patterns": [
            r"\bverify your (?:account|identity)\b",
            r"\bconfirm your (?:account|identity)\b",
            r"\benter your password\b",
            r"\bupdate your password\b",
            r"\blog[ -]?in\b",
            r"\bsign[ -]?in\b",
            r"\bcredentials?\b",
            r"\bsecurity code\b",
        ],
    },

    "financial_request": {
        "severity": "high",
        "description": "Financial or payment-related request detected.",
        "patterns": [
            r"\bbank details?\b",
            r"\bpayment details?\b",
            r"\bwire transfer\b",
            r"\bbank transfer\b",
            r"\bmake a payment\b",
            r"\boverdue invoice\b",
            r"\bpayment failed\b",
            r"\bcredit card\b",
        ],
    },

    "call_to_action": {
        "severity": "low",
        "description": "Strong call-to-action language detected.",
        "patterns": [
            r"\bclick here\b",
            r"\bclick (?:the )?link\b",
            r"\bfollow (?:the|this) link\b",
            r"\bopen the attachment\b",
            r"\bdownload the attachment\b",
        ],
    },
}


def find_pattern_matches(text, patterns):
    """
    Find all unique phrases matching a group of regex patterns.
    """

    matches = []

    for pattern in patterns:
        found = re.finditer(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        for match in found:
            value = match.group(0)

            if value.lower() not in [
                existing.lower()
                for existing in matches
            ]:
                matches.append(value)

    return matches


def analyze_keywords(text):
    """
    Analyse text for common phishing and social engineering language.
    """

    if not text:
        return []

    indicators = []

    for category, config in PHISHING_PATTERNS.items():

        matches = find_pattern_matches(
            text,
            config["patterns"],
        )

        if matches:
            indicators.append({
                "category": category,
                "severity": config["severity"],
                "description": config["description"],
                "matches": matches,
            })

    return indicators
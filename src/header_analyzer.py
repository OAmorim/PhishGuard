import re
from email.utils import parseaddr

import tldextract


AUTHENTICATION_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)


def extract_email_domain(header_value):
    """
    Extract the domain from an email address stored in a header.
    """

    if not header_value:
        return ""

    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower()


def get_registered_domain(domain):
    """
    Reduce a hostname to its registered domain.
    """

    if not domain:
        return ""

    extracted = tldextract.extract(domain)

    if not extracted.domain:
        return domain.lower()

    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()

    return extracted.domain.lower()


def parse_authentication_results(authentication_header):
    """
    Extract SPF, DKIM and DMARC results from Authentication-Results.
    """

    if not authentication_header:
        return {}

    results = {}

    matches = AUTHENTICATION_PATTERN.findall(
        authentication_header
    )

    for protocol, result in matches:
        results[protocol.lower()] = result.lower()

    return results


def analyze_authentication_results(authentication_results):
    """
    Turn email authentication problems into security indicators.
    """

    indicators = []

    for protocol, result in authentication_results.items():

        if result == "pass":
            continue

        if protocol == "dmarc" and result == "fail":
            indicators.append({
                "type": "dmarc_failure",
                "severity": "high",
                "message": "DMARC authentication failed.",
            })

        elif protocol == "spf" and result in {"fail", "softfail"}:
            indicators.append({
                "type": "spf_failure",
                "severity": "medium",
                "message": (
                    f"SPF authentication returned {result}."
                ),
            })

        elif protocol == "dkim" and result == "fail":
            indicators.append({
                "type": "dkim_failure",
                "severity": "medium",
                "message": "DKIM authentication failed.",
            })

        elif result in {
            "neutral",
            "none",
            "temperror",
            "permerror",
        }:
            indicators.append({
                "type": f"{protocol}_inconclusive",
                "severity": "low",
                "message": (
                    f"{protocol.upper()} authentication "
                    f"returned {result}."
                ),
            })

    return indicators


def analyze_headers(email_data):
    """
    Analyse sender information and authentication results.
    """

    indicators = []

    from_domain = extract_email_domain(
        email_data.get("from", "")
    )

    reply_to_domain = extract_email_domain(
        email_data.get("reply_to", "")
    )

    return_path_domain = extract_email_domain(
        email_data.get("return_path", "")
    )

    from_registered = get_registered_domain(from_domain)
    reply_to_registered = get_registered_domain(reply_to_domain)
    return_path_registered = get_registered_domain(
        return_path_domain
    )

    if not from_domain:
        indicators.append({
            "type": "missing_sender",
            "severity": "medium",
            "message": (
                "The email does not contain a valid sender address."
            ),
        })

    if (
        from_registered
        and reply_to_registered
        and from_registered != reply_to_registered
    ):
        indicators.append({
            "type": "reply_to_mismatch",
            "severity": "medium",
            "message": (
                "The From and Reply-To addresses use "
                "different registered domains."
            ),
        })

    if (
        from_registered
        and return_path_registered
        and from_registered != return_path_registered
    ):
        indicators.append({
            "type": "return_path_mismatch",
            "severity": "low",
            "message": (
                "The From and Return-Path addresses use "
                "different registered domains."
            ),
        })

    authentication_results = parse_authentication_results(
        email_data.get("authentication_results", "")
    )

    indicators.extend(
        analyze_authentication_results(
            authentication_results
        )
    )

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "authentication_results": authentication_results,
        "indicators": indicators,
    }
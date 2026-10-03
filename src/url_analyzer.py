import ipaddress
import re
from urllib.parse import urlparse

import tldextract


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "work",
    "support",
    "zip",
    "mov",
}


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


def extract_urls(text):
    """
    Extract HTTP and HTTPS URLs from text.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Remove punctuation commonly found immediately after URLs
    cleaned_urls = []

    for url in urls:
        cleaned_url = url.rstrip(
            ".,;!?)"
        )

        cleaned_urls.append(
            cleaned_url
        )

    return cleaned_urls


def is_ip_address(hostname):
    """
    Check whether a hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:
        return False


def get_registered_domain(hostname):
    """
    Return the registered domain for a hostname.

    IP addresses are returned unchanged.
    """

    if not hostname:
        return ""

    if is_ip_address(hostname):
        return hostname

    extracted = tldextract.extract(
        hostname
    )

    if (
        extracted.domain
        and extracted.suffix
    ):
        return (
            f"{extracted.domain}."
            f"{extracted.suffix}"
        )

    if extracted.domain:
        return extracted.domain

    return hostname


def analyze_url(url):
    """
    Analyse a single URL and return suspicious indicators.

    Malformed URLs are tolerated instead of causing the
    application to crash.
    """

    indicators = []

    try:
        parsed = urlparse(
            url
        )

    except ValueError:
        return {
            "url": url,
            "hostname": "",
            "registered_domain": "",
            "indicators": [],
        }

    try:
        hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else ""
        )

    except ValueError:
        return {
            "url": url,
            "hostname": "",
            "registered_domain": "",
            "indicators": [],
        }

    registered_domain = (
        get_registered_domain(
            hostname
        )
        if hostname
        else ""
    )

    # Plain HTTP does not provide transport encryption
    if parsed.scheme.lower() == "http":
        indicators.append({
            "type": "insecure_protocol",
            "severity": "medium",
            "message": (
                "The URL uses HTTP instead of HTTPS."
            ),
        })

    # Phishing URLs sometimes use raw IP addresses
    if (
        hostname
        and is_ip_address(hostname)
    ):
        indicators.append({
            "type": "ip_address_url",
            "severity": "high",
            "message": (
                "The URL uses an IP address instead "
                "of a domain name."
            ),
        })

    # Shortened URLs can hide the real destination
    if (
        registered_domain
        in URL_SHORTENERS
    ):
        indicators.append({
            "type": "url_shortener",
            "severity": "medium",
            "message": (
                "The URL uses a known URL "
                "shortening service."
            ),
        })

    # Punycode may be used for lookalike domains
    if (
        hostname
        and "xn--" in hostname
    ):
        indicators.append({
            "type": "punycode_domain",
            "severity": "high",
            "message": (
                "The URL contains a Punycode "
                "domain, which may be used for "
                "lookalike domains."
            ),
        })

    # Some TLDs are frequently seen in suspicious URLs.
    # This alone does not mean that a URL is phishing.
    if hostname:
        extracted = tldextract.extract(
            hostname
        )

        suffix = (
            extracted.suffix.lower()
            if extracted.suffix
            else ""
        )

        if suffix in SUSPICIOUS_TLDS:
            indicators.append({
                "type": "suspicious_tld",
                "severity": "medium",
                "message": (
                    f"The URL uses the .{suffix} "
                    "top-level domain."
                ),
            })

    return {
        "url": url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "indicators": indicators,
    }


def analyze_urls(text):
    """
    Extract and analyse all URLs found in text.
    """

    urls = extract_urls(
        text
    )

    return [
        analyze_url(url)
        for url in urls
    ]
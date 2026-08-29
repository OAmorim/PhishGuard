import ipaddress
import re
from urllib.parse import urlparse

import tldextract


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)


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


def extract_urls(text):
    """
    Extract HTTP and HTTPS URLs from text.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Remove common punctuation that may appear after a URL
    cleaned_urls = [
        url.rstrip(".,;:!?)]}")
        for url in urls
    ]

    return list(dict.fromkeys(cleaned_urls))


def is_ip_address(hostname):
    """
    Check whether a hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_registered_domain(hostname):
    """
    Extract the registered domain from a hostname.
    """

    if not hostname:
        return ""

    extracted = tldextract.extract(hostname)

    if not extracted.domain:
        return ""

    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return extracted.domain


def analyze_url(url):
    """
    Analyse a URL and return detected phishing indicators.
    """

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()

    indicators = []

    if parsed.scheme.lower() == "http":
        indicators.append({
            "type": "insecure_protocol",
            "severity": "medium",
            "message": "URL uses HTTP instead of HTTPS.",
        })

    if is_ip_address(hostname):
        indicators.append({
            "type": "ip_address_url",
            "severity": "high",
            "message": "URL uses an IP address instead of a domain name.",
        })

    registered_domain = get_registered_domain(hostname)

    if registered_domain in URL_SHORTENERS:
        indicators.append({
            "type": "url_shortener",
            "severity": "medium",
            "message": "URL uses a known URL shortening service.",
        })

    if hostname.startswith("xn--") or ".xn--" in hostname:
        indicators.append({
            "type": "punycode_domain",
            "severity": "high",
            "message": "URL contains a Punycode domain.",
        })

    extracted = tldextract.extract(hostname)

    if extracted.suffix.lower() in SUSPICIOUS_TLDS:
        indicators.append({
            "type": "suspicious_tld",
            "severity": "medium",
            "message": (
                f"URL uses the potentially suspicious "
                f".{extracted.suffix} top-level domain."
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

    urls = extract_urls(text)

    return [
        analyze_url(url)
        for url in urls
    ]
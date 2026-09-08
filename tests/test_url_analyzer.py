from src.url_analyzer import analyze_url, extract_urls


def test_extract_urls():
    text = (
        "Click here: https://example.com/login "
        "or visit http://192.168.1.1/test"
    )

    urls = extract_urls(text)

    assert len(urls) == 2
    assert "https://example.com/login" in urls
    assert "http://192.168.1.1/test" in urls


def test_ip_address_url():
    result = analyze_url(
        "http://185.31.22.10/paypal/login"
    )

    indicator_types = [
        indicator["type"]
        for indicator in result["indicators"]
    ]

    assert "ip_address_url" in indicator_types
    assert "insecure_protocol" in indicator_types


def test_normal_https_url():
    result = analyze_url(
        "https://www.microsoft.com/security"
    )

    assert result["hostname"] == "www.microsoft.com"

    indicator_types = [
        indicator["type"]
        for indicator in result["indicators"]
    ]

    assert "ip_address_url" not in indicator_types
    assert "insecure_protocol" not in indicator_types

def test_url_shortener():
    result = analyze_url(
        "https://bit.ly/example"
    )

    indicator_types = [
        indicator["type"]
        for indicator in result["indicators"]
    ]

    assert "url_shortener" in indicator_types


def test_suspicious_tld():
    result = analyze_url(
        "https://account-verification.xyz/login"
    )

    indicator_types = [
        indicator["type"]
        for indicator in result["indicators"]
    ]

    assert "suspicious_tld" in indicator_types


def test_ip_registered_domain():
    result = analyze_url(
        "http://185.31.22.10/login"
    )

    assert result["registered_domain"] == "185.31.22.10"
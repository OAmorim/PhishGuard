from src.url_analyzer import (
    analyze_url,
    analyze_urls,
    extract_urls,
    get_registered_domain,
    is_ip_address,
)


def get_indicator_types(result):
    return {
        indicator["type"]
        for indicator in result["indicators"]
    }


def test_extract_urls():
    text = (
        "Visit https://example.com/login "
        "or http://test.example.org/page."
    )

    urls = extract_urls(
        text
    )

    assert (
        "https://example.com/login"
        in urls
    )

    assert (
        "http://test.example.org/page"
        in urls
    )


def test_ip_address_detection():
    assert is_ip_address(
        "185.31.22.10"
    ) is True

    assert is_ip_address(
        "example.com"
    ) is False

    assert (
        get_registered_domain(
            "185.31.22.10"
        )
        == "185.31.22.10"
    )


def test_ip_based_http_url():
    result = analyze_url(
        "http://185.31.22.10/login"
    )

    indicator_types = (
        get_indicator_types(
            result
        )
    )

    assert (
        result["hostname"]
        == "185.31.22.10"
    )

    assert (
        "insecure_protocol"
        in indicator_types
    )

    assert (
        "ip_address_url"
        in indicator_types
    )


def test_url_shortener_detection():
    result = analyze_url(
        "https://bit.ly/account-check"
    )

    indicator_types = (
        get_indicator_types(
            result
        )
    )

    assert (
        result["registered_domain"]
        == "bit.ly"
    )

    assert (
        "url_shortener"
        in indicator_types
    )


def test_punycode_and_suspicious_tld_detection():
    result = analyze_url(
        "http://xn--example-test.xyz/login"
    )

    indicator_types = (
        get_indicator_types(
            result
        )
    )

    assert (
        "punycode_domain"
        in indicator_types
    )

    assert (
        "suspicious_tld"
        in indicator_types
    )

    assert (
        "insecure_protocol"
        in indicator_types
    )


def test_clean_https_url():
    result = analyze_url(
        "https://www.microsoft.com/security"
    )

    assert (
        result["hostname"]
        == "www.microsoft.com"
    )

    assert (
        result["registered_domain"]
        == "microsoft.com"
    )

    assert (
        result["indicators"]
        == []
    )


def test_analyze_multiple_urls():
    text = (
        "Safe link: "
        "https://www.microsoft.com/security "
        "Suspicious link: "
        "http://185.31.22.10/login"
    )

    results = analyze_urls(
        text
    )

    assert len(results) == 2

    assert (
        results[0]["registered_domain"]
        == "microsoft.com"
    )

    second_indicators = (
        get_indicator_types(
            results[1]
        )
    )

    assert (
        "ip_address_url"
        in second_indicators
    )


def test_invalid_ipv6_url_does_not_crash():
    result = analyze_url(
        "http://[invalid-ipv6"
    )

    assert (
        result["url"]
        == "http://[invalid-ipv6"
    )

    assert (
        result["hostname"]
        == ""
    )

    assert (
        result["registered_domain"]
        == ""
    )

    assert (
        result["indicators"]
        == []
    )
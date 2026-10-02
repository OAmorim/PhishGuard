from email import policy
from email.parser import BytesParser, Parser

from bs4 import BeautifulSoup


def extract_body(message):
    """
    Extract the readable body from an email message.
    """

    if message.is_multipart():
        part = message.get_body(
            preferencelist=("plain", "html")
        )

        if part is None:
            return ""

        content = part.get_content()

        if part.get_content_type() == "text/html":
            return BeautifulSoup(
                content,
                "html.parser",
            ).get_text(" ", strip=True)

        return content

    content = message.get_content()

    if message.get_content_type() == "text/html":
        return BeautifulSoup(
            content,
            "html.parser",
        ).get_text(" ", strip=True)

    return content


def parse_email(raw_email):
    """
    Parse a raw email supplied as text or bytes.
    """

    if isinstance(raw_email, bytes):
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email)

    elif isinstance(raw_email, str):
        message = Parser(
            policy=policy.default
        ).parsestr(raw_email)

    else:
        raise TypeError(
            "Email input must be a string or bytes."
        )

    authentication_headers = message.get_all(
        "Authentication-Results",
        [],
    )

    email_data = {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "subject": message.get("Subject", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "authentication_results": " ".join(
            str(header)
            for header in authentication_headers
        ),
        "body": extract_body(message),
    }

    return email_data
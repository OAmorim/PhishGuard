from email import policy
from email.parser import Parser

from bs4 import BeautifulSoup


def extract_body(message):
    """
    Extract the readable body from an email message.
    """

    if message.is_multipart():
        part = message.get_body(preferencelist=("plain", "html"))

        if part is None:
            return ""

        content = part.get_content()

        if part.get_content_type() == "text/html":
            return BeautifulSoup(content, "html.parser").get_text(
                " ",
                strip=True
            )

        return content

    content = message.get_content()

    if message.get_content_type() == "text/html":
        return BeautifulSoup(content, "html.parser").get_text(
            " ",
            strip=True
        )

    return content


def parse_email(raw_email):
    """
    Parse a raw email and extract relevant information.
    """

    parser = Parser(policy=policy.default)
    message = parser.parsestr(raw_email)

    email_data = {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "subject": message.get("Subject", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "body": extract_body(message),
    }

    return email_data
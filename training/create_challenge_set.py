from pathlib import Path
import csv


CHALLENGE_DIR = Path("data/challenge")
METADATA_PATH = CHALLENGE_DIR / "metadata.csv"


CASES = [
    {
        "id": "legitimate_webinar",
        "label": "LEGITIMATE",
        "scenario": "Legitimate webinar invitation",
        "content": """From: Events Team <events@example.com>
To: user@example.com
Reply-To: events@example.com
Return-Path: events@example.com
Subject: Upcoming webinar
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Dear Drew,

We are pleased to inform you about our upcoming webinar.

Register now to secure your spot.

Kind regards,
Events Team
""",
    },
    {
        "id": "legitimate_purchase",
        "label": "LEGITIMATE",
        "scenario": "Legitimate purchase confirmation",
        "content": """From: Shop <orders@example.com>
To: user@example.com
Reply-To: orders@example.com
Return-Path: orders@example.com
Subject: Order confirmation
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Dear Customer,

Thank you for your purchase.

Your order will be shipped soon.

You can view your order at:

https://example.com/orders

Kind regards,
Customer Service
""",
    },
    {
        "id": "legitimate_newsletter",
        "label": "LEGITIMATE",
        "scenario": "Legitimate newsletter",
        "content": """From: Newsletter <newsletter@example.com>
To: user@example.com
Reply-To: newsletter@example.com
Return-Path: newsletter@example.com
Subject: Monthly newsletter
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Welcome to our newsletter!

Stay tuned for the latest updates and offers.

Visit our website:

https://example.com/news
""",
    },
    {
        "id": "legitimate_security_update",
        "label": "LEGITIMATE",
        "scenario": "Legitimate account security notification",
        "content": """From: Security Team <security@example.com>
To: user@example.com
Reply-To: security@example.com
Return-Path: security@example.com
Subject: Security information updated
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Hello,

Your account security information was recently updated.

If you made this change, no further action is required.

You can review your security settings at:

https://example.com/security

Security Team
""",
    },
    {
        "id": "legitimate_shipping",
        "label": "LEGITIMATE",
        "scenario": "Legitimate shipping notification",
        "content": """From: Shipping <shipping@example.com>
To: user@example.com
Reply-To: shipping@example.com
Return-Path: shipping@example.com
Subject: Your order has shipped
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Hello,

Your order has been shipped and is currently on its way.

Track your delivery here:

https://example.com/tracking

Thank you for shopping with us.
""",
    },
    {
        "id": "legitimate_meeting",
        "label": "LEGITIMATE",
        "scenario": "Normal business meeting reminder",
        "content": """From: Project Team <project@example.com>
To: user@example.com
Reply-To: project@example.com
Return-Path: project@example.com
Subject: Project meeting tomorrow
Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass

Hello,

This is a reminder that our project meeting is scheduled for tomorrow at 10:00.

We will review the current tasks and discuss next week's priorities.

Regards,
Project Team
""",
    },
    {
        "id": "phishing_paypal",
        "label": "PHISHING",
        "scenario": "Credential phishing with spoofed sender",
        "content": """From: PayPal Security <security@paypal.com>
To: user@example.com
Reply-To: verify@malicious-domain.xyz
Return-Path: bounce@malicious-domain.xyz
Subject: URGENT: Your PayPal account has been suspended
Authentication-Results: mail.example.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

Your account has been suspended.

You must verify your identity immediately:

http://185.31.22.10/paypal/login

Failure to verify your account within 24 hours will result in permanent account termination.

PayPal Security Team
""",
    },
    {
        "id": "phishing_microsoft",
        "label": "PHISHING",
        "scenario": "Credential phishing using a lookalike domain",
        "content": """From: Microsoft Security <security@microsoft.com>
To: user@example.com
Reply-To: support@microsoft-security-support.xyz
Return-Path: support@microsoft-security-support.xyz
Subject: Verify your Microsoft account
Authentication-Results: mail.example.com; spf=fail; dkim=fail; dmarc=fail

Your Microsoft account requires immediate verification.

Please confirm your password and account information here:

http://microsoft-security-support.xyz/login

Failure to verify your account may result in loss of access.
""",
    },
    {
        "id": "phishing_invoice",
        "label": "PHISHING",
        "scenario": "Subtle invoice phishing",
        "content": """From: Billing Department <billing@invoice-service.example>
To: user@example.com
Subject: Outstanding invoice

Your invoice is attached.

Please review and pay promptly to avoid penalties.

Payment is required as soon as possible.
""",
    },
    {
        "id": "phishing_wire_transfer",
        "label": "PHISHING",
        "scenario": "Business email compromise payment request",
        "content": """From: Managing Director <director@company.example>
To: employee@example.com
Reply-To: director.finance@external-mail.xyz
Subject: Urgent payment request

I need you to process an urgent payment today.

Please arrange the bank transfer immediately.

This is confidential and must be completed before the end of the day.

Send confirmation once the payment has been made.
""",
    },
    {
        "id": "phishing_shortened_url",
        "label": "PHISHING",
        "scenario": "Phishing using a URL shortener",
        "content": """From: Account Support <support@example.com>
To: user@example.com
Subject: Immediate account verification

Unusual activity has been detected on your account.

Verify your account immediately to prevent suspension:

https://bit.ly/account-verification

Failure to act may result in your account being disabled.
""",
    },
    {
        "id": "phishing_punycode",
        "label": "PHISHING",
        "scenario": "Phishing using an internationalised lookalike domain",
        "content": """From: Payment Security <security@payment.example>
To: user@example.com
Subject: Payment verification required

We detected a problem with your recent payment.

Confirm your account information immediately:

http://xn--paypa-4ve.com/login

Your account may be restricted if verification is not completed.
""",
    },
]


def main():
    CHALLENGE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = []

    for case in CASES:
        label_folder = (
            "phishing"
            if case["label"] == "PHISHING"
            else "legitimate"
        )

        output_dir = (
            CHALLENGE_DIR / label_folder
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path = (
            output_dir
            / f"{case['id']}.eml"
        )

        file_path.write_text(
            case["content"].strip() + "\n",
            encoding="utf-8",
        )

        rows.append({
            "id": case["id"],
            "label": case["label"],
            "scenario": case["scenario"],
            "file": file_path.as_posix(),
        })

    with open(
        METADATA_PATH,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "id",
                "label",
                "scenario",
                "file",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    print(
        f"Created {len(CASES)} challenge emails."
    )

    print(
        f"Metadata saved to {METADATA_PATH}"
    )


if __name__ == "__main__":
    main()
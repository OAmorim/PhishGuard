import streamlit as st

from src.email_parser import parse_email
from src.url_analyzer import analyze_urls


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
)


st.title("🛡️ PhishGuard")
st.subheader("AI-Assisted Phishing Email Analyzer")

st.write(
    "Paste a suspicious email below to analyse its content, "
    "headers, URLs, and phishing indicators."
)


raw_email = st.text_area(
    "Email content",
    height=350,
    placeholder=(
        "From: sender@example.com\n"
        "To: user@example.com\n"
        "Subject: Example email\n\n"
        "Paste the email body here..."
    ),
)


if st.button("Analyse Email", type="primary"):

    if not raw_email.strip():
        st.warning("Please paste an email before starting the analysis.")

    else:
        # Parse the raw email.
        email_data = parse_email(raw_email)

        # Analyse URLs found in the email body.
        url_results = analyze_urls(email_data["body"])

        st.success("Email parsed successfully.")

        # EMAIL INFORMATION
       
        st.divider()
        st.subheader("📧 Email Information")

        col1, col2 = st.columns(2)

        with col1:
            st.write("**From:**")
            st.write(email_data["from"] or "Not available")

            st.write("**Subject:**")
            st.write(email_data["subject"] or "Not available")

        with col2:
            st.write("**To:**")
            st.write(email_data["to"] or "Not available")

            st.write("**Reply-To:**")
            st.write(email_data["reply_to"] or "Not available")

        # URL ANALYSIS

        st.divider()
        st.subheader("🔗 URL Analysis")

        if not url_results:
            st.info("No URLs were detected in the email body.")

        else:
            suspicious_url_count = sum(
                1
                for result in url_results
                if result["indicators"]
            )

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "URLs detected",
                    len(url_results),
                )

            with col2:
                st.metric(
                    "URLs with indicators",
                    suspicious_url_count,
                )

            for result in url_results:

                st.markdown(f"### {result['url']}")

                st.write(
                    f"**Hostname:** "
                    f"{result['hostname'] or 'Unknown'}"
                )

                st.write(
                    f"**Registered domain:** "
                    f"{result['registered_domain'] or 'Unknown'}"
                )

                if not result["indicators"]:
                    st.success(
                        "No suspicious URL indicators detected."
                    )

                else:
                    for indicator in result["indicators"]:

                        severity = indicator["severity"]

                        if severity == "high":
                            st.error(
                                f"🔴 HIGH — {indicator['message']}"
                            )

                        elif severity == "medium":
                            st.warning(
                                f"🟠 MEDIUM — {indicator['message']}"
                            )

                        else:
                            st.info(
                                f"🔵 LOW — {indicator['message']}"
                            )

                st.divider()

       # EMAIL BODY
       
        st.subheader("📝 Extracted Body")

        st.text_area(
            "Body",
            value=email_data["body"],
            height=250,
            disabled=True,
        )
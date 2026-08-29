import streamlit as st

from src.email_parser import parse_email


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ PhishGuard")

st.subheader("AI-Assisted Phishing Email Analyzer")

st.write(
    "Paste a suspicious email below to analyse its content, "
    "headers, URLs and phishing indicators."
)


raw_email = st.text_area(
    "Email content",
    height=350,
    placeholder=(
        "From: sender@example.com\n"
        "To: user@example.com\n"
        "Subject: Example email\n\n"
        "Paste the email body here..."
    )
)


if st.button("Analyse Email", type="primary"):

    if not raw_email.strip():
        st.warning("Please paste an email before starting the analysis.")

    else:
        email_data = parse_email(raw_email)

        st.success("Email parsed successfully.")

        st.divider()

        st.subheader("Email Information")

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

        st.divider()

        st.subheader("Extracted Body")

        st.text_area(
            "Body",
            value=email_data["body"],
            height=250,
            disabled=True
        )
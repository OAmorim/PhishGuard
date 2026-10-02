import streamlit as st

from src.email_parser import parse_email
from src.header_analyzer import analyze_headers
from src.keyword_analyzer import analyze_keywords
from src.ml_classifier import classify_email, load_model
from src.risk_engine import calculate_risk_score
from src.url_analyzer import analyze_urls


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def get_ml_model():
    """
    Load the trained ML model once and reuse it across Streamlit reruns.
    """

    return load_model()


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
    ),
)


if st.button("Analyse Email", type="primary"):

    if not raw_email.strip():
        st.warning(
            "Please paste an email before starting the analysis."
        )

    else:
        # Parse the raw email into fields used by the analyzers
        email_data = parse_email(raw_email)

        # Analyse URLs found in the email body
        url_results = analyze_urls(
            email_data["body"]
        )

        # Analyse the subject and body for social engineering language
        text_to_analyze = (
            f"{email_data['subject']} "
            f"{email_data['body']}"
        )

        keyword_results = analyze_keywords(
            text_to_analyze
        )

        # Analyse sender information and authentication headers
        header_results = analyze_headers(
            email_data
        )

        # Combine the rule-based indicators into a heuristic risk score
        risk_result = calculate_risk_score(
            url_results,
            keyword_results,
            header_results,
        )

        # The ML model was trained using email bodies, so only the body
        # is passed to the classifier for now
        try:
            ml_model = get_ml_model()

            ml_result = classify_email(
                email_data["body"],
                ml_model,
            )

        except FileNotFoundError:
            ml_result = None

        st.success("Email analysed successfully.")

        # Show the heuristic result first
        st.divider()
        st.subheader("🛡️ Heuristic Risk Assessment")

        risk_score = risk_result["score"]
        risk_level = risk_result["level"]

        risk_col1, risk_col2 = st.columns(2)

        with risk_col1:
            st.metric(
                "Risk Score",
                f"{risk_score}/100",
            )

        with risk_col2:
            st.metric(
                "Risk Level",
                risk_level,
            )

        st.progress(
            risk_score / 100
        )

        if risk_level == "HIGH":
            st.error(
                "🔴 HIGH RISK — Multiple phishing indicators "
                "were detected in this email."
            )

        elif risk_level == "MEDIUM":
            st.warning(
                "🟠 MEDIUM RISK — Some suspicious indicators "
                "were detected and should be reviewed."
            )

        else:
            st.success(
                "🟢 LOW RISK — Few or no suspicious indicators "
                "were detected."
            )

        st.caption(
            "This score is calculated using heuristic rules based "
            "on the detected email, URL and header indicators."
        )

        if risk_result["breakdown"]:

            with st.expander(
                "View risk score breakdown"
            ):

                for item in risk_result["breakdown"]:

                    st.write(
                        f"**+{item['points']} — "
                        f"{item['source']}**"
                    )

                    st.write(
                        item["message"]
                    )

        else:
            st.info(
                "No weighted phishing indicators contributed "
                "to the risk score."
            )

        # Show the ML result separately from the heuristic score
        st.divider()
        st.subheader("🤖 Machine Learning Analysis")

        if ml_result is None:
            st.warning(
                "The trained ML model was not found. "
                "Run training/train_model.py before using "
                "the machine learning analysis."
            )

        else:
            phishing_probability = (
                ml_result["phishing_probability"]
            )

            prediction_label = (
                ml_result["label"]
            )

            ml_col1, ml_col2 = st.columns(2)

            with ml_col1:
                st.metric(
                    "Phishing Probability",
                    f"{phishing_probability * 100:.1f}%",
                )

            with ml_col2:
                st.metric(
                    "Model Prediction",
                    prediction_label,
                )

            st.progress(
                phishing_probability
            )

            if prediction_label == "PHISHING":
                st.error(
                    "🔴 The ML model classifies this "
                    "email as phishing."
                )

            else:
                st.success(
                    "🟢 The ML model classifies this "
                    "email as legitimate."
                )

            st.caption(
                "The machine learning prediction currently uses "
                "a 50% decision threshold and is shown "
                "independently from the heuristic risk score."
            )

        # Show the main email information
        st.divider()
        st.subheader("📧 Email Information")

        email_col1, email_col2 = st.columns(2)

        with email_col1:
            st.write("**From:**")
            st.write(
                email_data["from"]
                or "Not available"
            )

            st.write("**Subject:**")
            st.write(
                email_data["subject"]
                or "Not available"
            )

        with email_col2:
            st.write("**To:**")
            st.write(
                email_data["to"]
                or "Not available"
            )

            st.write("**Reply-To:**")
            st.write(
                email_data["reply_to"]
                or "Not available"
            )

        # Show sender domains and authentication results
        st.divider()
        st.subheader("📨 Header Analysis")

        header_col1, header_col2, header_col3 = (
            st.columns(3)
        )

        with header_col1:
            st.write("**From domain**")
            st.write(
                header_results["from_domain"]
                or "Not available"
            )

        with header_col2:
            st.write("**Reply-To domain**")
            st.write(
                header_results["reply_to_domain"]
                or "Not available"
            )

        with header_col3:
            st.write("**Return-Path domain**")
            st.write(
                header_results["return_path_domain"]
                or "Not available"
            )

        st.write("**Email Authentication**")

        authentication_results = header_results[
            "authentication_results"
        ]

        if authentication_results:

            auth_col1, auth_col2, auth_col3 = (
                st.columns(3)
            )

            with auth_col1:
                spf = authentication_results.get(
                    "spf",
                    "Not available",
                )

                st.write(
                    f"SPF: **{spf.upper()}**"
                )

            with auth_col2:
                dkim = authentication_results.get(
                    "dkim",
                    "Not available",
                )

                st.write(
                    f"DKIM: **{dkim.upper()}**"
                )

            with auth_col3:
                dmarc = authentication_results.get(
                    "dmarc",
                    "Not available",
                )

                st.write(
                    f"DMARC: **{dmarc.upper()}**"
                )

        else:
            st.info(
                "No SPF, DKIM or DMARC results were found "
                "in the email headers."
            )

        if header_results["indicators"]:

            for indicator in header_results["indicators"]:

                severity = indicator["severity"]
                message = indicator["message"]

                if severity == "high":
                    st.error(
                        f"🔴 HIGH — {message}"
                    )

                elif severity == "medium":
                    st.warning(
                        f"🟠 MEDIUM — {message}"
                    )

                else:
                    st.info(
                        f"🔵 LOW — {message}"
                    )

        else:
            st.success(
                "No suspicious header indicators detected."
            )

        # Show URL analysis
        st.divider()
        st.subheader("🔗 URL Analysis")

        if not url_results:
            st.info(
                "No URLs were detected in the email body."
            )

        else:
            suspicious_url_count = sum(
                1
                for result in url_results
                if result["indicators"]
            )

            url_col1, url_col2 = st.columns(2)

            with url_col1:
                st.metric(
                    "URLs detected",
                    len(url_results),
                )

            with url_col2:
                st.metric(
                    "URLs with indicators",
                    suspicious_url_count,
                )

            for result in url_results:

                st.markdown(
                    f"### {result['url']}"
                )

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
                        message = indicator["message"]

                        if severity == "high":
                            st.error(
                                f"🔴 HIGH — {message}"
                            )

                        elif severity == "medium":
                            st.warning(
                                f"🟠 MEDIUM — {message}"
                            )

                        else:
                            st.info(
                                f"🔵 LOW — {message}"
                            )

        # Show social engineering and suspicious language indicators
        st.divider()
        st.subheader(
            "🧠 Social Engineering Analysis"
        )

        if not keyword_results:
            st.success(
                "No common social engineering "
                "indicators detected."
            )

        else:
            for indicator in keyword_results:

                severity = indicator["severity"]

                matches = ", ".join(
                    indicator["matches"]
                )

                message = (
                    f"{indicator['description']} "
                    f"Detected: {matches}"
                )

                if severity == "high":
                    st.error(
                        f"🔴 HIGH — {message}"
                    )

                elif severity == "medium":
                    st.warning(
                        f"🟠 MEDIUM — {message}"
                    )

                else:
                    st.info(
                        f"🔵 LOW — {message}"
                    )

        # Keep the extracted body visible for manual inspection
        st.divider()
        st.subheader("📝 Extracted Body")

        st.text_area(
            "Body",
            value=email_data["body"],
            height=250,
            disabled=True,
        )
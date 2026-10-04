import streamlit as st

from src.email_parser import parse_email
from src.explanation_engine import build_explanation
from src.header_analyzer import analyze_headers
from src.hybrid_engine import calculate_hybrid_assessment
from src.keyword_analyzer import analyze_keywords
from src.llm_explainer import generate_llm_explanation
from src.ml_classifier import classify_email, load_model
from src.risk_engine import calculate_risk_score
from src.url_analyzer import analyze_urls


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
)


st.markdown(
    """
    <style>
        .block-container {
            max-width: 1200px;
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        div[data-testid="stMetric"] {
            background-color: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 1rem;
            border-radius: 0.75rem;
        }

        div[data-testid="stMetricLabel"] {
            font-weight: 600;
        }

        .phishguard-subtitle {
            color: #9ca3af;
            margin-top: -0.5rem;
            margin-bottom: 1.5rem;
            font-size: 1.05rem;
        }

        .section-description {
            color: #9ca3af;
            font-size: 0.9rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_ml_model():
    """
    Load the trained ML model once and reuse it across
    Streamlit reruns.
    """

    return load_model()


st.title("🛡️ PhishGuard")

st.markdown(
    """
    <p class="phishguard-subtitle">
        AI-Assisted Phishing Email Analyzer
    </p>
    """,
    unsafe_allow_html=True,
)

st.write(
    "Analyse an email by pasting its raw content "
    "or uploading an `.eml` file."
)


input_method = st.radio(
    "Choose input method",
    [
        "Paste email",
        "Upload .eml",
    ],
    horizontal=True,
)


email_input = None


if input_method == "Paste email":

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

    if raw_email.strip():
        email_input = raw_email


else:

    uploaded_file = st.file_uploader(
        "Upload email",
        type=["eml"],
        help=(
            "Upload an email saved in .eml format."
        ),
    )

    if uploaded_file is not None:
        email_input = uploaded_file.getvalue()

        st.info(
            f"Loaded file: {uploaded_file.name}"
        )


# Optional local LLM explanation.
# The LLM explains the existing result but does not classify the email.
use_llm_explanation = st.checkbox(
    "Generate local AI analyst explanation",
    value=False,
    help=(
        "Uses a local Ollama model to explain the existing "
        "PhishGuard assessment. The LLM does not perform "
        "the phishing classification."
    ),
)


if use_llm_explanation:
    st.caption(
        "The explanation is generated locally with Ollama. "
        "Only structured PhishGuard analysis results are sent "
        "to the LLM, not the raw email body."
    )


if st.button(
    "Analyse Email",
    type="primary",
):

    if email_input is None:
        st.warning(
            "Please paste an email or upload an .eml "
            "file before starting the analysis."
        )

    else:
        # Parse the email into fields used by the analyzers
        email_data = parse_email(
            email_input
        )

        # Analyse URLs found in the email body
        url_results = analyze_urls(
            email_data["body"]
        )

        # Analyse subject and body for social engineering language
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

        # Calculate the heuristic phishing risk
        risk_result = calculate_risk_score(
            url_results,
            keyword_results,
            header_results,
        )

        ml_result = None
        hybrid_result = None
        explanation_result = None
        llm_explanation = None
        llm_error = None

        # Run ML and hybrid analysis
        try:
            ml_model = get_ml_model()

            ml_result = classify_email(
                email_data["body"],
                ml_model,
            )

            hybrid_result = (
                calculate_hybrid_assessment(
                    risk_result,
                    ml_result,
                )
            )

            explanation_result = build_explanation(
                risk_result,
                ml_result,
                hybrid_result,
            )

        except FileNotFoundError:
            ml_result = None
            hybrid_result = None
            explanation_result = None

        # Generate the optional LLM explanation only after
        # the detection pipeline has finished.
        if (
            use_llm_explanation
            and hybrid_result is not None
            and ml_result is not None
        ):
            try:
                with st.spinner(
                    "Generating local AI analyst explanation..."
                ):
                    llm_explanation = (
                        generate_llm_explanation(
                            risk_result,
                            ml_result,
                            hybrid_result,
                        )
                    )

            except (
                ConnectionError,
                RuntimeError,
            ) as exc:
                llm_error = str(exc)

        st.success(
            "Email analysed successfully."
        )

        # Final assessment
        st.divider()
        st.subheader("🧩 Final Assessment")

        if hybrid_result is None:
            st.warning(
                "The final assessment is unavailable "
                "because the machine learning model "
                "could not be loaded."
            )

        else:
            hybrid_level = (
                hybrid_result["level"]
            )

            with st.container(
                border=True
            ):

                if hybrid_level == "HIGH":
                    st.error(
                        "🔴 STRONG PHISHING EVIDENCE"
                    )

                elif hybrid_level == "REVIEW":
                    st.warning(
                        "🟠 MANUAL REVIEW RECOMMENDED"
                    )

                else:
                    st.success(
                        "🟢 LOW DETECTED EVIDENCE"
                    )

                st.write(
                    explanation_result["summary"]
                )

                metric_col1, metric_col2, metric_col3 = (
                    st.columns(3)
                )

                with metric_col1:
                    st.metric(
                        "Final assessment",
                        hybrid_level,
                    )

                with metric_col2:
                    st.metric(
                        "Heuristic score",
                        (
                            f"{explanation_result['heuristic_score']}"
                            "/100"
                        ),
                    )

                with metric_col3:
                    st.metric(
                        "ML phishing probability",
                        (
                            f"{explanation_result['ml_probability'] * 100:.1f}%"
                        ),
                    )

                # Detailed evidence
                with st.expander(
                    "🔎 Why this result?",
                    expanded=(
                        hybrid_level == "HIGH"
                    ),
                ):

                    if explanation_result[
                        "evidence"
                    ]:

                        for evidence in (
                            explanation_result[
                                "evidence"
                            ]
                        ):
                            st.markdown(
                                f"- **{evidence['source']}** — "
                                f"{evidence['message']} "
                                f"`+{evidence['points']} points`"
                            )

                    else:
                        st.info(
                            "No weighted heuristic phishing "
                            "indicators were detected."
                        )

                # Deterministic recommended actions
                st.markdown(
                    "#### Recommended Actions"
                )

                for action in (
                    explanation_result[
                        "actions"
                    ]
                ):
                    st.markdown(
                        f"- {action}"
                    )

                # Optional local LLM explanation
                st.markdown(
                    "#### 🤖 AI Analyst Explanation"
                )

                if not use_llm_explanation:
                    st.caption(
                        "Enable the local AI analyst explanation "
                        "before analysing the email to generate "
                        "an additional natural-language summary."
                    )

                elif llm_explanation:

                    with st.container(
                        border=True
                    ):
                        st.markdown(
                            llm_explanation
                        )

                    st.caption(
                        "Generated locally using Ollama. "
                        "The LLM explains the existing assessment "
                        "and does not determine the classification."
                    )

                elif llm_error:
                    st.warning(
                        llm_error
                    )

                    st.caption(
                        "The phishing analysis above is still "
                        "valid. Only the optional LLM explanation "
                        "could not be generated."
                    )

                else:
                    st.info(
                        "No AI analyst explanation "
                        "was generated."
                    )

                st.caption(
                    "PhishGuard combines heuristic indicators and "
                    "machine learning to support email triage. "
                    "The result does not guarantee that an email is "
                    "safe or malicious."
                )

        # Heuristic analysis
        st.divider()
        st.subheader(
            "🛡️ Heuristic Risk Assessment"
        )

        risk_score = risk_result[
            "score"
        ]

        risk_level = risk_result[
            "level"
        ]

        risk_col1, risk_col2 = (
            st.columns(2)
        )

        with risk_col1:
            st.metric(
                "Risk score",
                f"{risk_score}/100",
            )

        with risk_col2:
            st.metric(
                "Risk level",
                risk_level,
            )

        st.progress(
            risk_score / 100
        )

        if risk_level == "HIGH":
            st.error(
                "🔴 HIGH — Multiple suspicious "
                "phishing indicators were detected."
            )

        elif risk_level == "MEDIUM":
            st.warning(
                "🟠 MEDIUM — Some suspicious "
                "indicators were detected and "
                "should be reviewed."
            )

        else:
            st.success(
                "🟢 LOW DETECTED EVIDENCE — "
                "Few or no heuristic phishing "
                "indicators were detected."
            )

            st.caption(
                "A low heuristic score does not mean "
                "that the email is guaranteed to be safe."
            )

        st.caption(
            "The heuristic score is calculated from "
            "detected URL, language and email header "
            "indicators."
        )

        if risk_result[
            "breakdown"
        ]:

            with st.expander(
                "View risk score breakdown"
            ):

                for item in (
                    risk_result[
                        "breakdown"
                    ]
                ):

                    st.write(
                        f"**+{item['points']} — "
                        f"{item['source']}**"
                    )

                    st.write(
                        item["message"]
                    )

        else:
            st.info(
                "No weighted phishing indicators "
                "contributed to the heuristic score."
            )

        # Machine learning analysis
        st.divider()
        st.subheader(
            "🤖 Machine Learning Analysis"
        )

        if ml_result is None:
            st.warning(
                "The trained ML model was not found. "
                "Run training/train_model.py before "
                "using the machine learning analysis."
            )

        else:
            phishing_probability = (
                ml_result[
                    "phishing_probability"
                ]
            )

            prediction_label = (
                ml_result[
                    "label"
                ]
            )

            ml_col1, ml_col2 = (
                st.columns(2)
            )

            with ml_col1:
                st.metric(
                    "Phishing probability",
                    (
                        f"{phishing_probability * 100:.1f}%"
                    ),
                )

            with ml_col2:
                st.metric(
                    "Model prediction",
                    prediction_label,
                )

            st.progress(
                phishing_probability
            )

            if prediction_label == "PHISHING":
                st.warning(
                    "The ML model detected patterns "
                    "associated with phishing emails."
                )

            else:
                st.info(
                    "The ML model did not classify "
                    "this email as phishing."
                )

            st.caption(
                "The machine learning result uses a "
                "50% decision threshold. It is an "
                "independent signal and should not be "
                "treated as proof that an email is "
                "legitimate or malicious."
            )

        # Email information
        st.divider()

        with st.expander(
            "📧 Email Information",
            expanded=True,
        ):

            email_col1, email_col2 = (
                st.columns(2)
            )

            with email_col1:
                st.write(
                    "**From:**"
                )

                st.write(
                    email_data["from"]
                    or "Not available"
                )

                st.write(
                    "**Subject:**"
                )

                st.write(
                    email_data["subject"]
                    or "Not available"
                )

            with email_col2:
                st.write(
                    "**To:**"
                )

                st.write(
                    email_data["to"]
                    or "Not available"
                )

                st.write(
                    "**Reply-To:**"
                )

                st.write(
                    email_data["reply_to"]
                    or "Not available"
                )

        # Header analysis
        st.divider()

        with st.expander(
            "📨 Header Analysis",
            expanded=True,
        ):

            header_col1, header_col2, header_col3 = (
                st.columns(3)
            )

            with header_col1:
                st.write(
                    "**From domain**"
                )

                st.write(
                    header_results[
                        "from_domain"
                    ]
                    or "Not available"
                )

            with header_col2:
                st.write(
                    "**Reply-To domain**"
                )

                st.write(
                    header_results[
                        "reply_to_domain"
                    ]
                    or "Not available"
                )

            with header_col3:
                st.write(
                    "**Return-Path domain**"
                )

                st.write(
                    header_results[
                        "return_path_domain"
                    ]
                    or "Not available"
                )

            st.write(
                "**Email Authentication**"
            )

            authentication_results = (
                header_results[
                    "authentication_results"
                ]
            )

            if authentication_results:

                auth_col1, auth_col2, auth_col3 = (
                    st.columns(3)
                )

                with auth_col1:
                    spf = (
                        authentication_results.get(
                            "spf",
                            "Not available",
                        )
                    )

                    st.write(
                        f"SPF: **{spf.upper()}**"
                    )

                with auth_col2:
                    dkim = (
                        authentication_results.get(
                            "dkim",
                            "Not available",
                        )
                    )

                    st.write(
                        f"DKIM: **{dkim.upper()}**"
                    )

                with auth_col3:
                    dmarc = (
                        authentication_results.get(
                            "dmarc",
                            "Not available",
                        )
                    )

                    st.write(
                        f"DMARC: **{dmarc.upper()}**"
                    )

            else:
                st.info(
                    "No SPF, DKIM or DMARC results "
                    "were found in the email headers."
                )

            if header_results[
                "indicators"
            ]:

                for indicator in (
                    header_results[
                        "indicators"
                    ]
                ):

                    severity = (
                        indicator[
                            "severity"
                        ]
                    )

                    message = (
                        indicator[
                            "message"
                        ]
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

            else:
                st.success(
                    "No suspicious header "
                    "indicators detected."
                )

        # URL analysis
        st.divider()

        with st.expander(
            "🔗 URL Analysis",
            expanded=True,
        ):

            if not url_results:
                st.info(
                    "No URLs were detected "
                    "in the email body."
                )

            else:
                suspicious_url_count = sum(
                    1
                    for result in url_results
                    if result["indicators"]
                )

                url_col1, url_col2 = (
                    st.columns(2)
                )

                with url_col1:
                    st.metric(
                        "URLs detected",
                        len(
                            url_results
                        ),
                    )

                with url_col2:
                    st.metric(
                        "URLs with indicators",
                        suspicious_url_count,
                    )

                for result in (
                    url_results
                ):

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

                    if not result[
                        "indicators"
                    ]:
                        st.success(
                            "No suspicious URL "
                            "indicators detected."
                        )

                    else:
                        for indicator in (
                            result[
                                "indicators"
                            ]
                        ):

                            severity = (
                                indicator[
                                    "severity"
                                ]
                            )

                            message = (
                                indicator[
                                    "message"
                                ]
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

        # Social engineering analysis
        st.divider()

        with st.expander(
            "🧠 Social Engineering Analysis",
            expanded=True,
        ):

            if not keyword_results:
                st.success(
                    "No common social engineering "
                    "indicators detected."
                )

            else:
                for indicator in (
                    keyword_results
                ):

                    severity = (
                        indicator[
                            "severity"
                        ]
                    )

                    matches = ", ".join(
                        indicator[
                            "matches"
                        ]
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

        # Extracted body
        st.divider()

        with st.expander(
            "📝 View Extracted Email Body"
        ):
            st.text_area(
                "Body",
                value=email_data[
                    "body"
                ],
                height=250,
                disabled=True,
            )
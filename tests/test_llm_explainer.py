from src.llm_explainer import (
    build_llm_context,
    build_prompt,
    get_analysis_relationship,
)


def create_results(
    hybrid_level="HIGH",
    heuristic_level="HIGH",
    ml_label="PHISHING",
    ml_probability=0.999,
):
    risk_result = {
        "score": 100,
        "level": heuristic_level,
        "breakdown": [
            {
                "source": "Header",
                "indicator": "dmarc_failure",
                "points": 25,
                "message": (
                    "DMARC authentication failed."
                ),
            },
            {
                "source": "Header",
                "indicator": "reply_to_mismatch",
                "points": 15,
                "message": (
                    "The From and Reply-To addresses "
                    "use different registered domains."
                ),
            },
            {
                "source": "URL",
                "indicator": "ip_address_url",
                "points": 25,
                "message": (
                    "The URL uses an IP address "
                    "instead of a domain name."
                ),
            },
        ],
    }

    ml_result = {
        "phishing_probability": ml_probability,
        "prediction": (
            1
            if ml_label == "PHISHING"
            else 0
        ),
        "label": ml_label,
        "threshold": 0.50,
    }

    hybrid_result = {
        "level": hybrid_level,
        "agreement": (
            hybrid_level != "REVIEW"
        ),
    }

    return (
        risk_result,
        ml_result,
        hybrid_result,
    )


def test_llm_context_contains_analysis():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    context = build_llm_context(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        context["final_assessment"]
        == "HIGH"
    )

    assert (
        context["analysis_relationship"]
        == "AGREEMENT"
    )

    assert (
        context["review_reason"]
        is None
    )

    assert (
        context["heuristic_score"]
        == 100
    )

    assert (
        context["ml_prediction"]
        == "PHISHING"
    )

    assert (
        context["ml_phishing_probability"]
        == 99.9
    )

    assert len(
        context["evidence"]
    ) == 3


def test_high_result_is_marked_as_agreement():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="HIGH",
        heuristic_level="HIGH",
        ml_label="PHISHING",
    )

    relationship = get_analysis_relationship(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        relationship[
            "analysis_relationship"
        ]
        == "AGREEMENT"
    )

    assert (
        relationship["review_reason"]
        is None
    )


def test_review_low_vs_phishing_is_disagreement():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="LOW",
        ml_label="PHISHING",
        ml_probability=0.7712,
    )

    risk_result["score"] = 0
    risk_result["breakdown"] = []

    relationship = get_analysis_relationship(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        relationship[
            "analysis_relationship"
        ]
        == "DISAGREEMENT"
    )

    assert (
        "heuristic analysis detected low phishing risk"
        in relationship["review_reason"]
    )

    assert (
        "77.12%"
        in relationship["review_reason"]
    )


def test_review_high_vs_legitimate_is_disagreement():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="HIGH",
        ml_label="LEGITIMATE",
        ml_probability=0.25,
    )

    relationship = get_analysis_relationship(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        relationship[
            "analysis_relationship"
        ]
        == "DISAGREEMENT"
    )

    assert (
        "machine learning model classified "
        "the email as LEGITIMATE"
        in relationship["review_reason"]
    )


def test_prompt_contains_core_guardrails():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        "change the final assessment"
        in prompt
    )

    assert (
        "invent evidence"
        in prompt
    )

    assert (
        "completely safe"
        in prompt
    )

    assert (
        "produce a new risk score"
        in prompt
    )


def test_prompt_prioritises_authentication_evidence():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        "SPF, DKIM or DMARC"
        in prompt
    )

    assert (
        "domain mismatches"
        in prompt
    )

    assert (
        "DMARC authentication failed."
        in prompt
    )


def test_prompt_hides_internal_indicator_names():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        "expose internal indicator identifiers"
        in prompt
    )

    assert (
        "Describe evidence naturally."
        in prompt
    )


def test_high_prompt_has_correct_actions():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="HIGH"
    )

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        "does not interact with suspicious links"
        in prompt
    )

    assert (
        "reporting, quarantining or escalating"
        in prompt
    )

    assert (
        "Do not tell the user that the main next step "
        "is to manually review"
        in prompt
    )


def test_review_prompt_requires_manual_review():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="LOW",
        ml_label="PHISHING",
        ml_probability=0.7712,
    )

    risk_result["score"] = 0
    risk_result["breakdown"] = []

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        "State that the result requires manual review."
        in normalized_prompt
    )

    assert (
        "additional validation"
        in normalized_prompt
    )


def test_review_prompt_contains_explicit_disagreement():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="LOW",
        ml_label="PHISHING",
        ml_probability=0.7712,
    )

    risk_result["score"] = 0
    risk_result["breakdown"] = []

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        '"analysis_relationship": "DISAGREEMENT"'
        in normalized_prompt
    )

    assert (
        "77.12%"
        in normalized_prompt
    )

    assert (
        "Do not omit the machine learning result"
        in normalized_prompt
    )


def test_review_low_heuristic_explains_disagreement():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="LOW",
        ml_label="PHISHING",
        ml_probability=0.7712,
    )

    risk_result["score"] = 5
    risk_result["breakdown"] = []

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        "the two methods disagree"
        in normalized_prompt
    )

    assert (
        "detected little or no weighted suspicious evidence"
        in normalized_prompt
    )

    assert (
        "ML model detected phishing-like patterns"
        in normalized_prompt
    )

    assert (
        "this disagreement is why manual review is recommended"
        in normalized_prompt
    )


def test_prompt_uses_correct_no_evidence_wording():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="REVIEW",
        heuristic_level="LOW",
        ml_label="PHISHING",
        ml_probability=0.7712,
    )

    risk_result["score"] = 0
    risk_result["breakdown"] = []

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        "The heuristic analysis detected "
        "no weighted suspicious indicators."
        in normalized_prompt
    )


def test_low_prompt_does_not_claim_safety():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results(
        hybrid_level="LOW",
        heuristic_level="LOW",
        ml_label="LEGITIMATE",
        ml_probability=0.10,
    )

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        "does not guarantee that the email is safe"
        in normalized_prompt
    )


def test_prompt_does_not_guarantee_legitimacy():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    normalized_prompt = " ".join(
        prompt.split()
    )

    assert (
        "Never say that verification will ensure "
        "or guarantee legitimacy"
        in normalized_prompt
    )

    assert (
        "can help determine, assess or confirm"
        in normalized_prompt
    )


def test_prompt_does_not_include_raw_email():
    (
        risk_result,
        ml_result,
        hybrid_result,
    ) = create_results()

    prompt = build_prompt(
        risk_result,
        ml_result,
        hybrid_result,
    )

    assert (
        "raw_email"
        not in prompt
    )
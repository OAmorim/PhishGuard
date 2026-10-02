from pathlib import Path
import json

import joblib
import pandas as pd

from src.email_parser import parse_email
from src.header_analyzer import analyze_headers
from src.hybrid_engine import calculate_hybrid_assessment
from src.keyword_analyzer import analyze_keywords
from src.risk_engine import calculate_risk_score
from src.url_analyzer import analyze_urls


METADATA_PATH = Path(
    "data/challenge/metadata.csv"
)

MODEL_PATH = Path(
    "models/phishing_model.joblib"
)

RESULTS_CSV_PATH = Path(
    "results/hybrid_challenge_results.csv"
)

SUMMARY_PATH = Path(
    "results/hybrid_challenge_summary.json"
)


LABEL_MAP = {
    "LEGITIMATE": 0,
    "PHISHING": 1,
}


def classify_ml(
    model,
    body,
    threshold=0.50,
):
    probabilities = model.predict_proba(
        [body]
    )[0]

    classes = list(model.classes_)

    phishing_index = classes.index(1)

    probability = float(
        probabilities[phishing_index]
    )

    prediction = int(
        probability >= threshold
    )

    return {
        "prediction": prediction,
        "label": (
            "PHISHING"
            if prediction == 1
            else "LEGITIMATE"
        ),
        "phishing_probability": probability,
        "threshold": threshold,
    }


def map_heuristic_prediction(level):
    if level == "HIGH":
        return 1

    if level == "LOW":
        return 0

    return None


def map_hybrid_prediction(level):
    if level == "HIGH":
        return 1

    if level == "LOW":
        return 0

    return None


def evaluate_predictions(
    dataframe,
    prediction_column,
):
    total = len(dataframe)

    reviewed = dataframe[
        prediction_column
    ].isna()

    decided = dataframe[
        ~reviewed
    ].copy()

    review_count = int(
        reviewed.sum()
    )

    decided_count = len(decided)

    if decided_count > 0:
        correct = (
            decided[prediction_column]
            == decided["expected_label"]
        )

        decision_accuracy = float(
            correct.mean()
        )

    else:
        decision_accuracy = 0.0

    false_positives = int(
        (
            (dataframe["expected_label"] == 0)
            & (dataframe[prediction_column] == 1)
        ).sum()
    )

    false_negatives = int(
        (
            (dataframe["expected_label"] == 1)
            & (dataframe[prediction_column] == 0)
        ).sum()
    )

    phishing_total = int(
        (
            dataframe["expected_label"] == 1
        ).sum()
    )

    legitimate_total = int(
        (
            dataframe["expected_label"] == 0
        ).sum()
    )

    phishing_reviews = int(
        (
            (dataframe["expected_label"] == 1)
            & reviewed
        ).sum()
    )

    legitimate_reviews = int(
        (
            (dataframe["expected_label"] == 0)
            & reviewed
        ).sum()
    )

    coverage = (
        decided_count / total
        if total > 0
        else 0.0
    )

    review_rate = (
        review_count / total
        if total > 0
        else 0.0
    )

    false_positive_rate = (
        false_positives / legitimate_total
        if legitimate_total > 0
        else 0.0
    )

    false_negative_rate = (
        false_negatives / phishing_total
        if phishing_total > 0
        else 0.0
    )

    return {
        "total": total,
        "decided": decided_count,
        "reviews": review_count,
        "coverage": coverage,
        "review_rate": review_rate,
        "decision_accuracy": decision_accuracy,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "phishing_reviews": phishing_reviews,
        "legitimate_reviews": legitimate_reviews,
    }


def print_summary(
    name,
    metrics,
):
    print(f"\n{name}")
    print("=" * len(name))

    print(
        f"Coverage:            "
        f"{metrics['coverage']:.2%}"
    )

    print(
        f"Review rate:         "
        f"{metrics['review_rate']:.2%}"
    )

    print(
        f"Decision accuracy:   "
        f"{metrics['decision_accuracy']:.2%}"
    )

    print(
        f"False positives:     "
        f"{metrics['false_positives']}"
    )

    print(
        f"False negatives:     "
        f"{metrics['false_negatives']}"
    )

    print(
        f"Phishing reviewed:   "
        f"{metrics['phishing_reviews']}"
    )

    print(
        f"Legitimate reviewed: "
        f"{metrics['legitimate_reviews']}"
    )


def main():
    print("Loading challenge set...")

    metadata = pd.read_csv(
        METADATA_PATH
    )

    print(
        f"Challenge emails: {len(metadata)}"
    )

    print("Loading ML model...")

    model = joblib.load(
        MODEL_PATH
    )

    results = []

    for _, case in metadata.iterrows():

        email_path = Path(
            case["file"]
        )

        raw_email = email_path.read_bytes()

        email_data = parse_email(
            raw_email
        )

        url_results = analyze_urls(
            email_data["body"]
        )

        text_to_analyze = (
            f"{email_data['subject']} "
            f"{email_data['body']}"
        )

        keyword_results = analyze_keywords(
            text_to_analyze
        )

        header_results = analyze_headers(
            email_data
        )

        risk_result = calculate_risk_score(
            url_results,
            keyword_results,
            header_results,
        )

        ml_result = classify_ml(
            model,
            email_data["body"],
        )

        hybrid_result = (
            calculate_hybrid_assessment(
                risk_result,
                ml_result,
            )
        )

        expected_label = LABEL_MAP[
            case["label"]
        ]

        heuristic_prediction = (
            map_heuristic_prediction(
                risk_result["level"]
            )
        )

        hybrid_prediction = (
            map_hybrid_prediction(
                hybrid_result["level"]
            )
        )

        results.append({
            "id": case["id"],
            "scenario": case["scenario"],
            "expected": case["label"],
            "expected_label": expected_label,
            "heuristic_score": (
                risk_result["score"]
            ),
            "heuristic_level": (
                risk_result["level"]
            ),
            "heuristic_prediction": (
                heuristic_prediction
            ),
            "ml_probability": (
                ml_result[
                    "phishing_probability"
                ]
            ),
            "ml_label": (
                ml_result["label"]
            ),
            "ml_prediction": (
                ml_result["prediction"]
            ),
            "hybrid_level": (
                hybrid_result["level"]
            ),
            "hybrid_prediction": (
                hybrid_prediction
            ),
        })

    results_df = pd.DataFrame(
        results
    )

    RESULTS_CSV_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results_df.to_csv(
        RESULTS_CSV_PATH,
        index=False,
    )

    print("\nPer-email results")
    print("=================")

    for _, row in results_df.iterrows():

        ml_probability = (
            row["ml_probability"] * 100
        )

        print(
            f"{row['id']:<28} "
            f"Expected={row['expected']:<10} "
            f"Heuristic={row['heuristic_level']:<6} "
            f"ML={row['ml_label']:<10} "
            f"({ml_probability:5.1f}%) "
            f"Hybrid={row['hybrid_level']}"
        )

    heuristic_metrics = (
        evaluate_predictions(
            results_df,
            "heuristic_prediction",
        )
    )

    ml_metrics = (
        evaluate_predictions(
            results_df,
            "ml_prediction",
        )
    )

    hybrid_metrics = (
        evaluate_predictions(
            results_df,
            "hybrid_prediction",
        )
    )

    print_summary(
        "Heuristic Engine",
        heuristic_metrics,
    )

    print_summary(
        "Machine Learning",
        ml_metrics,
    )

    print_summary(
        "Hybrid Engine",
        hybrid_metrics,
    )

    summary = {
        "dataset": {
            "samples": len(results_df),
            "phishing": int(
                (
                    results_df["expected_label"]
                    == 1
                ).sum()
            ),
            "legitimate": int(
                (
                    results_df["expected_label"]
                    == 0
                ).sum()
            ),
        },
        "heuristic": heuristic_metrics,
        "machine_learning": ml_metrics,
        "hybrid": hybrid_metrics,
    }

    with open(
        SUMMARY_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            summary,
            file,
            indent=4,
        )

    print(
        f"\nDetailed results saved to "
        f"{RESULTS_CSV_PATH}"
    )

    print(
        f"Summary saved to "
        f"{SUMMARY_PATH}"
    )


if __name__ == "__main__":
    main()
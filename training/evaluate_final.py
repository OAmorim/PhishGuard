from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.email_parser import parse_email
from src.header_analyzer import analyze_headers
from src.hybrid_engine import calculate_hybrid_assessment
from src.keyword_analyzer import analyze_keywords
from src.risk_engine import calculate_risk_score
from src.url_analyzer import analyze_urls


DATASET_PATH = Path(
    "data/raw/ephishLLM.json"
)

MODEL_PATH = Path(
    "models/phishing_model.joblib"
)

RESULTS_PATH = Path(
    "results/final_benchmark_results.csv"
)

SUMMARY_PATH = Path(
    "results/final_benchmark_summary.json"
)

ML_THRESHOLD = 0.50


def create_neutral_raw_email(
    subject,
    body,
):
    """
    Create a neutral email envelope for datasets that contain
    only subject and body content.

    No suspicious header indicators are intentionally added.
    """

    return (
        "From: benchmark-sender@example.com\n"
        "To: benchmark-recipient@example.com\n"
        f"Subject: {subject}\n"
        "\n"
        f"{body}"
    )


def map_selective_prediction(level):
    """
    Convert LOW/HIGH into binary labels.

    MEDIUM and REVIEW represent cases that require
    further analysis rather than an automatic decision.
    """

    if level == "HIGH":
        return 1

    if level == "LOW":
        return 0

    return None


def calculate_binary_metrics(
    y_true,
    y_pred,
):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    return {
        "samples": len(y_true),
        "accuracy": float(
            accuracy_score(
                y_true,
                y_pred,
            )
        ),
        "precision": float(
            precision_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "f1_score": float(
            f1_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def calculate_selective_metrics(
    dataframe,
    prediction_column,
):
    """
    Evaluate engines that may return REVIEW instead of
    automatically classifying every email.
    """

    review_mask = dataframe[
        prediction_column
    ].isna()

    decided_df = dataframe[
        ~review_mask
    ].copy()

    total = len(dataframe)
    decided = len(decided_df)
    reviews = int(
        review_mask.sum()
    )

    correct_decisions = int(
        (
            decided_df[prediction_column]
            == decided_df["expected_label"]
        ).sum()
    )

    decision_accuracy = (
        correct_decisions / decided
        if decided > 0
        else 0.0
    )

    false_positives = int(
        (
            (decided_df["expected_label"] == 0)
            & (
                decided_df[
                    prediction_column
                ] == 1
            )
        ).sum()
    )

    false_negatives = int(
        (
            (decided_df["expected_label"] == 1)
            & (
                decided_df[
                    prediction_column
                ] == 0
            )
        ).sum()
    )

    legitimate_reviews = int(
        (
            (dataframe["expected_label"] == 0)
            & review_mask
        ).sum()
    )

    phishing_reviews = int(
        (
            (dataframe["expected_label"] == 1)
            & review_mask
        ).sum()
    )

    metrics = {
        "samples": total,
        "decided": decided,
        "reviews": reviews,
        "coverage": (
            decided / total
            if total > 0
            else 0.0
        ),
        "review_rate": (
            reviews / total
            if total > 0
            else 0.0
        ),
        "decision_accuracy": (
            decision_accuracy
        ),
        "correct_decisions": (
            correct_decisions
        ),
        "false_positives": (
            false_positives
        ),
        "false_negatives": (
            false_negatives
        ),
        "legitimate_reviews": (
            legitimate_reviews
        ),
        "phishing_reviews": (
            phishing_reviews
        ),
    }

    if decided > 0:
        binary_metrics = (
            calculate_binary_metrics(
                decided_df[
                    "expected_label"
                ].astype(int),
                decided_df[
                    prediction_column
                ].astype(int),
            )
        )

        metrics["precision"] = (
            binary_metrics["precision"]
        )

        metrics["recall"] = (
            binary_metrics["recall"]
        )

        metrics["f1_score"] = (
            binary_metrics["f1_score"]
        )

    else:
        metrics["precision"] = 0.0
        metrics["recall"] = 0.0
        metrics["f1_score"] = 0.0

    return metrics


def print_binary_metrics(
    name,
    metrics,
):
    print(f"\n{name}")
    print("=" * len(name))

    print(
        f"Samples:          "
        f"{metrics['samples']}"
    )

    print(
        f"Accuracy:         "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Precision:        "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall:           "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1-score:         "
        f"{metrics['f1_score']:.4f}"
    )

    print(
        f"False positives:  "
        f"{metrics['false_positives']}"
    )

    print(
        f"False negatives:  "
        f"{metrics['false_negatives']}"
    )

    print("\nConfusion matrix:")

    print(
        [
            metrics["true_negatives"],
            metrics["false_positives"],
        ]
    )

    print(
        [
            metrics["false_negatives"],
            metrics["true_positives"],
        ]
    )


def print_selective_metrics(
    name,
    metrics,
):
    print(f"\n{name}")
    print("=" * len(name))

    print(
        f"Samples:            "
        f"{metrics['samples']}"
    )

    print(
        f"Coverage:           "
        f"{metrics['coverage']:.2%}"
    )

    print(
        f"Review rate:        "
        f"{metrics['review_rate']:.2%}"
    )

    print(
        f"Decision accuracy:  "
        f"{metrics['decision_accuracy']:.2%}"
    )

    print(
        f"Precision:          "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall:             "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1-score:           "
        f"{metrics['f1_score']:.4f}"
    )

    print(
        f"False positives:    "
        f"{metrics['false_positives']}"
    )

    print(
        f"False negatives:    "
        f"{metrics['false_negatives']}"
    )

    print(
        f"Legitimate reviews: "
        f"{metrics['legitimate_reviews']}"
    )

    print(
        f"Phishing reviews:   "
        f"{metrics['phishing_reviews']}"
    )


def main():
    print(
        "Loading final evaluation dataset..."
    )

    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    df = pd.DataFrame(data)

    df = (
        df[
            df["Language"] == "en"
        ]
        .copy()
        .reset_index(drop=True)
    )

    print(
        f"English emails: {len(df)}"
    )

    print("\nClass distribution:")
    print(
        df["type"]
        .value_counts()
        .sort_index()
    )

    print("\nLoading ML model...")

    model = joblib.load(
        MODEL_PATH
    )

    # ML was trained using email bodies, so evaluate
    # it using only the body here as well.
    ml_probabilities = (
        model.predict_proba(
            df["Body"].astype(str)
        )
    )

    classes = list(
        model.classes_
    )

    phishing_index = classes.index(1)

    df["ml_probability"] = (
        ml_probabilities[
            :,
            phishing_index,
        ]
    )

    df["ml_prediction"] = (
        df["ml_probability"]
        >= ML_THRESHOLD
    ).astype(int)

    results = []

    print(
        "\nRunning heuristic and hybrid analysis..."
    )

    total = len(df)

    for index, row in df.iterrows():
        subject = str(
            row["Subject"]
        )

        body = str(
            row["Body"]
        )

        raw_email = (
            create_neutral_raw_email(
                subject,
                body,
            )
        )

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

        keyword_results = (
            analyze_keywords(
                text_to_analyze
            )
        )

        header_results = (
            analyze_headers(
                email_data
            )
        )

        risk_result = (
            calculate_risk_score(
                url_results,
                keyword_results,
                header_results,
            )
        )

        ml_probability = float(
            row["ml_probability"]
        )

        ml_prediction = int(
            row["ml_prediction"]
        )

        ml_result = {
            "phishing_probability": (
                ml_probability
            ),
            "prediction": (
                ml_prediction
            ),
            "label": (
                "PHISHING"
                if ml_prediction == 1
                else "LEGITIMATE"
            ),
            "threshold": ML_THRESHOLD,
        }

        hybrid_result = (
            calculate_hybrid_assessment(
                risk_result,
                ml_result,
            )
        )

        heuristic_prediction = (
            map_selective_prediction(
                risk_result["level"]
            )
        )

        hybrid_prediction = (
            map_selective_prediction(
                hybrid_result["level"]
            )
        )

        results.append({
            "sample_id": int(index),
            "expected_label": int(
                row["type"]
            ),
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
                ml_probability
            ),
            "ml_prediction": (
                ml_prediction
            ),
            "hybrid_level": (
                hybrid_result["level"]
            ),
            "hybrid_prediction": (
                hybrid_prediction
            ),
        })

        if (
            (index + 1) % 1000 == 0
            or index + 1 == total
        ):
            print(
                f"Processed "
                f"{index + 1}/{total}"
            )

    results_df = pd.DataFrame(
        results
    )

    RESULTS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results_df.to_csv(
        RESULTS_PATH,
        index=False,
    )

    ml_metrics = (
        calculate_binary_metrics(
            results_df[
                "expected_label"
            ],
            results_df[
                "ml_prediction"
            ],
        )
    )

    heuristic_metrics = (
        calculate_selective_metrics(
            results_df,
            "heuristic_prediction",
        )
    )

    hybrid_metrics = (
        calculate_selective_metrics(
            results_df,
            "hybrid_prediction",
        )
    )

    print_binary_metrics(
        "Machine Learning",
        ml_metrics,
    )

    print_selective_metrics(
        "Heuristic Engine",
        heuristic_metrics,
    )

    print_selective_metrics(
        "Hybrid Engine",
        hybrid_metrics,
    )

    print(
        "\nHybrid result distribution:"
    )

    print(
        results_df[
            "hybrid_level"
        ].value_counts()
    )

    summary = {
        "dataset": {
            "name": "E-PhishGen",
            "language_filter": "en",
            "samples": int(
                len(results_df)
            ),
            "legitimate": int(
                (
                    results_df[
                        "expected_label"
                    ] == 0
                ).sum()
            ),
            "phishing": int(
                (
                    results_df[
                        "expected_label"
                    ] == 1
                ).sum()
            ),
            "benchmark_scope": (
                "Content-based evaluation. "
                "The source dataset does not provide "
                "original email authentication headers."
            ),
        },
        "machine_learning": (
            ml_metrics
        ),
        "heuristic": (
            heuristic_metrics
        ),
        "hybrid": (
            hybrid_metrics
        ),
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
        f"{RESULTS_PATH}"
    )

    print(
        f"Summary saved to "
        f"{SUMMARY_PATH}"
    )


if __name__ == "__main__":
    main()
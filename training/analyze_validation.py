from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


DATASET_PATH = Path(
    "data/raw/Phishing_validation_emails.csv"
)

MODEL_PATH = Path(
    "models/phishing_model.joblib"
)

PREDICTIONS_PATH = Path(
    "results/external_validation_predictions.csv"
)

THRESHOLDS_PATH = Path(
    "results/threshold_analysis.csv"
)


LABEL_MAP = {
    "Safe Email": 0,
    "Phishing Email": 1,
}


def calculate_metrics(y_true, probabilities, threshold):
    """
    Calculate classification metrics for a given probability threshold.
    """

    predictions = (
        probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    accuracy = accuracy_score(
        y_true,
        predictions,
    )

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0,
    )

    specificity = (
        tn / (tn + fp)
        if (tn + fp) > 0
        else 0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )

    return {
        "threshold": threshold,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
    }


def print_email_preview(row):
    """
    Print a short version of a misclassified email.
    """

    text = str(
        row["Email Text"]
    ).replace("\n", " ")

    preview = text[:300]

    if len(text) > 300:
        preview += "..."

    print(
        f"Actual:      {row['Email Type']}"
    )

    print(
        f"Probability: "
        f"{row['phishing_probability']:.4f}"
    )

    print(
        f"Preview:     {preview}"
    )

    print("-" * 80)


def main():
    print("Loading model...")

    model = joblib.load(
        MODEL_PATH
    )

    print(
        "Loading external validation dataset..."
    )

    df = pd.read_csv(
        DATASET_PATH
    )

    # Keep only unique emails for this analysis
    df = (
        df.drop_duplicates(
            subset=["Email Text"]
        )
        .reset_index(drop=True)
        .copy()
    )

    df["label"] = df["Email Type"].map(
        LABEL_MAP
    ).astype(int)

    print(
        f"Unique emails: {len(df)}"
    )

    print("\nClass distribution:")
    print(
        df["Email Type"].value_counts()
    )

    # Logistic Regression returns the probability of each class.
    # Column 1 corresponds to the phishing class.
    probabilities = model.predict_proba(
        df["Email Text"]
    )[:, 1]

    df["phishing_probability"] = (
        probabilities
    )

    # Start by analysing the normal 0.50 threshold
    df["prediction"] = (
        df["phishing_probability"] >= 0.50
    ).astype(int)

    df["predicted_type"] = df[
        "prediction"
    ].map({
        0: "Safe Email",
        1: "Phishing Email",
    })

    df["correct"] = (
        df["prediction"] == df["label"]
    )

    PREDICTIONS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Publish predictions without redistributing source email text.
    export_df = df.drop(columns=["Email Text"]).copy()
    export_df.insert(0, "sample_id", range(len(export_df)))
    export_df.to_csv(
        PREDICTIONS_PATH,
        index=False,
    )

    print(
        f"\nPredictions saved to "
        f"{PREDICTIONS_PATH}"
    )

    # Inspect false positives
    false_positives = df[
        (df["label"] == 0)
        & (df["prediction"] == 1)
    ].sort_values(
        "phishing_probability",
        ascending=False,
    )

    print(
        f"\nFalse positives: "
        f"{len(false_positives)}"
    )

    print("=" * 80)

    for _, row in false_positives.iterrows():
        print_email_preview(row)

    # Inspect false negatives
    false_negatives = df[
        (df["label"] == 1)
        & (df["prediction"] == 0)
    ].sort_values(
        "phishing_probability",
        ascending=True,
    )

    print(
        f"\nFalse negatives: "
        f"{len(false_negatives)}"
    )

    print("=" * 80)

    for _, row in false_negatives.iterrows():
        print_email_preview(row)

    # Test several decision thresholds
    thresholds = [
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
        0.85,
        0.90,
    ]

    threshold_results = []

    for threshold in thresholds:
        metrics = calculate_metrics(
            df["label"],
            probabilities,
            threshold,
        )

        threshold_results.append(
            metrics
        )

    threshold_df = pd.DataFrame(
        threshold_results
    )

    threshold_df.to_csv(
        THRESHOLDS_PATH,
        index=False,
    )

    print("\nThreshold analysis")
    print("==================")

    display_columns = [
        "threshold",
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positives",
        "false_negatives",
    ]

    print(
        threshold_df[
            display_columns
        ].to_string(
            index=False,
            float_format=lambda value: (
                f"{value:.4f}"
            ),
        )
    )

    print(
        f"\nThreshold results saved to "
        f"{THRESHOLDS_PATH}"
    )


if __name__ == "__main__":
    main()
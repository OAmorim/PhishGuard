from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
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

RESULTS_PATH = Path(
    "results/external_validation_metrics.json"
)


LABEL_MAP = {
    "Safe Email": 0,
    "Phishing Email": 1,
}


def evaluate_model(model, x, y):
    """
    Evaluate the model on a validation dataset.
    """

    predictions = model.predict(x)

    accuracy = accuracy_score(
        y,
        predictions,
    )

    precision = precision_score(
        y,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y,
        predictions,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y,
        predictions,
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": matrix.tolist(),
        "samples": len(y),
    }


def print_metrics(title, metrics):
    """
    Print validation metrics in a readable format.
    """

    print(f"\n{title}")
    print("=" * len(title))

    print(
        f"Samples:   {metrics['samples']}"
    )

    print(
        f"Accuracy:  {metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: {metrics['precision']:.4f}"
    )

    print(
        f"Recall:    {metrics['recall']:.4f}"
    )

    print(
        f"F1-score:  {metrics['f1_score']:.4f}"
    )

    print("\nConfusion matrix:")

    for row in metrics["confusion_matrix"]:
        print(row)


def main():
    print("Loading trained model...")

    model = joblib.load(
        MODEL_PATH
    )

    print("Loading external validation dataset...")

    df = pd.read_csv(
        DATASET_PATH
    )

    print(
        f"\nOriginal rows: {len(df)}"
    )

    print(
        f"Unique email texts: "
        f"{df['Email Text'].nunique()}"
    )

    # Convert text labels into the same numeric format used during training
    df["label"] = df["Email Type"].map(
        LABEL_MAP
    )

    if df["label"].isnull().any():
        unknown_labels = (
            df.loc[
                df["label"].isnull(),
                "Email Type",
            ]
            .unique()
            .tolist()
        )

        raise ValueError(
            f"Unknown labels found: {unknown_labels}"
        )

    df["label"] = df["label"].astype(int)

    # Check whether identical emails have conflicting labels
    label_counts = (
        df.groupby("Email Text")["label"]
        .nunique()
    )

    conflicting_emails = label_counts[
        label_counts > 1
    ]

    print(
        f"Emails with conflicting labels: "
        f"{len(conflicting_emails)}"
    )

    if len(conflicting_emails) > 0:
        raise ValueError(
            "The validation dataset contains identical "
            "emails with conflicting labels."
        )

    # Evaluate the complete dataset for transparency
    full_metrics = evaluate_model(
        model,
        df["Email Text"],
        df["label"],
    )

    print_metrics(
        "Full external validation",
        full_metrics,
    )

    # Remove duplicate email bodies for the main external evaluation
    unique_df = (
        df.drop_duplicates(
            subset=["Email Text"]
        )
        .reset_index(drop=True)
    )

    print(
        f"\nRows after deduplication: "
        f"{len(unique_df)}"
    )

    print("\nDeduplicated class distribution:")
    print(
        unique_df["Email Type"].value_counts()
    )

    unique_metrics = evaluate_model(
        model,
        unique_df["Email Text"],
        unique_df["label"],
    )

    print_metrics(
        "Deduplicated external validation",
        unique_metrics,
    )

    results = {
        "dataset": {
            "original_rows": len(df),
            "unique_email_texts": len(unique_df),
            "duplicate_rows": (
                len(df) - len(unique_df)
            ),
            "conflicting_labels": (
                len(conflicting_emails)
            ),
        },
        "full_dataset": full_metrics,
        "deduplicated_dataset": unique_metrics,
    }

    RESULTS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        RESULTS_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
        )

    print(
        f"\nResults saved to "
        f"{RESULTS_PATH}"
    )


if __name__ == "__main__":
    main()
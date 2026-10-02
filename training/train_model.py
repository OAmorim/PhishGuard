from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


DATASET_PATH = Path("data/raw/Balanced_Dataset.csv")
MODEL_PATH = Path("models/phishing_model.joblib")
RESULTS_PATH = Path("results/ml_metrics.json")


def load_dataset():
    """
    Load and perform the minimum cleaning needed for training.
    """

    print("Loading dataset...")

    df = pd.read_csv(DATASET_PATH)

    print(f"Original rows: {len(df)}")

    # Remove rows where the email body is missing
    df = df.dropna(
        subset=["body", "label"]
    ).copy()

    # Keep the labels as integers: 0 = legitimate, 1 = phishing
    df["label"] = df["label"].astype(int)

    # Remove exact duplicate emails
    before_duplicates = len(df)

    df = df.drop_duplicates(
        subset=["body"]
    ).reset_index(drop=True)

    removed_duplicates = (
        before_duplicates - len(df)
    )

    print(
        f"Rows after cleaning: {len(df)}"
    )

    print(
        f"Duplicate emails removed: "
        f"{removed_duplicates}"
    )

    print("\nClass distribution:")
    print(
        df["label"].value_counts()
    )

    return df


def build_model():
    """
    Build the text classification pipeline.
    """

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=50000,
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42,
            ),
        ),
    ])


def evaluate_model(
    model,
    x_test,
    y_test,
):
    """
    Evaluate the trained model and return the main metrics.
    """

    predictions = model.predict(
        x_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
    )

    recall = recall_score(
        y_test,
        predictions,
    )

    f1 = f1_score(
        y_test,
        predictions,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
    )

    print("\nModel evaluation")
    print("================")

    print(
        f"Accuracy:  {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall:    {recall:.4f}"
    )

    print(
        f"F1-score:  {f1:.4f}"
    )

    print("\nConfusion matrix:")
    print(matrix)

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing",
            ],
        )
    )

    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": (
            matrix.tolist()
        ),
        "test_samples": len(y_test),
    }

    return metrics


def main():
    df = load_dataset()

    x = df["body"]
    y = df["label"]

    print("\nCreating train/test split...")

    x_train, x_test, y_train, y_test = (
        train_test_split(
            x,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )
    )

    print(
        f"Training samples: {len(x_train)}"
    )

    print(
        f"Testing samples: {len(x_test)}"
    )

    model = build_model()

    print("\nTraining model...")
    model.fit(
        x_train,
        y_train,
    )

    metrics = evaluate_model(
        model,
        x_test,
        y_test,
    )

    # Create the output folders if they do not exist
    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULTS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"\nSaving model to "
        f"{MODEL_PATH}..."
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    with open(
        RESULTS_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metrics,
            file,
            indent=4,
        )

    print(
        f"Metrics saved to "
        f"{RESULTS_PATH}"
    )

    print("\nTraining complete.")


if __name__ == "__main__":
    main()
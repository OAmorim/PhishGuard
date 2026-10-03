from pathlib import Path
import json

import pandas as pd


DATASET_PATH = Path(
    "data/raw/ephishLLM.json"
)


def main():
    print("Loading final evaluation dataset...")

    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    df = pd.DataFrame(data)

    print("\nDataset shape:")
    print(df.shape)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing values:")
    print(df.isnull().sum())

    print("\nData types:")
    print(df.dtypes)

    print("\nLanguage distribution:")
    print(
        df["Language"].value_counts(
            dropna=False
        )
    )

    print("\nClass distribution:")
    print(
        df["type"].value_counts(
            dropna=False
        ).sort_index()
    )

    # Use only English emails for the final benchmark
    english_df = (
        df[
            df["Language"] == "en"
        ]
        .copy()
        .reset_index(drop=True)
    )

    print("\nEnglish emails:")
    print(len(english_df))

    print("\nEnglish class distribution:")
    print(
        english_df["type"]
        .value_counts()
        .sort_index()
    )

    # Check exact duplicate emails
    duplicate_mask = english_df.duplicated(
        subset=[
            "Subject",
            "Body",
        ],
        keep=False,
    )

    duplicate_rows = int(
        duplicate_mask.sum()
    )

    unique_emails = (
        english_df[
            [
                "Subject",
                "Body",
            ]
        ]
        .drop_duplicates()
        .shape[0]
    )

    print(
        "\nUnique English emails:"
    )
    print(unique_emails)

    print(
        "\nRows involved in exact duplicates:"
    )
    print(duplicate_rows)

    # Check whether identical content has conflicting labels
    label_counts = (
        english_df
        .groupby(
            [
                "Subject",
                "Body",
            ],
            dropna=False,
        )["type"]
        .nunique()
    )

    conflicting = label_counts[
        label_counts > 1
    ]

    print(
        "\nIdentical emails with conflicting labels:"
    )
    print(len(conflicting))

    print("\nFirst 5 English examples:")

    for index, row in (
        english_df.head(5).iterrows()
    ):
        print("\n" + "=" * 70)

        print(
            f"Example {index + 1}"
        )

        print(
            f"Type: {row['type']}"
        )

        print(
            f"Subject: {row['Subject']}"
        )

        body = str(
            row["Body"]
        ).replace(
            "\n",
            " ",
        )

        print(
            f"Body: {body[:300]}"
        )


if __name__ == "__main__":
    main()
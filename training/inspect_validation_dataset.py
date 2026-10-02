from pathlib import Path

import pandas as pd


DATASET_PATH = Path(
    "data/raw/Phishing_validation_emails.csv"
)


def main():
    print("Loading validation dataset...")

    df = pd.read_csv(DATASET_PATH)

    print("\nDataset shape:")
    print(df.shape)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing values:")
    print(df.isnull().sum())

    print("\nData types:")
    print(df.dtypes)

    print("\nUnique values per column:")

    for column in df.columns:
        unique_values = df[column].nunique(
            dropna=False
        )

        print(
            f"{column}: {unique_values}"
        )

        if unique_values <= 20:
            print(
                df[column].value_counts(
                    dropna=False
                )
            )

    print("\nFirst rows:")
    print(df.head())

    print("\nExample row:")
    print(df.iloc[0])


if __name__ == "__main__":
    main()
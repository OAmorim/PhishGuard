import pandas as pd


DATASET_PATH = "data/raw/Balanced_Dataset.csv"


def main():
    df = pd.read_csv(DATASET_PATH)

    print("\nDataset shape:")
    print(df.shape)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing values:")
    print(df.isnull().sum())

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    print("\nFirst rows:")
    print(df.head())


if __name__ == "__main__":
    main()
import pandas as pd

from preprocess import clean_dataframe


DATASET_FILE = (
    r"dataset\CIC_IDS2017\MachineLearningCVE"
    r"\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)


def main():
    print("=" * 60)
    print("SentinelAI Preprocessing Test")
    print("=" * 60)

    print("\nLoading dataset...")

    df = pd.read_csv(DATASET_FILE)

    print(f"Original rows: {len(df):,}")
    print(f"Original columns: {len(df.columns)}")

    print("\nCleaning dataset...")

    cleaned_df = clean_dataframe(df)

    print(f"Cleaned rows: {len(cleaned_df):,}")
    print(f"Cleaned columns: {len(cleaned_df.columns)}")

    print("\nRemaining missing values:")
    print(cleaned_df.isna().sum().sum())

    print("\nRemaining infinite values:")

    numeric_data = cleaned_df.select_dtypes(include="number")
    print(
        numeric_data.isin([float("inf"), float("-inf")]).sum().sum()
    )

    print("\nRemaining duplicate rows:")
    print(cleaned_df.duplicated().sum())

    print("\nLabels:")
    print(cleaned_df["Label"].value_counts())

    print("\n" + "=" * 60)
    print("Preprocessing test complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
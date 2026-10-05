from pathlib import Path

import pandas as pd

from preprocess import clean_dataframe


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

DATASET_FOLDER = Path(
    r"dataset\CIC_IDS2017\MachineLearningCVE"
)

PROCESSED_FOLDER = Path(
    r"dataset\processed"
)

OUTPUT_FILE = PROCESSED_FOLDER / "training_data.csv"


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

MAX_RECORDS_PER_CLASS = 50_000

RANDOM_STATE = 42


# ---------------------------------------------------------
# Main processing function
# ---------------------------------------------------------

def process_dataset():

    print("=" * 70)
    print("SentinelAI - Training Dataset Builder")
    print("=" * 70)

    csv_files = sorted(DATASET_FOLDER.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATASET_FOLDER}"
        )

    print(f"\nCSV files found: {len(csv_files)}")

    all_data = []

    # -----------------------------------------------------
    # Load and clean each file
    # -----------------------------------------------------

    for file in csv_files:

        print("\n" + "-" * 70)
        print(f"Processing: {file.name}")

        df = pd.read_csv(file)

        print(f"Original rows: {len(df):,}")

        df = clean_dataframe(df)

        print(f"Cleaned rows: {len(df):,}")

        df["Label"] = (
            df["Label"]
            .astype(str)
            .str.strip()
        )

        all_data.append(df)

    # -----------------------------------------------------
    # Combine all cleaned files
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("Combining cleaned datasets...")
    print("=" * 70)

    combined_df = pd.concat(
        all_data,
        ignore_index=True
    )

    print(
        f"\nRows before cross-file duplicate removal: "
        f"{len(combined_df):,}"
    )

    # Remove duplicates across all files.
    combined_df.drop_duplicates(
        inplace=True
    )

    print(
        f"Rows after duplicate removal: "
        f"{len(combined_df):,}"
    )

    # -----------------------------------------------------
    # Balance classes
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("Balancing classes...")
    print("=" * 70)

    balanced_parts = []

    for label, group in combined_df.groupby("Label"):

        original_count = len(group)

        if original_count > MAX_RECORDS_PER_CLASS:

            group = group.sample(
                n=MAX_RECORDS_PER_CLASS,
                random_state=RANDOM_STATE
            )

        print(
            f"{label}: "
            f"{original_count:,} -> "
            f"{len(group):,}"
        )

        balanced_parts.append(group)

    # Combine balanced classes.
    training_df = pd.concat(
        balanced_parts,
        ignore_index=True
    )

    # Shuffle.
    training_df = training_df.sample(
        frac=1,
        random_state=RANDOM_STATE
    ).reset_index(drop=True)

    # -----------------------------------------------------
    # Save dataset
    # -----------------------------------------------------

    PROCESSED_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    training_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # -----------------------------------------------------
    # Final information
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("Training dataset created successfully")
    print("=" * 70)

    print(f"\nOutput file:")
    print(OUTPUT_FILE)

    print(
        f"\nTotal training records: "
        f"{len(training_df):,}"
    )

    print(
        f"Total features: "
        f"{len(training_df.columns) - 1}"
    )

    print("\nFinal label distribution:")

    print(
        training_df["Label"].value_counts()
    )

    print("\n" + "=" * 70)
    print("BUILD COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    process_dataset()
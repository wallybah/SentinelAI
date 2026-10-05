import pandas as pd
import numpy as np
from pathlib import Path


# Location of the CIC-IDS2017 CSV files
DATASET_FOLDER = Path(
    r"dataset\CIC_IDS2017\MachineLearningCVE"
)


print("=" * 80)
print("SentinelAI - CIC-IDS2017 Dataset Inspection")
print("=" * 80)

csv_files = sorted(DATASET_FOLDER.glob("*.csv"))

print(f"\nCSV files found: {len(csv_files)}\n")

for file in csv_files:
    print("-" * 80)
    print(f"File: {file.name}")

    # Read the complete file for this inspection
    df = pd.read_csv(file)

    # Find the label column regardless of leading/trailing spaces
    label_column = next(
        column for column in df.columns
        if column.strip().lower() == "label"
    )

    # Missing values
    missing_values = df.isna().sum().sum()

    # Infinite values
    numeric_data = df.select_dtypes(include=np.number)
    infinite_values = np.isinf(numeric_data).sum().sum()

    # Duplicate rows
    duplicate_rows = df.duplicated().sum()

    # Number of unique labels
    unique_labels = df[label_column].nunique()

    # Label distribution
    labels = df[label_column].value_counts()

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")
    print(f"Unique labels: {unique_labels}")
    print(f"Missing values: {missing_values}")
    print(f"Infinite values: {infinite_values}")
    print(f"Duplicate rows: {duplicate_rows}")

    print("\nLabel distribution:")

    for label, count in labels.items():
        print(f"  {label}: {count:,}")

print("\n" + "=" * 80)
print("Inspection complete.")
print("=" * 80)
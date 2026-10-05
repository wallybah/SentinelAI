import numpy as np
import pandas as pd


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean a CIC-IDS2017 dataframe.

    The original dataframe is not modified.
    """

    # Work on a copy so the original data remains untouched.
    df = df.copy()

    # Remove leading/trailing whitespace from column names.
    df.columns = df.columns.str.strip()

    # Find the target column.
    label_column = next(
        (column for column in df.columns if column.lower() == "label"),
        None,
    )

    if label_column is None:
        raise ValueError("Label column was not found in the dataset.")

    # Replace positive/negative infinity with NaN.
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Remove rows without a valid target label.
    df.dropna(subset=[label_column], inplace=True)

    # Separate numerical columns from the label.
    numeric_columns = df.select_dtypes(include=np.number).columns

    # Fill missing numerical values using the median.
    for column in numeric_columns:
        if df[column].isna().any():
            median_value = df[column].median()

            if pd.isna(median_value):
                median_value = 0

            df[column] = df[column].fillna(median_value)

    # Remove exact duplicate rows.
    df.drop_duplicates(inplace=True)

    # Normalize label text.
    df[label_column] = df[label_column].astype(str).str.strip()

    return df
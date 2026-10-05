from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

DATASET_FILE = Path(
    r"dataset\processed\training_data.csv"
)

MODEL_FOLDER = Path("models")

MODEL_FILE = MODEL_FOLDER / "sentinelai_random_forest.joblib"
LABEL_ENCODER_FILE = MODEL_FOLDER / "label_encoder.joblib"
FEATURE_FILE = MODEL_FOLDER / "feature_names.joblib"


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

TEST_SIZE = 0.20
RANDOM_STATE = 42


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("SentinelAI - Random Forest Training")
    print("=" * 70)

    # -----------------------------------------------------
    # Load dataset
    # -----------------------------------------------------

    print("\nLoading training dataset...")

    df = pd.read_csv(DATASET_FILE)

    print(f"Records: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # -----------------------------------------------------
    # Separate features and target
    # -----------------------------------------------------

    X = df.drop(columns=["Label"])
    y = df["Label"]

    print(f"\nFeatures: {X.shape[1]}")
    print(f"Classes: {y.nunique()}")

    print("\nClasses:")
    for label in sorted(y.unique()):
        print(f"  - {label}")

    # -----------------------------------------------------
    # Ensure all features are numeric
    # -----------------------------------------------------

    non_numeric_columns = X.select_dtypes(
        exclude="number"
    ).columns.tolist()

    if non_numeric_columns:

        print("\nNon-numeric columns found:")

        for column in non_numeric_columns:
            print(f"  - {column}")

        X = X.drop(
            columns=non_numeric_columns
        )

        print(
            f"\nRemoved {len(non_numeric_columns)} "
            "non-numeric columns."
        )

    feature_names = X.columns.tolist()

    # -----------------------------------------------------
    # Encode labels
    # -----------------------------------------------------

    print("\nEncoding labels...")

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    print("Encoded classes:")

    for number, label in enumerate(
        label_encoder.classes_
    ):
        print(f"  {number}: {label}")

    # -----------------------------------------------------
    # Train/test split
    # -----------------------------------------------------

    print("\nCreating stratified train/test split...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_encoded,
    )

    print(f"Training records: {len(X_train):,}")
    print(f"Testing records:  {len(X_test):,}")

    # -----------------------------------------------------
    # Train Random Forest
    # -----------------------------------------------------

    print("\nTraining Random Forest...")
    print("This may take some time.")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train
    )

    print("Training complete.")

    # -----------------------------------------------------
    # Predictions
    # -----------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    # -----------------------------------------------------
    # Evaluation
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

    MODEL_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    joblib.dump(
        label_encoder,
        LABEL_ENCODER_FILE
    )

    joblib.dump(
        feature_names,
        FEATURE_FILE
    )

    print("\n" + "=" * 70)
    print("MODEL SAVED")
    print("=" * 70)

    print(f"\nModel:")
    print(MODEL_FILE)

    print(f"\nLabel encoder:")
    print(LABEL_ENCODER_FILE)

    print(f"\nFeature names:")
    print(FEATURE_FILE)

    print("\nTraining completed successfully.")


if __name__ == "__main__":
    main()
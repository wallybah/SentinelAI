from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

DATASET_FILE = Path(
    r"dataset\processed\training_data.csv"
)

MODEL_FILE = Path(
    r"models\sentinelai_random_forest.joblib"
)

LABEL_ENCODER_FILE = Path(
    r"models\label_encoder.joblib"
)

FEATURE_FILE = Path(
    r"models\feature_names.joblib"
)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("SentinelAI - Model Evaluation")
    print("=" * 70)

    # -----------------------------------------------------
    # Check model files
    # -----------------------------------------------------

    print("\nChecking saved model files...")

    required_files = [
        MODEL_FILE,
        LABEL_ENCODER_FILE,
        FEATURE_FILE,
    ]

    for file in required_files:

        if not file.exists():
            raise FileNotFoundError(
                f"Required file not found: {file}"
            )

        print(f"Found: {file}")

    # -----------------------------------------------------
    # Load model
    # -----------------------------------------------------

    print("\nLoading trained model...")

    model = joblib.load(MODEL_FILE)

    label_encoder = joblib.load(
        LABEL_ENCODER_FILE
    )

    feature_names = joblib.load(
        FEATURE_FILE
    )

    # -----------------------------------------------------
    # Load dataset
    # -----------------------------------------------------

    print("\nLoading evaluation dataset...")

    df = pd.read_csv(DATASET_FILE)

    print(
        f"Records: {len(df):,}"
    )

    # -----------------------------------------------------
    # Prepare features
    # -----------------------------------------------------

    X = df[feature_names]

    y = label_encoder.transform(
        df["Label"]
    )

    print(
        f"Features: {X.shape[1]}"
    )

    print(
        f"Classes: {len(label_encoder.classes_)}"
    )

    # -----------------------------------------------------
    # Generate predictions
    # -----------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(X)

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y,
        y_pred
    )

    print("\n" + "=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y,
            y_pred
        )
    )

    print("\n" + "=" * 70)
    print("Evaluation complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


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

RESULTS_FOLDER = Path(
    r"results"
)

REPORT_FILE = (
    RESULTS_FOLDER /
    "classification_report.csv"
)

CONFUSION_FILE = (
    RESULTS_FOLDER /
    "confusion_matrix.csv"
)

METRICS_FILE = (
    RESULTS_FOLDER /
    "model_metrics.json"
)


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
    print("SentinelAI - Save Model Evaluation Results")
    print("=" * 70)

    # -----------------------------------------------------
    # Load files
    # -----------------------------------------------------

    print("\nLoading dataset...")

    df = pd.read_csv(DATASET_FILE)

    model = joblib.load(
        MODEL_FILE
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_FILE
    )

    feature_names = joblib.load(
        FEATURE_FILE
    )

    print(
        f"Total records: {len(df):,}"
    )

    # -----------------------------------------------------
    # Prepare data
    # -----------------------------------------------------

    X = df[feature_names]

    y = label_encoder.transform(
        df["Label"]
    )

    # -----------------------------------------------------
    # Recreate EXACT original test split
    # -----------------------------------------------------

    print("\nRecreating original 80/20 split...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(
        f"Training records: {len(X_train):,}"
    )

    print(
        f"Testing records:  {len(X_test):,}"
    )

    # -----------------------------------------------------
    # Predict test data
    # -----------------------------------------------------

    print("\nEvaluating saved model...")

    y_pred = model.predict(
        X_test
    )

    # -----------------------------------------------------
    # Calculate accuracy
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    print(
        f"\nTest accuracy: {accuracy:.4f}"
    )

    # -----------------------------------------------------
    # Classification report
    # -----------------------------------------------------

    report = classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    report_df = pd.DataFrame(
        report
    ).transpose()

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    matrix = confusion_matrix(
        y_test,
        y_pred
    )

    confusion_df = pd.DataFrame(
        matrix,
        index=label_encoder.classes_,
        columns=label_encoder.classes_,
    )

    # -----------------------------------------------------
    # Overall metrics
    # -----------------------------------------------------

    metrics = {
        "model": "Random Forest",
        "records": int(len(df)),
        "training_records": int(len(X_train)),
        "testing_records": int(len(X_test)),
        "features": int(len(feature_names)),
        "classes": int(len(label_encoder.classes_)),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "accuracy": float(accuracy),
        "macro_precision": float(
            report["macro avg"]["precision"]
        ),
        "macro_recall": float(
            report["macro avg"]["recall"]
        ),
        "macro_f1": float(
            report["macro avg"]["f1-score"]
        ),
        "weighted_precision": float(
            report["weighted avg"]["precision"]
        ),
        "weighted_recall": float(
            report["weighted avg"]["recall"]
        ),
        "weighted_f1": float(
            report["weighted avg"]["f1-score"]
        ),
    }

    # -----------------------------------------------------
    # Save results
    # -----------------------------------------------------

    RESULTS_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    report_df.to_csv(
        REPORT_FILE
    )

    confusion_df.to_csv(
        CONFUSION_FILE
    )

    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4
        )

    # -----------------------------------------------------
    # Display results
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("SAVED EVALUATION RESULTS")
    print("=" * 70)

    print(
        f"\nClassification report:"
        f"\n{REPORT_FILE}"
    )

    print(
        f"\nConfusion matrix:"
        f"\n{CONFUSION_FILE}"
    )

    print(
        f"\nModel metrics:"
        f"\n{METRICS_FILE}"
    )

    print("\nKey metrics:")

    print(
        f"Accuracy:          "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Macro Precision:   "
        f"{metrics['macro_precision']:.4f}"
    )

    print(
        f"Macro Recall:      "
        f"{metrics['macro_recall']:.4f}"
    )

    print(
        f"Macro F1:          "
        f"{metrics['macro_f1']:.4f}"
    )

    print("\n" + "=" * 70)
    print("EVALUATION SAVED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
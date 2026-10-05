from pathlib import Path

import joblib
import pandas as pd


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

MODEL_FILE = MODEL_DIR / "sentinelai_random_forest.joblib"

LABEL_ENCODER_FILE = MODEL_DIR / "label_encoder.joblib"

FEATURE_FILE = MODEL_DIR / "feature_names.joblib"


# ---------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------

SEVERITY_MAP = {
    "BENIGN": "LOW",

    "Bot": "HIGH",
    "DDoS": "CRITICAL",
    "DoS GoldenEye": "HIGH",
    "DoS Hulk": "CRITICAL",
    "DoS Slowhttptest": "HIGH",
    "DoS slowloris": "HIGH",
    "FTP-Patator": "HIGH",
    "Heartbleed": "CRITICAL",
    "Infiltration": "CRITICAL",
    "PortScan": "MEDIUM",
    "SSH-Patator": "HIGH",
    "Web Attack ï¿½ Brute Force": "HIGH",
    "Web Attack ï¿½ Sql Injection": "CRITICAL",
    "Web Attack ï¿½ XSS": "HIGH",
}


# ---------------------------------------------------------
# Prediction engine
# ---------------------------------------------------------

class SentinelAIPredictor:

    def __init__(self):

        print("Loading SentinelAI model...")

        self.model = joblib.load(
            MODEL_FILE
        )

        self.label_encoder = joblib.load(
            LABEL_ENCODER_FILE
        )

        self.feature_names = joblib.load(
            FEATURE_FILE
        )

        print("Model loaded successfully.")

    # -----------------------------------------------------
    # Predict a single network-flow record
    # -----------------------------------------------------

    def predict(self, flow):

        # Convert input into DataFrame.
        if isinstance(flow, dict):

            data = pd.DataFrame(
                [flow]
            )

        elif isinstance(flow, pd.DataFrame):

            data = flow.copy()

        else:

            raise TypeError(
                "Input must be a dictionary or pandas DataFrame."
            )

        # -------------------------------------------------
        # Check required features
        # -------------------------------------------------

        missing_features = [
            feature
            for feature in self.feature_names
            if feature not in data.columns
        ]

        if missing_features:

            raise ValueError(
                "Missing required features: "
                + ", ".join(missing_features)
            )

        # -------------------------------------------------
        # Select features in EXACT model order
        # -------------------------------------------------

        X = data[
            self.feature_names
        ]

        # -------------------------------------------------
        # Generate prediction
        # -------------------------------------------------

        prediction = self.model.predict(
            X
        )

        # Convert encoded label back to text.
        attack_type = self.label_encoder.inverse_transform(
            prediction
        )[0]

        # -------------------------------------------------
        # Confidence
        # -------------------------------------------------

        probabilities = self.model.predict_proba(
            X
        )[0]

        confidence = float(
            probabilities.max()
        ) * 100

        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        severity = SEVERITY_MAP.get(
            attack_type,
            "HIGH"
        )

        # -------------------------------------------------
        # Result
        # -------------------------------------------------

        is_malicious = (
            attack_type != "BENIGN"
        )

        return {
            "attack_type": attack_type,
            "confidence": round(
                confidence,
                2
            ),
            "severity": severity,
            "status": (
                "MALICIOUS"
                if is_malicious
                else "BENIGN"
            ),
        }


# ---------------------------------------------------------
# Test the prediction engine
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("SentinelAI - Prediction Engine Test")
    print("=" * 70)

    predictor = SentinelAIPredictor()

    # -----------------------------------------------------
    # Load one real record from CIC-IDS2017
    # -----------------------------------------------------

    dataset_file = Path(
        r"dataset\processed\training_data.csv"
    )

    print(
        "\nLoading a real network-flow record..."
    )

    df = pd.read_csv(
        dataset_file,
        nrows=1
    )

    # -----------------------------------------------------
    # Make prediction
    # -----------------------------------------------------

    result = predictor.predict(
        df
    )

    print("\n" + "=" * 70)
    print("PREDICTION RESULT")
    print("=" * 70)

    print(
        f"\nAttack Type : "
        f"{result['attack_type']}"
    )

    print(
        f"Confidence  : "
        f"{result['confidence']}%"
    )

    print(
        f"Severity    : "
        f"{result['severity']}"
    )

    print(
        f"Status      : "
        f"{result['status']}"
    )

    print("\n" + "=" * 70)
    print("Prediction engine working successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()
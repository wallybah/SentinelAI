from pathlib import Path

import pandas as pd

from .predict import (
    SentinelAIPredictor,
    SEVERITY_MAP,
)

from .recommendations import (
    RecommendationEngine,
)


# =========================================================
# Severity ranking
# =========================================================

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# =========================================================
# SentinelAI CSV Analyzer
# =========================================================

class SentinelAIAnalyzer:

    def __init__(self):

        print("Initializing SentinelAI analyzer...")

        self.predictor = SentinelAIPredictor()

        self.recommendation_engine = (
            RecommendationEngine()
        )

        print("Analyzer ready.")

    # =====================================================
    # Analyze CSV
    # =====================================================

    def analyze_csv(self, file_path):

        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(
                f"CSV file not found: {file_path}"
            )

        print(
            f"\nLoading CSV: {file_path.name}"
        )

        df = pd.read_csv(file_path)

        print(
            f"Rows loaded: {len(df):,}"
        )

        if df.empty:
            raise ValueError(
                "The CSV file contains no records."
            )

        # -------------------------------------------------
        # Clean column names
        # -------------------------------------------------

        df.columns = (
            df.columns
            .astype(str)
            .str.strip()
        )

        print("Column names cleaned.")

        # -------------------------------------------------
        # Check required model features
        # -------------------------------------------------

        missing_features = [
            feature
            for feature in self.predictor.feature_names
            if feature not in df.columns
        ]

        if missing_features:

            raise ValueError(
                "The CSV is missing required "
                "network-flow features:\n"
                + "\n".join(
                    f"  - {feature}"
                    for feature in missing_features
                )
            )

        print(
            f"All {len(self.predictor.feature_names)} "
            "required model features found."
        )

        # -------------------------------------------------
        # Select features in exact model order
        # -------------------------------------------------

        X = df[
            self.predictor.feature_names
        ].copy()

        # -------------------------------------------------
        # Convert features to numeric
        # -------------------------------------------------

        for column in X.columns:

            X[column] = pd.to_numeric(
                X[column],
                errors="coerce",
            )

        # -------------------------------------------------
        # Replace infinity with NaN
        # -------------------------------------------------

        X.replace(
            [float("inf"), float("-inf")],
            float("nan"),
            inplace=True,
        )

        # -------------------------------------------------
        # Handle missing values
        # -------------------------------------------------

        missing_before = int(
            X.isna().sum().sum()
        )

        if missing_before > 0:

            print(
                f"Missing numeric values detected: "
                f"{missing_before:,}"
            )

            for column in X.columns:

                if X[column].isna().any():

                    median_value = X[column].median()

                    if pd.isna(median_value):
                        median_value = 0

                    X[column] = (
                        X[column]
                        .fillna(median_value)
                    )

        missing_after = int(
            X.isna().sum().sum()
        )

        print(
            f"Missing values after cleaning: "
            f"{missing_after:,}"
        )

        # -------------------------------------------------
        # Generate predictions
        # -------------------------------------------------

        print(
            "\nRunning SentinelAI predictions..."
        )

        predictions = (
            self.predictor.model.predict(X)
        )

        probabilities = (
            self.predictor.model.predict_proba(X)
        )

        # -------------------------------------------------
        # Convert encoded predictions to labels
        # -------------------------------------------------

        predicted_labels = (
            self.predictor.label_encoder
            .inverse_transform(predictions)
        )

        # -------------------------------------------------
        # Build prediction table
        # -------------------------------------------------

        results = pd.DataFrame(
            {
                "Prediction": predicted_labels,

                "Confidence": (
                    probabilities.max(axis=1)
                    * 100
                ),
            }
        )

        # -------------------------------------------------
        # Add severity
        # -------------------------------------------------

        results["Severity"] = (
            results["Prediction"]
            .map(
                lambda label:
                SEVERITY_MAP.get(
                    label,
                    "HIGH",
                )
            )
        )

        # -------------------------------------------------
        # Add status
        # -------------------------------------------------

        results["Status"] = (
            results["Prediction"]
            .apply(
                lambda label:
                "BENIGN"
                if label == "BENIGN"
                else "MALICIOUS"
            )
        )

        # -------------------------------------------------
        # Round confidence
        # -------------------------------------------------

        results["Confidence"] = (
            results["Confidence"]
            .round(2)
        )

        # =================================================
        # Summary statistics
        # =================================================

        total_records = len(results)

        benign_count = int(
            (
                results["Prediction"]
                == "BENIGN"
            ).sum()
        )

        malicious_count = (
            total_records - benign_count
        )

        malicious_percentage = (
            malicious_count
            / total_records
            * 100
            if total_records > 0
            else 0
        )

        # =================================================
        # Attack distribution
        # =================================================

        attack_distribution = (
            results["Prediction"]
            .value_counts()
            .to_dict()
        )

        # =================================================
        # Severity distribution
        # =================================================

        severity_distribution = (
            results["Severity"]
            .value_counts()
            .to_dict()
        )

        # =================================================
        # Determine highest severity
        # =================================================

        highest_severity = "LOW"

        for severity in severity_distribution:

            current_rank = SEVERITY_RANK.get(
                severity,
                0,
            )

            highest_rank = SEVERITY_RANK.get(
                highest_severity,
                0,
            )

            if current_rank > highest_rank:
                highest_severity = severity

        # =================================================
        # Generate recommendations
        # =================================================

        print(
            "\nGenerating security recommendations..."
        )

        recommendations = (
            self.recommendation_engine
            .get_analysis_recommendations(
                attack_distribution
            )
        )

        # =================================================
        # Build final analysis object
        # =================================================

        analysis = {

            "file_name":
                file_path.name,

            "total_records":
                total_records,

            "benign_records":
                benign_count,

            "malicious_records":
                malicious_count,

            "malicious_percentage":
                round(
                    malicious_percentage,
                    2,
                ),

            "highest_severity":
                highest_severity,

            "attack_distribution":
                attack_distribution,

            "severity_distribution":
                severity_distribution,

            "recommendations":
                recommendations,

            "predictions":
                results,
        }

        return analysis


# =========================================================
# Standalone test
# =========================================================

def main():

    print("=" * 70)
    print(
        "SentinelAI - Integrated CSV Threat Analysis Test"
    )
    print("=" * 70)

    # -----------------------------------------------------
    # Initialize analyzer
    # -----------------------------------------------------

    analyzer = SentinelAIAnalyzer()

    # -----------------------------------------------------
    # Dataset used for testing
    # -----------------------------------------------------

    project_root = Path(__file__).resolve().parent.parent

    dataset_file = (
        project_root
        / "dataset"
        / "CIC_IDS2017"
        / "MachineLearningCVE"
        / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    # -----------------------------------------------------
    # Run analysis
    # -----------------------------------------------------

    analysis = analyzer.analyze_csv(
        dataset_file
    )

    # =====================================================
    # Display analysis summary
    # =====================================================

    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)

    print(
        f"\nFile:"
        f"\n{analysis['file_name']}"
    )

    print(
        f"\nTotal records:"
        f"\n{analysis['total_records']:,}"
    )

    print(
        f"\nBenign records:"
        f"\n{analysis['benign_records']:,}"
    )

    print(
        f"\nMalicious records:"
        f"\n{analysis['malicious_records']:,}"
    )

    print(
        f"\nMalicious percentage:"
        f"\n{analysis['malicious_percentage']}%"
    )

    print(
        f"\nHighest severity:"
        f"\n{analysis['highest_severity']}"
    )

    # =====================================================
    # Attack distribution
    # =====================================================

    print("\nAttack distribution:")

    for attack, count in sorted(
        analysis[
            "attack_distribution"
        ].items(),

        key=lambda item: item[1],

        reverse=True,
    ):

        percentage = (
            count
            / analysis["total_records"]
            * 100
        )

        print(
            f"  {attack}: "
            f"{count:,} "
            f"({percentage:.2f}%)"
        )

    # =====================================================
    # Severity distribution
    # =====================================================

    print("\nSeverity distribution:")

    for severity, count in sorted(
        analysis[
            "severity_distribution"
        ].items(),

        key=lambda item:
        SEVERITY_RANK.get(
            item[0],
            0,
        ),

        reverse=True,
    ):

        print(
            f"  {severity}: "
            f"{count:,}"
        )

    # =====================================================
    # Security recommendations
    # =====================================================

    print("\n" + "=" * 70)
    print("SECURITY RECOMMENDATIONS")
    print("=" * 70)

    for attack, recommendations in (
        analysis[
            "recommendations"
        ].items()
    ):

        # Don't show BENIGN recommendations in the
        # primary security recommendation section.
        if attack == "BENIGN":
            continue

        print(
            f"\n[{attack}]"
        )

        for number, recommendation in enumerate(
            recommendations,
            start=1,
        ):

            print(
                f"  {number}. "
                f"{recommendation}"
            )

    print("\n" + "=" * 70)
    print("INTEGRATED ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
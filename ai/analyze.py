from pathlib import Path

import numpy as np
import pandas as pd

from .predict import SentinelAIPredictor, SEVERITY_MAP
from .recommendations import RecommendationEngine


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class SentinelAIAnalyzer:
    CHUNK_SIZE = 10_000

    def __init__(self):
        print("Initializing SentinelAI analyzer...")
        self.predictor = SentinelAIPredictor()
        self.recommendation_engine = RecommendationEngine()
        print("Analyzer ready.")

    def _find_missing_columns(self, file_path, columns):
        """Find feature columns that contain missing or infinite values."""
        missing_columns = set()

        for chunk in pd.read_csv(
            file_path,
            chunksize=self.CHUNK_SIZE,
        ):
            chunk.columns = chunk.columns.astype(str).str.strip()
            chunk = chunk[columns]
            chunk = chunk.apply(pd.to_numeric, errors="coerce")
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

            for column in columns:
                if chunk[column].isna().any():
                    missing_columns.add(column)

        return missing_columns

    def _calculate_global_medians(self, file_path, missing_columns):
        """Calculate global medians only for columns that need them."""
        if not missing_columns:
            return {}

        value_chunks = {
            column: []
            for column in missing_columns
        }

        for chunk in pd.read_csv(
            file_path,
            chunksize=self.CHUNK_SIZE,
        ):
            chunk.columns = chunk.columns.astype(str).str.strip()
            chunk = chunk[list(missing_columns)]
            chunk = chunk.apply(pd.to_numeric, errors="coerce")
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

            for column in missing_columns:
                values = chunk[column].dropna()

                if not values.empty:
                    value_chunks[column].append(values)

        global_medians = {}

        for column in missing_columns:
            if value_chunks[column]:
                all_values = pd.concat(value_chunks[column], ignore_index=True)
                median_value = all_values.median()

                if pd.isna(median_value):
                    median_value = 0

                global_medians[column] = median_value
            else:
                global_medians[column] = 0

        return global_medians

    def _prepare_features(self, chunk, global_medians):
        """Prepare one CSV chunk for model prediction."""
        X = chunk[self.predictor.feature_names].copy()

        for column in X.columns:
            X[column] = pd.to_numeric(X[column], errors="coerce")

        X.replace([np.inf, -np.inf], np.nan, inplace=True)

        for column, median_value in global_medians.items():
            if column in X.columns:
                X[column] = X[column].fillna(median_value)

        return X

    def analyze_csv(self, file_path):
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"CSV file not found: {file_path}")

        print(f"\nLoading CSV: {file_path.name}")

        # Read only the header first.
        header = pd.read_csv(file_path, nrows=0)
        header.columns = header.columns.astype(str).str.strip()

        missing_features = [
            feature
            for feature in self.predictor.feature_names
            if feature not in header.columns
        ]

        if missing_features:
            raise ValueError(
                f"Missing required features: {missing_features}"
            )

        feature_columns = list(self.predictor.feature_names)

        print("Pass 1/3: checking missing values...")

        missing_columns = self._find_missing_columns(
            file_path,
            feature_columns,
        )

        print(
            f"Columns requiring median imputation: "
            f"{len(missing_columns)}"
        )

        print("Pass 2/3: calculating global medians...")

        global_medians = self._calculate_global_medians(
            file_path,
            missing_columns,
        )

        print("Pass 3/3: running model predictions...")

        attack_distribution = {}
        severity_distribution = {}
        total_records = 0
        benign_count = 0
        malicious_count = 0

        for chunk_number, chunk in enumerate(
            pd.read_csv(
                file_path,
                chunksize=self.CHUNK_SIZE,
            ),
            start=1,
        ):
            chunk.columns = chunk.columns.astype(str).str.strip()

            X = self._prepare_features(
                chunk,
                global_medians,
            )

            predictions = self.predictor.model.predict(X)

            predicted_labels = (
                self.predictor.label_encoder.inverse_transform(
                    predictions
                )
            )

            for label in predicted_labels:
                label = str(label)

                attack_distribution[label] = (
                    attack_distribution.get(label, 0) + 1
                )

                severity = SEVERITY_MAP.get(label, "HIGH")

                severity_distribution[severity] = (
                    severity_distribution.get(severity, 0) + 1
                )

                if label == "BENIGN":
                    benign_count += 1
                else:
                    malicious_count += 1

                total_records += 1

            print(
                f"Processed chunk {chunk_number}: "
                f"{total_records:,} records"
            )

        if total_records == 0:
            raise ValueError("CSV file contains no records.")

        malicious_percentage = (
            malicious_count / total_records * 100
        )

        highest_severity = "LOW"

        for severity in severity_distribution:
            current_rank = SEVERITY_RANK.get(severity, 0)
            highest_rank = SEVERITY_RANK.get(
                highest_severity,
                0,
            )

            if current_rank > highest_rank:
                highest_severity = severity

        recommendations = (
            self.recommendation_engine.get_analysis_recommendations(
                attack_distribution
            )
        )

        analysis = {
            "file_name": file_path.name,
            "total_records": total_records,
            "benign_records": benign_count,
            "malicious_records": malicious_count,
            "malicious_percentage": round(
                malicious_percentage,
                2,
            ),
            "highest_severity": highest_severity,
            "attack_distribution": attack_distribution,
            "severity_distribution": severity_distribution,
            "recommendations": recommendations,
        }

        return analysis


if __name__ == "__main__":
    analyzer = SentinelAIAnalyzer()

    dataset_path = (
        Path(__file__).resolve().parent.parent
        / "dataset"
        / "CIC_IDS2017"
        / "MachineLearningCVE"
        / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    result = analyzer.analyze_csv(dataset_path)

    print("\n" + "=" * 60)
    print("SENTINELAI ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Total records: {result['total_records']:,}")
    print(f"Benign: {result['benign_records']:,}")
    print(f"Malicious: {result['malicious_records']:,}")
    print(f"Malicious percentage: {result['malicious_percentage']}%")
    print(f"Highest severity: {result['highest_severity']}")

    print("\nAttack distribution:")
    for label, count in result["attack_distribution"].items():
        print(f"  {label}: {count:,}")

    print("\nSeverity distribution:")
    for severity, count in result["severity_distribution"].items():
        print(f"  {severity}: {count:,}")

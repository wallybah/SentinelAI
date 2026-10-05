from datetime import datetime, timezone
from pathlib import Path
import json
import csv
import os
from urllib.request import urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ============================================================
# SENTINELAI AI ASSISTANT BACKEND
# ============================================================

app = FastAPI(
    title="SentinelAI AI Assistant",
    version="2.1.0",
    description=(
        "Analysis-aware cybersecurity assistant for SentinelAI."
    ),
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RESULTS_FILE = (
    BASE_DIR
    / "results"
    / "latest_analysis.json"
)

ML_METRICS_FILE = (
    BASE_DIR
    / "results"
    / "model_metrics.json"
)

ML_CLASSIFICATION_FILE = (
    BASE_DIR
    / "results"
    / "classification_report.csv"
)

MAIN_BACKEND_URL = os.getenv(
    "MAIN_BACKEND_URL",
    "http://127.0.0.1:8000",
)

ML_CONFUSION_FILE = (
    BASE_DIR
    / "results"
    / "confusion_matrix.csv"
)


# ============================================================
# REQUEST MODEL
# ============================================================

class AssistantRequest(BaseModel):
    question: str


# ============================================================
# LOAD LATEST ANALYSIS
# ============================================================

def load_latest_analysis():
    """
    Load the most recent SentinelAI analysis.

    Locally, the Assistant reads:

        results/latest_analysis.json

    When deployed as a separate service, the Assistant can
    request the latest analysis from the main SentinelAI backend.
    """

    # --------------------------------------------------------
    # Local analysis file
    # --------------------------------------------------------

    if RESULTS_FILE.exists():

        try:

            with open(
                RESULTS_FILE,
                "r",
                encoding="utf-8",
            ) as file:

                return json.load(file)

        except Exception as error:

            print(
                "Could not load local latest analysis:",
                repr(error),
            )

    # --------------------------------------------------------
    # Deployed main backend
    # --------------------------------------------------------

    try:

        url = (
            MAIN_BACKEND_URL.rstrip("/")
            + "/api/latest-analysis"
        )

        with urlopen(
            url,
            timeout=10,
        ) as response:

            data = response.read().decode(
                "utf-8"
            )

            return json.loads(data)

    except Exception as error:

        print(
            "Could not load latest analysis from "
            "main backend:",
            repr(error),
        )

        return None

# ============================================================
# NUMBER FORMATTER
# ============================================================

def format_number(value):

    try:
        return f"{int(value):,}"

    except (
        TypeError,
        ValueError,
    ):

        return "0"


# ============================================================
# PERCENTAGE FORMATTER
# ============================================================

def format_percentage(value):

    try:
        return f"{float(value):.2f}%"

    except (
        TypeError,
        ValueError,
    ):

        return "0.00%"


# ============================================================
# CLEAN ATTACK NAME
# ============================================================

def clean_attack_name(name):
    """
    Fix common encoding problems that can occur with
    CIC-IDS2017 labels.
    """

    if not name:
        return ""

    name = str(name)

    replacements = {
        "ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¿Ãƒâ€šÃ‚Â½": "-",
        "ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¯ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¿ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â½": "-",
        "ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ": "-",
        "ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â": "-",
        "ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“": "-",
        "ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬": "-",
    }

    for bad, good in replacements.items():

        name = name.replace(
            bad,
            good,
        )

    return name


# ============================================================
# FIND ATTACK
# ============================================================

def find_attack(
    analysis,
    keywords,
):
    """
    Find an attack in the latest analysis using keywords.
    """

    distribution = analysis.get(
        "attack_distribution",
        {},
    )

    for attack_name, count in distribution.items():

        cleaned_name = clean_attack_name(
            attack_name
        )

        lowered_name = cleaned_name.lower()

        for keyword in keywords:

            if keyword.lower() in lowered_name:

                return {
                    "name": cleaned_name,
                    "count": int(count),
                }

    return None


# ============================================================
# GET ATTACK PERCENTAGE
# ============================================================

def attack_percentage(
    count,
    total,
):

    try:

        if total <= 0:
            return 0.0

        return (
            float(count)
            / float(total)
        ) * 100

    except (
        TypeError,
        ValueError,
        ZeroDivisionError,
    ):

        return 0.0


# ============================================================
# GET TOP MALICIOUS ATTACKS
# ============================================================

def get_malicious_attacks(analysis):

    distribution = analysis.get(
        "attack_distribution",
        {},
    )

    attacks = []

    for attack_name, count in distribution.items():

        cleaned_name = clean_attack_name(
            attack_name
        )

        # BENIGN is not an attack.
        if cleaned_name.upper() == "BENIGN":
            continue

        try:

            numeric_count = int(count)

        except (
            TypeError,
            ValueError,
        ):

            continue

        attacks.append(
            {
                "name": cleaned_name,
                "count": numeric_count,
            }
        )

    attacks.sort(
        key=lambda item: item["count"],
        reverse=True,
    )

    return attacks


# ============================================================
# LOAD ML MODEL EVALUATION
# ============================================================

def load_ml_evaluation():
    """
    Load the actual SentinelAI machine-learning evaluation
    results from the results directory.

    Sources:
        model_metrics.json
        classification_report.csv
        confusion_matrix.csv
    """

    if not ML_METRICS_FILE.exists():

        return None

    try:

        # ----------------------------------------------------
        # Overall metrics
        # ----------------------------------------------------

        with open(
            ML_METRICS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            metrics = json.load(file)


        # ----------------------------------------------------
        # Class performance
        # ----------------------------------------------------

        class_performance = []

        if ML_CLASSIFICATION_FILE.exists():

            with open(
                ML_CLASSIFICATION_FILE,
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as file:

                reader = csv.DictReader(
                    file
                )

                for row in reader:

                    name = (
                        row.get("")
                        or row.get("class")
                        or row.get("label")
                    )

                    if not name:
                        continue

                    name = str(
                        name
                    ).strip()

                    if name.lower() in {
                        "accuracy",
                        "macro avg",
                        "weighted avg",
                    }:

                        continue

                    try:

                        class_performance.append(
                            {
                                "name": clean_attack_name(
                                    name
                                ),
                                "precision": (
                                    float(
                                        row.get(
                                            "precision",
                                            0,
                                        )
                                    ) * 100
                                ),
                                "recall": (
                                    float(
                                        row.get(
                                            "recall",
                                            0,
                                        )
                                    ) * 100
                                ),
                                "f1": (
                                    float(
                                        row.get(
                                            "f1-score",
                                            0,
                                        )
                                    ) * 100
                                ),
                                "support": int(
                                    float(
                                        row.get(
                                            "support",
                                            0,
                                        )
                                    )
                                ),
                            }
                        )

                    except (
                        TypeError,
                        ValueError,
                    ):

                        continue


        # ----------------------------------------------------
        # Confusion matrix
        # ----------------------------------------------------

        confusion_labels = []

        confusion_matrix = []

        if ML_CONFUSION_FILE.exists():

            with open(
                ML_CONFUSION_FILE,
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as file:

                reader = csv.reader(
                    file
                )

                rows = list(
                    reader
                )

            if rows:

                confusion_labels = [
                    str(label).strip()
                    for label in rows[0][1:]
                ]

                for row in rows[1:]:

                    if len(row) < 2:
                        continue

                    try:

                        confusion_matrix.append(
                            [
                                int(
                                    float(
                                        value or 0
                                    )
                                )
                                for value in row[1:]
                            ]
                        )

                    except ValueError:

                        continue


        # ----------------------------------------------------
        # Return complete evaluation
        # ----------------------------------------------------

        return {
            "model": metrics.get(
                "model",
                "Unknown",
            ),

            "records": metrics.get(
                "records",
                0,
            ),

            "training_records": metrics.get(
                "training_records",
                0,
            ),

            "testing_records": metrics.get(
                "testing_records",
                0,
            ),

            "features": metrics.get(
                "features",
                0,
            ),

            "classes": metrics.get(
                "classes",
                len(confusion_labels),
            ),

            "test_size": metrics.get(
                "test_size",
                0,
            ),

            "random_state": metrics.get(
                "random_state",
                42,
            ),

            "accuracy": (
                float(
                    metrics.get(
                        "accuracy",
                        0,
                    )
                ) * 100
            ),

            "macro_precision": (
                float(
                    metrics.get(
                        "macro_precision",
                        0,
                    )
                ) * 100
            ),

            "macro_recall": (
                float(
                    metrics.get(
                        "macro_recall",
                        0,
                    )
                ) * 100
            ),

            "macro_f1": (
                float(
                    metrics.get(
                        "macro_f1",
                        0,
                    )
                ) * 100
            ),

            "weighted_precision": (
                float(
                    metrics.get(
                        "weighted_precision",
                        0,
                    )
                ) * 100
            ),

            "weighted_recall": (
                float(
                    metrics.get(
                        "weighted_recall",
                        0,
                    )
                ) * 100
            ),

            "weighted_f1": (
                float(
                    metrics.get(
                        "weighted_f1",
                        0,
                    )
                ) * 100
            ),

            "class_performance": (
                class_performance
            ),

            "confusion_labels": (
                confusion_labels
            ),

            "confusion_matrix": (
                confusion_matrix
            ),
        }


    except Exception as error:

        print(
            "Could not load ML evaluation:",
            repr(error),
        )

        return None


# ============================================================
# FIND ML CLASS
# ============================================================

def find_ml_class(
    evaluation,
    keywords,
):

    if not evaluation:
        return None

    classes = evaluation.get(
        "class_performance",
        [],
    )

    for item in classes:

        name = clean_attack_name(
            item.get(
                "name",
                "",
            )
        )

        lowered = name.lower()

        for keyword in keywords:

            if keyword.lower() in lowered:

                return item

    return None


# ============================================================
# FIND CONFUSION MATRIX VALUE
# ============================================================

def find_confusion_value(
    evaluation,
    actual_keywords,
    predicted_keywords,
):

    if not evaluation:
        return None

    labels = evaluation.get(
        "confusion_labels",
        [],
    )

    matrix = evaluation.get(
        "confusion_matrix",
        [],
    )

    actual_index = None
    predicted_index = None

    for index, label in enumerate(labels):

        cleaned = clean_attack_name(
            label
        ).lower()

        if any(
            keyword.lower() in cleaned
            for keyword in actual_keywords
        ):

            actual_index = index

        if any(
            keyword.lower() in cleaned
            for keyword in predicted_keywords
        ):

            predicted_index = index

    if (
        actual_index is None
        or predicted_index is None
    ):

        return None

    try:

        return int(
            matrix[
                actual_index
            ][
                predicted_index
            ]
        )

    except (
        IndexError,
        TypeError,
        ValueError,
    ):

        return None


# ============================================================
# GENERAL ATTACK EXPLANATIONS
# ============================================================

ATTACK_EXPLANATIONS = {

    "ddos": (
        "DDoS (Distributed Denial of Service) is an attack "
        "that attempts to overwhelm a service, server, or "
        "network resource with a large amount of traffic. "
        "In SentinelAI, DDoS activity is identified from "
        "network-flow characteristics."
    ),

    "bot": (
        "Bot activity can indicate systems communicating "
        "with or behaving like automated malicious hosts. "
        "A compromised host may participate in malicious "
        "activity without the user's knowledge."
    ),

    "xss": (
        "Cross-Site Scripting (XSS) is a web application "
        "attack involving malicious script content being "
        "injected into web pages or application responses. "
        "Important defenses include input validation, "
        "output encoding, sanitization, and Content "
        "Security Policy controls."
    ),

    "brute force": (
        "A brute-force attack repeatedly attempts "
        "authentication credentials or access requests. "
        "Useful defenses include rate limiting, strong "
        "authentication, account protection, and "
        "multi-factor authentication."
    ),

    "ssh": (
        "SSH provides secure remote access to systems. "
        "SSH-related attack activity should be investigated "
        "through authentication logs, source addresses, "
        "login attempts, and access-control configuration."
    ),

    "portscan": (
        "A PortScan attempts to discover open ports and "
        "services on a host or network. Port scanning can "
        "be reconnaissance activity that occurs before "
        "another attack."
    ),

    "dos hulk": (
        "DoS Hulk is a denial-of-service attack pattern "
        "associated with generating large numbers of HTTP "
        "requests against a target service."
    ),

    "slowhttptest": (
        "Slowhttptest represents slow HTTP denial-of-service "
        "behavior where connections or requests are kept "
        "open in order to consume server resources."
    ),

    "goldeneye": (
        "DoS GoldenEye is a denial-of-service attack that "
        "can generate repeated HTTP requests to consume "
        "web-server resources."
    ),
}


# ============================================================
# ATTACK-SPECIFIC RECOMMENDATIONS
# ============================================================

ATTACK_RECOMMENDATIONS = {

    "ddos": [
        "Enable rate limiting for incoming network traffic.",
        "Apply firewall rules to restrict suspicious traffic sources.",
        "Use DDoS mitigation or traffic filtering services.",
        "Monitor traffic volume and connection rates for abnormal spikes.",
        "Review affected services and verify their availability.",
    ],

    "bot": [
        "Investigate the affected host for signs of malware.",
        "Check running processes and unusual network connections.",
        "Review outbound connections from the affected system.",
        "Update operating systems and security software.",
        "Isolate the host if malicious activity is confirmed.",
    ],

    "xss": [
        "Apply proper input validation and output encoding.",
        "Use appropriate Content Security Policy controls.",
        "Review affected web application endpoints.",
        "Sanitize untrusted user input.",
        "Test the application for additional XSS vulnerabilities.",
    ],

    "brute force": [
        "Enable authentication rate limiting.",
        "Review login and authentication logs.",
        "Use account lockout or progressive delays.",
        "Require strong passwords and multi-factor authentication.",
        "Investigate repeated requests from suspicious sources.",
    ],

    "ssh": [
        "Review SSH authentication logs.",
        "Enable login throttling or account lockout controls.",
        "Restrict SSH access to trusted IP addresses.",
        "Disable password authentication when appropriate.",
        "Use strong authentication and SSH keys.",
    ],

    "portscan": [
        "Investigate the source of the scanning activity.",
        "Restrict unnecessary open ports using firewall rules.",
        "Disable unused network services.",
        "Review firewall and IDS/IPS logs for repeated scanning attempts.",
        "Restrict management services to trusted networks.",
    ],

    "dos hulk": [
        "Apply rate limiting to affected services.",
        "Block or restrict suspicious traffic sources.",
        "Review web-server and firewall logs.",
        "Monitor server resource utilization.",
        "Deploy appropriate DoS mitigation controls.",
    ],

    "slowhttptest": [
        "Review slow HTTP connection activity.",
        "Configure appropriate connection and request timeouts.",
        "Apply rate limiting to suspicious clients.",
        "Review web-server resource utilization.",
        "Use firewall or reverse-proxy protections where appropriate.",
    ],

    "goldeneye": [
        "Investigate the source of the denial-of-service traffic.",
        "Apply rate limiting and traffic filtering.",
        "Review firewall rules for suspicious connections.",
        "Monitor affected services for availability problems.",
        "Consider appropriate DoS/DDoS mitigation controls.",
    ],
}


# ============================================================
# ATTACK KEYWORD MATCHING
# ============================================================

def get_attack_key(question):

    q = question.lower()

    if (
        "ddos" in q
        or "distributed denial" in q
    ):
        return "ddos"

    if (
        "xss" in q
        or "cross site scripting" in q
        or "cross-site scripting" in q
    ):
        return "xss"

    if (
        "brute force" in q
        or "bruteforce" in q
    ):
        return "brute force"

    if (
        "ssh" in q
        or "ssh-patator" in q
    ):
        return "ssh"

    if (
        "portscan" in q
        or "port scan" in q
    ):
        return "portscan"

    if "bot" in q:
        return "bot"

    if (
        "slowhttptest" in q
        or "slow http" in q
    ):
        return "slowhttptest"

    if "goldeneye" in q:
        return "goldeneye"

    if "dos hulk" in q:
        return "dos hulk"

    return None


# ============================================================
# ATTACK DETAIL RESPONSE
# ============================================================

def attack_detail_response(
    analysis,
    attack_key,
):

    total = int(
        analysis.get(
            "total_records",
            0,
        )
    )

    attack = find_attack(
        analysis,
        [attack_key],
    )

    if attack is None:

        return (
            f"No {attack_key.upper()} activity was found "
            "in the latest SentinelAI analysis."
        )

    name = attack["name"]

    count = attack["count"]

    percentage = attack_percentage(
        count,
        total,
    )

    explanation = ATTACK_EXPLANATIONS.get(
        attack_key,
        "This is malicious network activity detected "
        "by the SentinelAI analysis.",
    )

    recommendations = ATTACK_RECOMMENDATIONS.get(
        attack_key,
        [],
    )

    response = (
        f"{name} analysis:\n\n"
        f"- Detected flows: {format_number(count)}\n"
        f"- Percentage of all flows: "
        f"{format_percentage(percentage)}\n"
        f"- Classification: MALICIOUS\n\n"
        f"What it means:\n"
        f"{explanation}"
    )

    if recommendations:

        response += (
            "\n\nRecommended actions:"
        )

        for recommendation in recommendations:

            response += (
                f"\n- {recommendation}"
            )

    return response


# ============================================================
# SUMMARY RESPONSE
# ============================================================

def summary_response(analysis):

    total = analysis.get(
        "total_records",
        0,
    )

    benign = analysis.get(
        "benign_records",
        0,
    )

    malicious = analysis.get(
        "malicious_records",
        0,
    )

    percentage = analysis.get(
        "malicious_percentage",
        0,
    )

    severity = analysis.get(
        "highest_severity",
        "UNKNOWN",
    )

    attacks = get_malicious_attacks(
        analysis
    )

    response = (
        "Latest SentinelAI analysis summary:\n\n"
        f"- Total network flows: {format_number(total)}\n"
        f"- Benign flows: {format_number(benign)}\n"
        f"- Malicious flows: {format_number(malicious)}\n"
        f"- Malicious traffic rate: "
        f"{format_percentage(percentage)}\n"
        f"- Highest severity: {severity}\n"
    )

    if attacks:

        top_attack = attacks[0]

        response += (
            f"- Most common malicious attack: "
            f"{top_attack['name']} "
            f"({format_number(top_attack['count'])} flows)\n"
            f"- Detected malicious categories: "
            f"{len(attacks)}\n"
        )

    return response


# ============================================================
# MOST COMMON ATTACK
# ============================================================

def most_common_attack_response(analysis):

    attacks = get_malicious_attacks(
        analysis
    )

    total = analysis.get(
        "total_records",
        0,
    )

    if not attacks:

        return (
            "No malicious attacks were detected "
            "in the latest analysis."
        )

    attack = attacks[0]

    percentage = attack_percentage(
        attack["count"],
        total,
    )

    return (
        f"{attack['name']} was the most common malicious "
        f"attack detected in the latest SentinelAI analysis, "
        f"with {format_number(attack['count'])} network flows. "
        f"This represents {format_percentage(percentage)} "
        f"of all analyzed flows."
    )


# ============================================================
# ATTACK LIST RESPONSE
# ============================================================

def attacks_detected_response(analysis):

    attacks = get_malicious_attacks(
        analysis
    )

    if not attacks:

        return (
            "No malicious attack categories were detected "
            "in the latest SentinelAI analysis."
        )

    response = (
        "The latest SentinelAI analysis detected "
        "the following malicious traffic categories:\n"
    )

    for attack in attacks:

        response += (
            f"- {attack['name']}: "
            f"{format_number(attack['count'])} flows\n"
        )

    return response.rstrip()


# ============================================================
# LOW-VOLUME ATTACKS
# ============================================================

def low_volume_response(analysis):

    attacks = get_malicious_attacks(
        analysis
    )

    low_volume = [
        attack
        for attack in attacks
        if attack["count"] <= 500
    ]

    if not low_volume:

        return (
            "No low-volume malicious attacks "
            "were identified using the current threshold."
        )

    response = (
        "Yes. The following malicious attacks have "
        "relatively low traffic volume:\n"
    )

    for attack in reversed(low_volume):

        response += (
            f"- {attack['name']}: "
            f"{format_number(attack['count'])} flows\n"
        )

    response += (
        "\nLow volume does not automatically mean low risk. "
        "Even a small number of flows can be important if "
        "they target a critical host, service, or account."
    )

    return response


# ============================================================
# DANGEROUS DATASET RESPONSE
# ============================================================

def dangerous_dataset_response(analysis):

    total = int(
        analysis.get(
            "total_records",
            0,
        )
    )

    malicious = int(
        analysis.get(
            "malicious_records",
            0,
        )
    )

    percentage = float(
        analysis.get(
            "malicious_percentage",
            0,
        )
    )

    severity = analysis.get(
        "highest_severity",
        "UNKNOWN",
    )

    attacks = get_malicious_attacks(
        analysis
    )

    if malicious > 0:

        response = (
            "Yes. The latest analysis should be treated "
            "as high risk because SentinelAI detected "
            "substantial malicious network activity.\n\n"
            f"- Total flows: {format_number(total)}\n"
            f"- Malicious flows: {format_number(malicious)}\n"
            f"- Malicious rate: "
            f"{format_percentage(percentage)}\n"
            f"- Highest severity: {severity}\n"
        )

        if attacks:

            response += (
                f"- Dominant attack: "
                f"{attacks[0]['name']} "
                f"({format_number(attacks[0]['count'])} flows)\n"
            )

        response += (
            "\nPriority: Investigate the dominant malicious "
            "traffic first and verify the affected systems "
            "and services."
        )

        return response

    return (
        "The latest analysis did not identify malicious "
        "traffic. However, a dataset being classified as "
        "benign does not by itself guarantee that a real "
        "network is completely secure."
    )


# ============================================================
# CRITICAL SEVERITY RESPONSE
# ============================================================

def critical_response(analysis):

    severity = analysis.get(
        "highest_severity",
        "UNKNOWN",
    )

    severity_distribution = analysis.get(
        "severity_distribution",
        {},
    )

    critical_count = severity_distribution.get(
        "CRITICAL",
        0,
    )

    attacks = get_malicious_attacks(
        analysis
    )

    response = (
        f"The analysis is marked {severity} because "
        "SentinelAI identified traffic associated with "
        "the highest-risk severity category.\n\n"
        f"- Critical-severity flows: "
        f"{format_number(critical_count)}\n"
    )

    if attacks:

        response += (
            f"- Dominant malicious attack: "
            f"{attacks[0]['name']}\n"
            f"- Dominant attack flows: "
            f"{format_number(attacks[0]['count'])}\n"
        )

    response += (
        "\nFrom a SOC perspective, Critical alerts should "
        "be prioritized for immediate investigation. "
        "Review affected hosts, network connections, "
        "firewall/IDS logs, and service availability."
    )

    return response


# ============================================================
# INVESTIGATION PRIORITY
# ============================================================

def investigation_priority_response(analysis):

    attacks = get_malicious_attacks(
        analysis
    )

    if not attacks:

        return (
            "No malicious attacks were detected. "
            "Continue normal monitoring and review "
            "the benign traffic for unexpected patterns."
        )

    response = (
        "Based on the latest SentinelAI analysis, "
        "I would investigate the threats in this order:\n\n"
    )

    for index, attack in enumerate(
        attacks[:5],
        start=1,
    ):

        response += (
            f"{index}. {attack['name']} - "
            f"{format_number(attack['count'])} flows\n"
        )

    response += (
        "\nFirst priority: investigate the dominant "
        "malicious traffic because it represents the "
        "largest malicious category.\n\n"
        "SOC investigation steps:\n"
        "- Identify affected source and destination systems.\n"
        "- Review firewall and IDS/IPS logs.\n"
        "- Check affected hosts for unusual processes "
        "and network connections.\n"
        "- Verify whether critical services are affected.\n"
        "- Apply the relevant SentinelAI mitigation recommendations."
    )

    return response


# ============================================================
# SOC ANALYST RESPONSE
# ============================================================

def soc_analyst_response(analysis):

    total = analysis.get(
        "total_records",
        0,
    )

    benign = analysis.get(
        "benign_records",
        0,
    )

    malicious = analysis.get(
        "malicious_records",
        0,
    )

    percentage = analysis.get(
        "malicious_percentage",
        0,
    )

    severity = analysis.get(
        "highest_severity",
        "UNKNOWN",
    )

    attacks = get_malicious_attacks(
        analysis
    )

    response = (
        "SOC analyst assessment of the latest "
        "SentinelAI analysis:\n\n"
        "1. Overall situation\n"
        f"SentinelAI analyzed {format_number(total)} "
        "network flows.\n"
        f"{format_number(malicious)} flows were classified "
        f"as malicious, representing "
        f"{format_percentage(percentage)} of the dataset.\n"
        f"{format_number(benign)} flows were classified "
        "as benign.\n\n"
        "2. Primary threat\n"
    )

    if attacks:

        response += (
            f"The most common malicious activity was "
            f"{attacks[0]['name']} with "
            f"{format_number(attacks[0]['count'])} flows.\n\n"
        )

    else:

        response += (
            "No malicious activity was identified.\n\n"
        )

    response += (
        "3. Severity\n"
        f"The highest severity is {severity}.\n"
        "The highest-risk activity should receive "
        "priority during investigation.\n\n"
        "4. Investigation priority\n"
    )

    if attacks:

        for index, attack in enumerate(
            attacks[:5],
            start=1,
        ):

            response += (
                f"{index}. {attack['name']} - "
                f"{format_number(attack['count'])} flows\n"
            )

    response += (
        "\n5. SOC response\n"
        "- Investigate the source and destination of "
        "the dominant malicious traffic.\n"
        "- Review firewall, IDS/IPS and server logs.\n"
        "- Check affected hosts for unusual processes "
        "or network connections.\n"
        "- Verify affected services and system availability.\n"
        "- Apply the relevant mitigation controls.\n"
        "- Continue monitoring for repeated or escalating activity."
    )

    return response


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

def recommendations_response(analysis):

    recommendations = analysis.get(
        "recommendations",
        {},
    )

    if not recommendations:

        return (
            "No security recommendations are available "
            "for the latest analysis."
        )

    response = (
        "Security recommendations from the latest "
        "SentinelAI analysis:\n"
    )

    attacks = get_malicious_attacks(
        analysis
    )

    for attack in attacks:

        attack_name = attack["name"]

        matching_key = None

        for key in ATTACK_RECOMMENDATIONS:

            if key in attack_name.lower():

                matching_key = key

                break

        if matching_key:

            response += (
                f"\n{attack_name}:\n"
            )

            for recommendation in (
                ATTACK_RECOMMENDATIONS[
                    matching_key
                ][:5]
            ):

                response += (
                    f"- {recommendation}\n"
                )

    if len(response.strip()) <= 50:

        for attack_name, items in recommendations.items():

            cleaned_name = clean_attack_name(
                attack_name
            )

            if cleaned_name.upper() == "BENIGN":

                continue

            response += (
                f"\n{cleaned_name}:\n"
            )

            for item in items[:5]:

                response += (
                    f"- {item}\n"
                )

    return response.rstrip()


# ============================================================
# MODEL PERFORMANCE RESPONSE
# ============================================================

def model_performance_response():

    evaluation = load_ml_evaluation()

    if evaluation is None:

        return (
            "ML model evaluation results are currently "
            "unavailable. Make sure the SentinelAI evaluation "
            "files exist in the results folder."
        )

    return (
        "SentinelAI machine-learning model performance:\n\n"
        f"- Model: {evaluation['model']}\n"
        f"- Evaluation records: "
        f"{format_number(evaluation['records'])}\n"
        f"- Training records: "
        f"{format_number(evaluation['training_records'])}\n"
        f"- Testing records: "
        f"{format_number(evaluation['testing_records'])}\n"
        f"- Features: "
        f"{format_number(evaluation['features'])}\n"
        f"- Classes: "
        f"{format_number(evaluation['classes'])}\n\n"
        f"- Accuracy: "
        f"{format_percentage(evaluation['accuracy'])}\n"
        f"- Macro Precision: "
        f"{format_percentage(evaluation['macro_precision'])}\n"
        f"- Macro Recall: "
        f"{format_percentage(evaluation['macro_recall'])}\n"
        f"- Macro F1: "
        f"{format_percentage(evaluation['macro_f1'])}\n"
        f"- Weighted F1: "
        f"{format_percentage(evaluation['weighted_f1'])}\n\n"
        "Macro metrics are especially useful here because "
        "they give equal importance to each attack class "
        "instead of allowing high-volume classes to dominate "
        "the evaluation."
    )


# ============================================================
# WEAKEST MODEL CLASS RESPONSE
# ============================================================

def weakest_model_class_response():

    evaluation = load_ml_evaluation()

    if evaluation is None:

        return (
            "ML model evaluation results are currently "
            "unavailable."
        )

    classes = evaluation.get(
        "class_performance",
        [],
    )

    if not classes:

        return (
            "Class-level ML evaluation results are "
            "currently unavailable."
        )

    weakest = min(
        classes,
        key=lambda item: item["f1"],
    )

    return (
        f"The weakest-performing class is "
        f"{weakest['name']}.\n\n"
        f"- Precision: "
        f"{format_percentage(weakest['precision'])}\n"
        f"- Recall: "
        f"{format_percentage(weakest['recall'])}\n"
        f"- F1 score: "
        f"{format_percentage(weakest['f1'])}\n"
        f"- Test samples: "
        f"{format_number(weakest['support'])}\n\n"
        "This indicates that the current Random Forest "
        "model has more difficulty distinguishing this "
        "traffic pattern than the other evaluated classes."
    )


# ============================================================
# MODEL LIMITATIONS RESPONSE
# ============================================================

def model_limitations_response():

    evaluation = load_ml_evaluation()

    if evaluation is None:

        return (
            "ML model evaluation results are currently "
            "unavailable."
        )

    classes = evaluation.get(
        "class_performance",
        [],
    )

    if not classes:

        return (
            "Class-level evaluation results are "
            "currently unavailable."
        )

    weakest = sorted(
        classes,
        key=lambda item: item["f1"],
    )[:3]

    response = (
        "Important SentinelAI model findings:\n\n"
        f"- Overall accuracy: "
        f"{format_percentage(evaluation['accuracy'])}\n"
        f"- Macro F1: "
        f"{format_percentage(evaluation['macro_f1'])}\n\n"
        "The three lowest F1-performing classes are:\n"
    )

    for item in weakest:

        response += (
            f"- {item['name']}: "
            f"{format_percentage(item['f1'])} F1\n"
        )

    response += (
        "\nThe main limitation is that overall accuracy "
        "does not represent every class equally. The web "
        "attack categories have noticeably lower F1 scores "
        "than several of the dominant traffic classes.\n\n"
        "In particular, Web Attack - XSS is currently the "
        "most difficult class for the model. Future work "
        "can investigate feature engineering, class "
        "balancing, additional web-traffic features, and "
        "comparison with other machine-learning algorithms."
    )

    return response


# ============================================================
# XSS MODEL RESPONSE
# ============================================================

def xss_model_response():

    evaluation = load_ml_evaluation()

    if evaluation is None:

        return (
            "ML model evaluation results are currently "
            "unavailable."
        )

    xss = find_ml_class(
        evaluation,
        [
            "xss",
            "web attack - xss",
            "web attack - xss",
        ],
    )

    if not xss:

        return (
            "No XSS class-level evaluation result "
            "was found."
        )

    confusion_value = find_confusion_value(
        evaluation,
        [
            "xss",
            "web attack - xss",
            "web attack - xss",
        ],
        [
            "brute force",
            "web attack - brute force",
            "web attack - brute force",
        ],
    )

    response = (
        "Web Attack - XSS model evaluation:\n\n"
        f"- Precision: "
        f"{format_percentage(xss['precision'])}\n"
        f"- Recall: "
        f"{format_percentage(xss['recall'])}\n"
        f"- F1 score: "
        f"{format_percentage(xss['f1'])}\n"
        f"- Test samples: "
        f"{format_number(xss['support'])}\n"
    )

    if confusion_value is not None:

        response += (
            f"\n- XSS samples classified as "
            f"Web Attack - Brute Force: "
            f"{format_number(confusion_value)}\n"
        )

    response += (
        "\nThis is currently the weakest-performing "
        "attack class in the SentinelAI evaluation. "
        "The result suggests that the current network-flow "
        "features do not always provide enough information "
        "to clearly distinguish XSS traffic from similar "
        "web-attack patterns."
    )

    return response


# ============================================================
# GENERAL QUESTION RESPONSE
# ============================================================

def general_response(analysis):

    if analysis is None:

        return (
            "I can help with cybersecurity topics and "
            "SentinelAI analysis. However, there is currently "
            "no latest analysis available.\n\n"
            "Upload and analyze a network-flow CSV first, "
            "then I can answer questions using the actual "
            "analysis results."
        )

    return (
        "I can help you analyze the latest SentinelAI results. "
        "You can ask questions such as:\n\n"
        "- Which attack was the most common?\n"
        "- What attacks were detected?\n"
        "- What is the attack rate?\n"
        "- What is the highest severity?\n"
        "- Why is the severity critical?\n"
        "- Is this dataset dangerous?\n"
        "- How many DDoS attacks were detected?\n"
        "- What should I investigate first?\n"
        "- Are there any low-volume attacks?\n"
        "- What are the security recommendations?\n"
        "- Tell me about the DDoS attack.\n"
        "- Explain this analysis like a SOC analyst.\n"
        "- What is the model accuracy?\n"
        "- What is the macro F1 score?\n"
        "- Which class performs worst?\n"
        "- What are the model limitations?\n"
        "- Tell me about the XSS model performance."
    )


# ============================================================
# MAIN RESPONSE ENGINE
# ============================================================

def generate_response(question):

    q = question.lower().strip()

    if not q:

        return (
            "Please enter a cybersecurity question."
        )

    analysis = load_latest_analysis()

    # --------------------------------------------------------
    # GREETING
    # --------------------------------------------------------

    if q in {
        "hello",
        "hi",
        "hey",
        "hello sentinelai",
        "hi sentinelai",
    }:

        return (
            "Hello! I am the SentinelAI cybersecurity "
            "assistant. I can analyze your latest SentinelAI "
            "results and answer SOC-related questions."
        )

    # --------------------------------------------------------
    # NO ANALYSIS
    # --------------------------------------------------------

    if analysis is None:

        return general_response(
            None
        )

    # --------------------------------------------------------
    # ML MODEL PERFORMANCE
    # --------------------------------------------------------

    if (
        "model performance" in q
        or "model accuracy" in q
        or "machine learning accuracy" in q
        or "ml accuracy" in q
        or "macro f1" in q
        or "macro precision" in q
        or "macro recall" in q
        or "weighted f1" in q
        or "how accurate is the model" in q
        or "how good is the model" in q
        or "random forest accuracy" in q
        or "random forest performance" in q
    ):

        return model_performance_response()

    # --------------------------------------------------------
    # WEAKEST MODEL CLASS
    # --------------------------------------------------------

    if (
        "weakest class" in q
        or "worst class" in q
        or "lowest f1" in q
        or "lowest performing class" in q
        or "which class performs worst" in q
        or "which class is weakest" in q
        or "weakest attack class" in q
    ):

        return weakest_model_class_response()

    # --------------------------------------------------------
    # MODEL LIMITATIONS
    # --------------------------------------------------------

    if (
        "model limitation" in q
        or "model limitations" in q
        or "limitations of the model" in q
        or "model weakness" in q
        or "model weaknesses" in q
        or "weakness of the model" in q
        or "weaknesses of the model" in q
    ):

        return model_limitations_response()
    # ============================================================
    # XSS MODEL PERFORMANCE
    # ============================================================

    if (
        "xss model" in q
        or "xss performance" in q
        or "xss f1" in q
        or "xss recall" in q
        or "xss precision" in q
        or "why is xss" in q
        or "why does xss" in q
        or "xss samples" in q
        or "xss classified as brute force" in q
        or "xss misclassified" in q
        or "xss confusion" in q
    ):
        return xss_model_response()
    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    if (
        "summary" in q
        or "summarize" in q
        or "overall analysis" in q
    ):

        return summary_response(
            analysis
        )

    # --------------------------------------------------------
    # SOC ANALYST
    # --------------------------------------------------------

    if (
        "soc analyst" in q
        or "soc analysis" in q
        or "like a soc" in q
        or "security operations" in q
    ):

        return soc_analyst_response(
            analysis
        )

    # --------------------------------------------------------
    # DANGEROUS DATASET
    # --------------------------------------------------------

    if (
        "dangerous" in q
        or "safe" in q
        or "is this dataset" in q
        or "is the dataset" in q
    ):

        return dangerous_dataset_response(
            analysis
        )

    # --------------------------------------------------------
    # CRITICAL SEVERITY
    # --------------------------------------------------------

    if (
        "why" in q
        and (
            "critical" in q
            or "severity" in q
        )
    ):

        return critical_response(
            analysis
        )

    if (
        "highest severity" in q
        or "most severe" in q
        or "maximum severity" in q
    ):

        severity = analysis.get(
            "highest_severity",
            "UNKNOWN",
        )

        return (
            f"The highest severity detected in the latest "
            f"SentinelAI analysis is {severity}."
        )

    # --------------------------------------------------------
    # ATTACK RATE
    # --------------------------------------------------------

    if (
        "attack rate" in q
        or "malicious rate" in q
        or "malicious percentage" in q
        or "percentage of malicious" in q
    ):

        percentage = analysis.get(
            "malicious_percentage",
            0,
        )

        return (
            f"The malicious traffic rate in the latest "
            f"analysis is {format_percentage(percentage)}."
        )

    # --------------------------------------------------------
    # MOST COMMON ATTACK
    # --------------------------------------------------------

    if (
        "most common" in q
        or "occurred the most" in q
        or "happened the most" in q
        or "largest attack" in q
        or "dominant attack" in q
    ):

        return most_common_attack_response(
            analysis
        )

    # --------------------------------------------------------
    # WHAT ATTACKS WERE DETECTED
    # --------------------------------------------------------

    if (
        "what attacks" in q
        or "which attacks" in q
        or "attacks detected" in q
        or "detected attacks" in q
        or "attack categories" in q
    ):

        return attacks_detected_response(
            analysis
        )

    # --------------------------------------------------------
    # INVESTIGATION PRIORITY
    # --------------------------------------------------------

    if (
        "investigate first" in q
        or "priority" in q
        or "where should i start" in q
        or "what should i check first" in q
        or "what should i investigate" in q
    ):

        return investigation_priority_response(
            analysis
        )

    # --------------------------------------------------------
    # LOW-VOLUME ATTACKS
    # --------------------------------------------------------

    if (
        "low-volume" in q
        or "low volume" in q
        or "small number" in q
        or "few attacks" in q
    ):

        return low_volume_response(
            analysis
        )

    # --------------------------------------------------------
    # BENIGN FLOWS
    # --------------------------------------------------------

    if (
        "benign" in q
        and (
            "how many" in q
            or "number" in q
            or "flows" in q
            or "traffic" in q
        )
    ):

        benign = analysis.get(
            "benign_records",
            0,
        )

        return (
            f"The latest SentinelAI analysis contains "
            f"{format_number(benign)} benign flows."
        )

    # --------------------------------------------------------
    # MALICIOUS FLOWS
    # --------------------------------------------------------

    if (
        "malicious flows" in q
        or "how many malicious" in q
        or "number of malicious" in q
    ):

        malicious = analysis.get(
            "malicious_records",
            0,
        )

        return (
            f"The latest SentinelAI analysis contains "
            f"{format_number(malicious)} malicious flows."
        )

    # --------------------------------------------------------
    # TOTAL FLOWS
    # --------------------------------------------------------

    if (
        "total flows" in q
        or "total records" in q
        or "how many flows" in q
        or "how many records" in q
    ):

        total = analysis.get(
            "total_records",
            0,
        )

        return (
            f"The latest SentinelAI analysis contains "
            f"{format_number(total)} network flows."
        )

    # --------------------------------------------------------
    # SECURITY RECOMMENDATIONS
    # --------------------------------------------------------

    if (
        "recommendation" in q
        or "recommended action" in q
        or "what should i do" in q
        or "how should i respond" in q
        or "mitigation" in q
    ):

        return recommendations_response(
            analysis
        )

    # --------------------------------------------------------
    # SPECIFIC ATTACK
    # --------------------------------------------------------

    attack_key = get_attack_key(
        q
    )

    if attack_key:

        # Questions asking how serious the attack is
        if (
            "serious" in q
            or "severity" in q
            or "dangerous" in q
            or "risk" in q
        ):

            attack = find_attack(
                analysis,
                [attack_key],
            )

            if attack:

                total = analysis.get(
                    "total_records",
                    0,
                )

                percentage = attack_percentage(
                    attack["count"],
                    total,
                )

                return (
                    f"{attack['name']} represents "
                    f"{format_number(attack['count'])} flows "
                    f"({format_percentage(percentage)} of all "
                    "analyzed flows).\n\n"
                    "Volume alone does not determine real-world "
                    "severity. The impact depends on the affected "
                    "system, source, destination, behavior, and "
                    "whether the activity is ongoing.\n\n"
                    "From a SOC perspective, investigate the "
                    "affected hosts, network connections, logs, "
                    "and related security events."
                )

        return attack_detail_response(
            analysis,
            attack_key,
        )

    # --------------------------------------------------------
    # DDoS COUNT
    # --------------------------------------------------------

    if (
        "how many ddos" in q
        or "number of ddos" in q
        or "ddos attacks" in q
    ):

        attack = find_attack(
            analysis,
            ["ddos"],
        )

        if attack:

            return (
                f"The latest SentinelAI analysis detected "
                f"{format_number(attack['count'])} "
                "DDoS-related network flows.\n\n"
                "DDoS attacks attempt to overwhelm a system "
                "or service with excessive traffic. Defensive "
                "actions include traffic filtering, rate "
                "limiting, monitoring connection rates, and "
                "appropriate DDoS mitigation controls."
            )

        return (
            "No DDoS activity was detected in the latest "
            "SentinelAI analysis."
        )

    # --------------------------------------------------------
    # SENTINELAI INFORMATION
    # --------------------------------------------------------

    if (
        "what is sentinelai" in q
        or "about sentinelai" in q
        or q == "sentinelai"
    ):

        return (
            "SentinelAI is an intelligent network threat "
            "detection and cybersecurity assistant. It "
            "analyzes network-flow CSV data, classifies "
            "traffic using a machine-learning engine, "
            "assigns severity levels, provides security "
            "recommendations, and allows analysts to "
            "investigate detected threats."
        )

    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    return general_response(
        analysis
    )


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "name": "SentinelAI AI Assistant",
        "version": "2.1.0",
        "status": "running",
        "message": (
            "SentinelAI AI Assistant backend "
            "is running successfully."
        ),
    }


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/api/assistant/health")
def health():

    return {
        "status": "healthy",
        "service": "SentinelAI AI Assistant",
        "ai_engine": "analysis-aware",
        "analysis_file": str(
            RESULTS_FILE
        ),
        "analysis_available": RESULTS_FILE.exists(),
        "ml_evaluation_available": (
            ML_METRICS_FILE.exists()
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# ============================================================
# CHAT ENDPOINT
# ============================================================

@app.post("/api/assistant/chat")
def chat(
    request: AssistantRequest
):

    response = generate_response(
        request.question
    )

    return {
        "success": True,
        "question": request.question,
        "response": response,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# ============================================================
# ASSISTANT INFO
# ============================================================

@app.get("/api/assistant/info")
def assistant_info():

    return {
        "name": "SentinelAI AI Assistant",
        "version": "2.1.0",
        "capabilities": [
            "Analysis-aware cybersecurity questions",
            "Dataset risk assessment",
            "DDoS analysis",
            "DoS analysis",
            "PortScan analysis",
            "XSS analysis",
            "Brute-force analysis",
            "SSH security analysis",
            "Bot activity analysis",
            "Severity analysis",
            "SOC analyst assessment",
            "Investigation prioritization",
            "Security recommendations",
            "Attack distribution analysis",
            "ML model performance analysis",
            "Class-level ML evaluation",
            "Model limitation analysis",
            "Confusion matrix analysis",
        ],
    }

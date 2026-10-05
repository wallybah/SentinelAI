from datetime import datetime, timezone
from pathlib import Path
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from ai.analyze import SentinelAIAnalyzer


# ============================================================
# SENTINELAI FASTAPI BACKEND
# ============================================================

app = FastAPI(
    title="SentinelAI API",
    description=(
        "AI-powered network threat detection "
        "and cybersecurity assistant."
    ),
    version="2.0.0",
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

RESULTS_DIR = BASE_DIR / "results"

LATEST_ANALYSIS_FILE = (
    RESULTS_DIR / "latest_analysis.json"
)

REPORTS_DIR = (
    RESULTS_DIR / "reports"
)

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# AI ANALYZER
# ============================================================

analyzer = SentinelAIAnalyzer()


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "name": "SentinelAI API",
        "version": "2.0.0",
        "status": "running",
        "message": (
            "SentinelAI backend is running successfully."
        ),
    }


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/api/latest-analysis")
def latest_analysis():
    """
    Return the latest SentinelAI analysis.

    Used by the separate AI Assistant service when
    the services are deployed independently.
    """

    analysis = load_latest_analysis()

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="No latest analysis is available.",
        )

    return analysis

@app.get("/api/health")
def health_check():

    return {
        "status": "healthy",
        "service": "SentinelAI API",
        "ai_engine": "available",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }

# ============================================================
# ML MODEL PERFORMANCE ENDPOINT
# ============================================================

@app.get("/api/model-performance")
def model_performance():

    import csv
    import json

    metrics_file = (
        RESULTS_DIR / "model_metrics.json"
    )

    classification_file = (
        RESULTS_DIR / "classification_report.csv"
    )

    confusion_file = (
        RESULTS_DIR / "confusion_matrix.csv"
    )

    # --------------------------------------------------------
    # Validate evaluation files
    # --------------------------------------------------------

    missing_files = [

        str(path.name)

        for path in [
            metrics_file,
            classification_file,
            confusion_file,
        ]

        if not path.exists()

    ]

    if missing_files:

        raise HTTPException(
            status_code=404,
            detail=(
                "ML evaluation files are missing: "
                + ", ".join(missing_files)
            ),
        )

    try:

        # ----------------------------------------------------
        # Load overall model metrics
        # ----------------------------------------------------

        with open(
            metrics_file,
            "r",
            encoding="utf-8",
        ) as file:

            metrics = json.load(file)


        # ----------------------------------------------------
        # Load classification report
        # ----------------------------------------------------

        class_performance = []

        with open(
            classification_file,
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                class_name = (
                    row.get("")
                    or row.get("class")
                    or row.get("label")
                )

                if not class_name:
                    continue

                class_name = str(
                    class_name
                ).strip()

                # Skip aggregate rows.
                if class_name.lower() in {
                    "accuracy",
                    "macro avg",
                    "weighted avg",
                }:

                    continue

                try:

                    class_performance.append({

                        "name":
                            class_name,

                        "precision":
                            float(
                                row.get(
                                    "precision",
                                    0
                                )
                            ) * 100,

                        "recall":
                            float(
                                row.get(
                                    "recall",
                                    0
                                )
                            ) * 100,

                        "f1":
                            float(
                                row.get(
                                    "f1-score",
                                    0
                                )
                            ) * 100,

                        "support":
                            int(
                                float(
                                    row.get(
                                        "support",
                                        0
                                    )
                                )
                            ),

                    })

                except (
                    TypeError,
                    ValueError,
                ):

                    continue


        # ----------------------------------------------------
        # Load confusion matrix
        # ----------------------------------------------------

        confusion_labels = []

        confusion_matrix = []

        with open(
            confusion_file,
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:

            reader = csv.reader(file)

            rows = list(reader)


        if rows:

            # First column is empty; remaining columns
            # contain predicted class names.
            confusion_labels = [
                str(label).strip()
                for label in rows[0][1:]
            ]


            for row in rows[1:]:

                if len(row) < 2:
                    continue

                try:

                    confusion_matrix.append([
                        int(float(value or 0))
                        for value in row[1:]
                    ])

                except ValueError:

                    continue


        # ----------------------------------------------------
        # Return complete ML evaluation
        # ----------------------------------------------------

        return {

            "success": True,

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

            "accuracy":
                float(
                    metrics.get(
                        "accuracy",
                        0,
                    )
                ) * 100,

            "macro_precision":
                float(
                    metrics.get(
                        "macro_precision",
                        0,
                    )
                ) * 100,

            "macro_recall":
                float(
                    metrics.get(
                        "macro_recall",
                        0,
                    )
                ) * 100,

            "macro_f1":
                float(
                    metrics.get(
                        "macro_f1",
                        0,
                    )
                ) * 100,

            "weighted_precision":
                float(
                    metrics.get(
                        "weighted_precision",
                        0,
                    )
                ) * 100,

            "weighted_recall":
                float(
                    metrics.get(
                        "weighted_recall",
                        0,
                    )
                ) * 100,

            "weighted_f1":
                float(
                    metrics.get(
                        "weighted_f1",
                        0,
                    )
                ) * 100,

            "class_performance":
                class_performance,

            "confusion_labels":
                confusion_labels,

            "confusion_matrix":
                confusion_matrix,

        }

    except Exception as error:

        print(
            "Model performance loading error:",
            repr(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "SentinelAI could not load "
                "the ML evaluation results."
            ),
        )

# ============================================================
# CSV ANALYSIS ENDPOINT
# ============================================================

@app.post("/api/analyze")
async def analyze_csv(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename was provided.",
        )

    filename = Path(
        file.filename
    ).name

    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    if not filename.lower().endswith(".csv"):

        raise HTTPException(
            status_code=400,
            detail="Only CSV files are supported.",
        )

    temporary_path = None

    try:

        # ----------------------------------------------------
        # Create temporary CSV
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".csv",
        ) as temporary_file:

            temporary_path = Path(
                temporary_file.name
            )

            while True:

                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                temporary_file.write(
                    chunk
                )

        # ----------------------------------------------------
        # Run SentinelAI analysis
        # ----------------------------------------------------

        analysis = analyzer.analyze_csv(
            temporary_path
        )

        # ----------------------------------------------------
        # Prepare response
        # ----------------------------------------------------

        response = {

            "success": True,

            "file_name":
                analysis["file_name"],

            "total_records":
                analysis["total_records"],

            "benign_records":
                analysis["benign_records"],

            "malicious_records":
                analysis["malicious_records"],

            "malicious_percentage":
                analysis["malicious_percentage"],

            "highest_severity":
                analysis["highest_severity"],

            "attack_distribution":
                analysis[
                    "attack_distribution"
                ],

            "severity_distribution":
                analysis[
                    "severity_distribution"
                ],

            "recommendations":
                analysis[
                    "recommendations"
                ],

            "analyzed_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),
        }

        return response

    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        print(
            "Analysis error:",
            repr(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "SentinelAI could not analyze "
                "the uploaded CSV."
            ),
        )

    finally:

        if temporary_path is not None:

            try:

                temporary_path.unlink(
                    missing_ok=True
                )

            except Exception:
                pass

        await file.close()


# ============================================================
# REPORT HELPERS
# ============================================================

def clean_attack_name(name):
    """Fix common CIC-IDS2017 encoding problems."""

    if not name:
        return ""

    value = str(name)

    replacements = {
        "ÃƒÂ¯Ã‚Â¿Ã‚Â½": "Ã¢â‚¬â€œ",
        "ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¿Ãƒâ€šÃ‚Â½": "Ã¢â‚¬â€œ",
        "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“": "Ã¢â‚¬â€œ",
        "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â": "Ã¢â‚¬â€",
        "ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ": "Ã¢â‚¬â€œ",
        "ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬": "Ã¢â‚¬â€œ",
    }

    for bad, good in replacements.items():
        value = value.replace(
            bad,
            good,
        )

    return value


def format_number(value):

    try:
        return f"{int(value):,}"

    except (
        TypeError,
        ValueError,
    ):
        return "0"


def format_percentage(value):

    try:
        return f"{float(value):.2f}%"

    except (
        TypeError,
        ValueError,
    ):
        return "0.00%"


# ============================================================
# PDF HEADER / FOOTER
# ============================================================

def add_page_header_footer(
    canvas,
    document,
):

    canvas.saveState()

    width, height = A4

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    canvas.setFont(
        "Helvetica-Bold",
        9,
    )

    canvas.drawString(
        20 * mm,
        height - 12 * mm,
        "SentinelAI",
    )

    canvas.setFont(
        "Helvetica",
        8,
    )

    canvas.drawRightString(
        width - 20 * mm,
        height - 12 * mm,
        "SOC Security Analysis Report",
    )

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    canvas.setFont(
        "Helvetica",
        8,
    )

    canvas.drawString(
        20 * mm,
        10 * mm,
        "Generated by SentinelAI",
    )

    canvas.drawRightString(
        width - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


# ============================================================
# LOAD LATEST ANALYSIS
# ============================================================

def load_latest_analysis():

    if not LATEST_ANALYSIS_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail=(
                "No SentinelAI analysis is available. "
                "Analyze a CSV file first."
            ),
        )

    try:

        import json

        with open(
            LATEST_ANALYSIS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            "Report analysis loading error:",
            repr(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "SentinelAI could not read "
                "the latest analysis."
            ),
        )


# ============================================================
# GENERATE SOC PDF
# ============================================================

def generate_soc_pdf(
    analysis,
    output_path,
):

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        alignment=TA_CENTER,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title="SentinelAI SOC Security Analysis Report",
        author="SentinelAI",
    )

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Spacer(
            1,
            15 * mm,
        )
    )

    story.append(
        Paragraph(
            "SentinelAI",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "SOC Security Analysis Report",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "Intelligent Network Threat Detection "
            "and Cybersecurity Analysis",
            subtitle_style,
        )
    )

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    # ========================================================
    # REPORT INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "Report Information",
            heading_style,
        )
    )

    analyzed_at = analysis.get(
        "analyzed_at",
        datetime.now(
            timezone.utc
        ).isoformat(),
    )

    report_info = [

        [
            "Dataset",
            str(
                analysis.get(
                    "file_name",
                    "Unknown",
                )
            ),
        ],

        [
            "Analysis Time",
            str(analyzed_at),
        ],

        [
            "Highest Severity",
            str(
                analysis.get(
                    "highest_severity",
                    "UNKNOWN",
                )
            ),
        ],

    ]

    info_table = Table(
        report_info,
        colWidths=[
            45 * mm,
            115 * mm,
        ],
    )

    info_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        info_table
    )

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style,
        )
    )

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

    malicious_percentage = analysis.get(
        "malicious_percentage",
        0,
    )

    highest_severity = analysis.get(
        "highest_severity",
        "UNKNOWN",
    )

    story.append(
        Paragraph(
            (
                "SentinelAI analyzed "
                f"<b>{format_number(total)}</b> "
                "network-flow records. "
                f"<b>{format_number(malicious)}</b> "
                "flows were classified as malicious, "
                f"representing "
                f"<b>{format_percentage(malicious_percentage)}</b> "
                "of the analyzed traffic. "
                f"<b>{format_number(benign)}</b> "
                "flows were classified as benign. "
                f"The highest detected severity was "
                f"<b>{highest_severity}</b>."
            ),
            body_style,
        )
    )

    # ========================================================
    # KEY METRICS
    # ========================================================

    story.append(
        Paragraph(
            "2. Key Security Metrics",
            heading_style,
        )
    )

    metrics = [

        [
            "Metric",
            "Value",
        ],

        [
            "Total Network Flows",
            format_number(total),
        ],

        [
            "Benign Flows",
            format_number(benign),
        ],

        [
            "Malicious Flows",
            format_number(malicious),
        ],

        [
            "Malicious Rate",
            format_percentage(
                malicious_percentage
            ),
        ],

        [
            "Highest Severity",
            str(highest_severity),
        ],

    ]

    metrics_table = Table(
        metrics,
        colWidths=[
            90 * mm,
            70 * mm,
        ],
        repeatRows=1,
    )

    metrics_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.black,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.whitesmoke,
                    ],
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        metrics_table
    )

    # ========================================================
    # ATTACK DISTRIBUTION
    # ========================================================

    story.append(
        Paragraph(
            "3. Detected Attack Distribution",
            heading_style,
        )
    )

    attack_distribution = analysis.get(
        "attack_distribution",
        {},
    )

    attack_rows = [

        [
            "Attack / Traffic Type",
            "Flows",
            "Percentage",
        ]

    ]

    for attack_name, count in sorted(
        attack_distribution.items(),
        key=lambda item: int(
            item[1]
        ),
        reverse=True,
    ):

        numeric_count = int(
            count
        )

        percentage = (
            numeric_count /
            int(total) *
            100
            if int(total) > 0
            else 0
        )

        attack_rows.append(
            [
                clean_attack_name(
                    attack_name
                ),
                format_number(
                    numeric_count
                ),
                format_percentage(
                    percentage
                ),
            ]
        )

    attack_table = Table(
        attack_rows,
        colWidths=[
            85 * mm,
            35 * mm,
            40 * mm,
        ],
        repeatRows=1,
    )

    attack_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.black,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8.5,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.whitesmoke,
                    ],
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (-1, -1),
                    "RIGHT",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    story.append(
        attack_table
    )

    # ========================================================
    # SEVERITY DISTRIBUTION
    # ========================================================

    story.append(
        Paragraph(
            "4. Severity Distribution",
            heading_style,
        )
    )

    severity_distribution = analysis.get(
        "severity_distribution",
        {},
    )

    severity_rows = [

        [
            "Severity",
            "Flows",
        ]

    ]

    for severity, count in sorted(
        severity_distribution.items()
    ):

        severity_rows.append(
            [
                str(severity),
                format_number(
                    count
                ),
            ]
        )

    severity_table = Table(
        severity_rows,
        colWidths=[
            100 * mm,
            60 * mm,
        ],
        repeatRows=1,
    )

    severity_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.black,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.whitesmoke,
                    ],
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (-1, -1),
                    "RIGHT",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        severity_table
    )

    # ========================================================
    # PRIMARY THREAT
    # ========================================================

    story.append(
        Paragraph(
            "5. Primary Threat Assessment",
            heading_style,
        )
    )

    malicious_attacks = []

    for attack_name, count in attack_distribution.items():

        cleaned_name = clean_attack_name(
            attack_name
        )

        if cleaned_name.upper() == "BENIGN":
            continue

        malicious_attacks.append(
            (
                cleaned_name,
                int(count),
            )
        )

    malicious_attacks.sort(
        key=lambda item: item[1],
        reverse=True,
    )

    if malicious_attacks:

        primary_name, primary_count = (
            malicious_attacks[0]
        )

        primary_percentage = (
            primary_count /
            int(total) *
            100
            if int(total) > 0
            else 0
        )

        story.append(
            Paragraph(
                (
                    f"The dominant malicious activity was "
                    f"<b>{primary_name}</b>, with "
                    f"<b>{format_number(primary_count)}</b> "
                    f"flows. This represents "
                    f"<b>{format_percentage(primary_percentage)}</b> "
                    "of all analyzed flows."
                ),
                body_style,
            )
        )

    else:

        story.append(
            Paragraph(
                "No malicious attack category was identified "
                "in the latest analysis.",
                body_style,
            )
        )

    # ========================================================
    # SOC INVESTIGATION
    # ========================================================

    story.append(
        Paragraph(
            "6. SOC Investigation Guidance",
            heading_style,
        )
    )

    investigation_points = [

        "Identify the source and destination systems associated with the dominant malicious activity.",

        "Review firewall, IDS/IPS, server, and authentication logs around the detected activity.",

        "Check affected hosts for unusual processes, connections, or other suspicious behavior.",

        "Verify whether critical services experienced availability or performance problems.",

        "Investigate whether the activity is isolated or part of a repeated or escalating pattern.",

        "Apply the appropriate mitigation controls and continue monitoring for recurrence.",

    ]

    for index, point in enumerate(
        investigation_points,
        start=1,
    ):

        story.append(
            Paragraph(
                f"{index}. {point}",
                body_style,
            )
        )

    # ========================================================
    # SECURITY RECOMMENDATIONS
    # ========================================================

    story.append(
        Paragraph(
            "7. Security Recommendations",
            heading_style,
        )
    )

    recommendations = analysis.get(
        "recommendations",
        {},
    )

    if recommendations:

        for attack_name, items in recommendations.items():

            cleaned_name = clean_attack_name(
                attack_name
            )

            if not items:
                continue

            story.append(
                Paragraph(
                    f"<b>{cleaned_name}</b>",
                    body_style,
                )
            )

            for item in items:

                story.append(
                    Paragraph(
                        f"Ã¢â‚¬Â¢ {item}",
                        small_style,
                    )
                )

            story.append(
                Spacer(
                    1,
                    3 * mm,
                )
            )

    else:

        story.append(
            Paragraph(
                "No specific security recommendations "
                "were provided by the analysis.",
                body_style,
            )
        )

    # ========================================================
    # FINAL ASSESSMENT
    # ========================================================

    story.append(
        Paragraph(
            "8. Final SOC Assessment",
            heading_style,
        )
    )

    if malicious > 0:

        final_assessment = (
            "The latest SentinelAI analysis identified "
            "malicious network activity and should be "
            "treated as requiring security investigation. "
            f"The malicious traffic rate was "
            f"{format_percentage(malicious_percentage)}, "
            f"with the highest severity classified as "
            f"{highest_severity}. The SOC should prioritize "
            "the dominant malicious activity, validate the "
            "affected systems and services, review relevant "
            "security logs, and apply appropriate mitigation "
            "controls."
        )

    else:

        final_assessment = (
            "The latest SentinelAI analysis did not identify "
            "malicious traffic. Normal security monitoring "
            "should continue, and the organization's existing "
            "security controls should remain maintained."
        )

    story.append(
        Paragraph(
            final_assessment,
            body_style,
        )
    )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Note:</b> This report is generated from "
                "the SentinelAI network-flow analysis results. "
                "Detection results should be validated against "
                "additional security telemetry and operational "
                "context before making incident-response decisions."
            ),
            small_style,
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story,
        onFirstPage=add_page_header_footer,
        onLaterPages=add_page_header_footer,
    )


# ============================================================
# GENERATE SOC REPORT ENDPOINT
# ============================================================

@app.post("/api/report")
async def generate_report():

    analysis = load_latest_analysis()

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    report_filename = (
        f"SentinelAI_SOC_Report_{timestamp}.pdf"
    )

    report_path = (
        REPORTS_DIR /
        report_filename
    )

    try:

        generate_soc_pdf(
            analysis,
            report_path,
        )

    except Exception as error:

        print(
            "PDF generation error:",
            repr(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "SentinelAI could not generate "
                "the SOC report."
            ),
        )

    if not report_path.exists():

        raise HTTPException(
            status_code=500,
            detail=(
                "The SOC report was not created."
            ),
        )

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=report_filename,
    )
// ============================================================
// SENTINELAI FRONTEND
// ============================================================

const API_BASE = window.SENTINELAI_API_BASE || "http://127.0.0.1:8000";

const ASSISTANT_API = window.SENTINELAI_ASSISTANT_API || "http://127.0.0.1:8001";


// ============================================================
// GLOBAL STATE
// ============================================================

let currentAnalysis = null;

let selectedFile = null;


// ============================================================
// HELPER
// ============================================================

function $(id) {
    return document.getElementById(id);
}


// ============================================================
// NUMBER FORMATTING
// ============================================================

function formatNumber(value) {

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "0";
    }

    return number.toLocaleString();
}


// ============================================================
// PERCENTAGE FORMATTING
// ============================================================

function formatPercentage(value) {

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "0%";
    }

    return `${number.toFixed(2)}%`;
}


// ============================================================
// CALCULATE PERCENTAGE
// ============================================================

function calculatePercentage(
    count,
    total
) {

    const numericCount = Number(count);

    const numericTotal = Number(total);

    if (
        !Number.isFinite(numericCount) ||
        !Number.isFinite(numericTotal) ||
        numericTotal <= 0
    ) {

        return 0;
    }

    return (
        numericCount /
        numericTotal
    ) * 100;
}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// ============================================================
// ASSISTANT MESSAGE FORMATTING
// ============================================================

function formatAssistantMessage(message) {

    if (
        message === null ||
        message === undefined
    ) {

        return "";
    }

    const text =
        String(message);

    return escapeHtml(text)
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n")
        .replace(/\n/g, "<br>");
}


// ============================================================
// CLEAN ATTACK NAME
// ============================================================

function cleanAttackName(name) {

    if (!name) {
        return "";
    }

    return String(name)
        .replaceAll("ï¿½", "â€“")
        .replaceAll("Ã¯Â¿Â½", "â€“")
        .replaceAll("Ã¢â‚¬â€œ", "â€“")
        .replaceAll("Ã¢â‚¬â€", "â€”")
        .replaceAll("Ã¢â€ â€™", "â†’")
        .trim();
}


// ============================================================
// PAGE NAVIGATION
// ============================================================

function showPage(page) {

    document
        .querySelectorAll(".page")
        .forEach((element) => {

            element.classList.remove(
                "active"
            );

        });


    document
        .querySelectorAll(".nav-item")
        .forEach((element) => {

            element.classList.remove(
                "active"
            );

        });


    const pageElement =
        $(`${page}-page`);


    if (pageElement) {

        pageElement.classList.add(
            "active"
        );

    }


    document
        .querySelectorAll(
            `[data-page="${page}"]`
        )
        .forEach((element) => {

            if (
                element.classList.contains(
                    "nav-item"
                )
            ) {

                element.classList.add(
                    "active"
                );

            }

        });


    const titles = {

        dashboard:
            "Network Security Dashboard",

        upload:
            "Analyze Network Traffic",

        results:
            "Security Results",

        assistant:
            "SentinelAI Assistant",

        about:
            "About SentinelAI"

    };


    const pageTitle =
        $("page-title");


    if (pageTitle) {

        pageTitle.textContent =
            titles[page] ||
            "SentinelAI";

    }


    window.scrollTo({

        top: 0,

        behavior: "smooth"

    });
}


// ============================================================
// MAIN API HEALTH CHECK
// ============================================================

async function checkApiHealth() {

    const apiStatusText =
        $("api-status-text");

    const sidebarStatus =
        $("sidebar-status");

    const apiStatus =
        $("api-status");


    if (apiStatusText) {

        apiStatusText.textContent =
            "Checking API...";

    }


    if (sidebarStatus) {

        sidebarStatus.textContent =
            "Checking API...";

    }


    try {

        const response =
            await fetch(
                `${API_BASE}/api/health`
            );


        if (!response.ok) {

            throw new Error(
                "API health check failed."
            );

        }


        if (apiStatusText) {

            apiStatusText.textContent =
                "API Connected";

        }


        if (sidebarStatus) {

            sidebarStatus.textContent =
                "API Connected";

        }


        if (apiStatus) {

            apiStatus.classList.remove(
                "offline"
            );

        }


        console.log(
            "SentinelAI main API connected."
        );


        return true;

    }

    catch (error) {

        if (apiStatusText) {

            apiStatusText.textContent =
                "API Offline";

        }


        if (sidebarStatus) {

            sidebarStatus.textContent =
                "API Offline";

        }


        if (apiStatus) {

            apiStatus.classList.add(
                "offline"
            );

        }


        console.error(
            "Main API error:",
            error
        );


        return false;
    }
}


// ============================================================
// UPDATE DASHBOARD
// ============================================================

function updateDashboard(data) {

    if (!data) {
        return;
    }


    const totalFlows =
        $("total-flows");

    const maliciousFlows =
        $("malicious-flows");

    const benignFlows =
        $("benign-flows");

    const attackRate =
        $("attack-rate");


    if (totalFlows) {

        totalFlows.textContent =
            formatNumber(
                data.total_records
            );

    }


    if (maliciousFlows) {

        maliciousFlows.textContent =
            formatNumber(
                data.malicious_records
            );

    }


    if (benignFlows) {

        benignFlows.textContent =
            formatNumber(
                data.benign_records
            );

    }


    if (attackRate) {

        attackRate.textContent =
            formatPercentage(
                data.malicious_percentage
            );

    }


    const analysisBadge =
        $("analysis-badge");


    if (analysisBadge) {

        analysisBadge.textContent =
            data.file_name
                ? `Analyzed: ${data.file_name}`
                : "Analysis Complete";

    }


    updateAttackDistribution(
        data.attack_distribution,
        data.total_records
    );


    updateSeverityDistribution(
        data.severity_distribution
    );
}


// ============================================================
// DASHBOARD ATTACK DISTRIBUTION
// ============================================================

function updateAttackDistribution(
    distribution,
    totalRecords
) {

    const container =
        $("attack-list");


    if (!container) {
        return;
    }


    if (
        !distribution ||
        Object.keys(distribution).length === 0
    ) {

        container.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">
                    â—‹
                </div>

                <h4>
                    No analysis available
                </h4>

                <p>
                    Upload a network-flow CSV
                    to see detected attacks.
                </p>

            </div>

        `;

        return;
    }


    const entries =
        Object.entries(
            distribution
        )
        .sort(
            (a, b) =>
                Number(b[1]) -
                Number(a[1])
        );


    const total =
        Number(totalRecords) > 0
            ? Number(totalRecords)
            : entries.reduce(
                (sum, [, count]) =>
                    sum +
                    Number(count || 0),
                0
            );


    container.innerHTML =
        entries
            .map(
                ([attack, count]) => {

                    const numericCount =
                        Number(count);


                    const percentage =
                        calculatePercentage(
                            numericCount,
                            total
                        );


                    const displayName =
                        cleanAttackName(
                            attack
                        );


                    return `

                        <div
                            class="attack-row"
                            data-attack="${escapeHtml(
                                displayName
                            )}"
                            style="
                                cursor: pointer;
                            "
                            title="Click to investigate ${escapeHtml(
                                displayName
                            )}"
                        >

                            <div class="attack-row-header">

                                <span class="attack-name">

                                    ${escapeHtml(
                                        displayName
                                    )}

                                </span>


                                <span class="attack-value">

                                    ${formatNumber(
                                        numericCount
                                    )}

                                    <span
                                        style="
                                            color: var(--text-secondary);
                                            font-weight: 400;
                                            margin-left: 8px;
                                        "
                                    >

                                        ${formatPercentage(
                                            percentage
                                        )}

                                    </span>

                                </span>

                            </div>


                            <div class="attack-bar">

                                <span
                                    style="
                                        width:
                                        ${percentage}%;
                                    "
                                ></span>

                            </div>

                        </div>

                    `;

                }
            )
            .join("");


    setupDashboardAttackClicks(
        total
    );
}


// ============================================================
// DASHBOARD ATTACK CLICK SETUP
// ============================================================

function setupDashboardAttackClicks(
    totalRecords
) {

    const container =
        $("attack-list");


    if (!container) {
        return;
    }


    container
        .querySelectorAll(
            ".attack-row[data-attack]"
        )
        .forEach(
            (row) => {

                row.addEventListener(
                    "click",
                    () => {

                        const attack =
                            row.dataset.attack;


                        showAttackInvestigation(
                            attack,
                            currentAnalysis,
                            totalRecords,
                            "dashboard"
                        );

                    }
                );

            }
        );
}


// ============================================================
// DASHBOARD SEVERITY DISTRIBUTION
// ============================================================

function updateSeverityDistribution(
    distribution
) {

    if (!distribution) {
        distribution = {};
    }


    const severities = [

        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"

    ];


    const total =
        Object.values(
            distribution
        )
        .reduce(
            (sum, value) =>
                sum +
                Number(value || 0),
            0
        );


    severities.forEach(
        (severity) => {

            const lower =
                severity.toLowerCase();


            const count =
                Number(
                    distribution[
                        severity
                    ] || 0
                );


            const countElement =
                $(`${lower}-count`);


            const barElement =
                $(`${lower}-bar`);


            if (countElement) {

                countElement.textContent =
                    formatNumber(
                        count
                    );

            }


            if (barElement) {

                const percentage =
                    total > 0
                        ? (
                            count /
                            total
                        ) * 100
                        : 0;


                barElement.style.width =
                    `${percentage}%`;

            }

        }
    );
}


// ============================================================
// UPDATE RESULTS PAGE
// ============================================================

function updateResultsPage(data) {

    if (!data) {
        return;
    }


    const emptyState =
        $("results-empty");

    const resultsContent =
        $("results-content");


    if (emptyState) {

        emptyState.classList.add(
            "hidden"
        );

    }


    if (resultsContent) {

        resultsContent.classList.remove(
            "hidden"
        );

    }


    const fileName =
        $("result-file-name");


    if (fileName) {

        fileName.textContent =
            data.file_name ||
            "Network Dataset";

    }


    const severity =
        $("result-severity");


    if (severity) {

        severity.textContent =
            data.highest_severity ||
            "UNKNOWN";

    }


    const total =
        $("result-total");


    if (total) {

        total.textContent =
            formatNumber(
                data.total_records
            );

    }


    const malicious =
        $("result-malicious");


    if (malicious) {

        malicious.textContent =
            formatNumber(
                data.malicious_records
            );

    }


    const benign =
        $("result-benign");


    if (benign) {

        benign.textContent =
            formatNumber(
                data.benign_records
            );

    }


    const rate =
        $("result-attack-rate");


    if (rate) {

        rate.textContent =
            formatPercentage(
                data.malicious_percentage
            );

    }


    updateResultsAttackDistribution(
        data.attack_distribution,
        data.total_records
    );


    updateResultsSeverityDistribution(
        data.severity_distribution
    );


    updateRecommendations(
        data.recommendations
    );
}


// ============================================================
// RESULTS ATTACK DISTRIBUTION
// ============================================================

function updateResultsAttackDistribution(
    distribution,
    totalRecords
) {

    const container =
        $("result-attack-list");


    if (!container) {
        return;
    }


    if (
        !distribution ||
        Object.keys(distribution).length === 0
    ) {

        container.innerHTML = `

            <div class="empty-state">

                No attack data available.

            </div>

        `;

        return;
    }


    const entries =
        Object.entries(
            distribution
        )
        .sort(
            (a, b) =>
                Number(b[1]) -
                Number(a[1])
        );


    const total =
        Number(totalRecords) > 0
            ? Number(totalRecords)
            : entries.reduce(
                (sum, [, count]) =>
                    sum +
                    Number(count || 0),
                0
            );


    container.innerHTML =
        entries
            .map(
                ([attack, count]) => {

                    const numericCount =
                        Number(count);


                    const percentage =
                        calculatePercentage(
                            numericCount,
                            total
                        );


                    const displayName =
                        cleanAttackName(
                            attack
                        );


                    return `

                        <div
                            class="attack-row investigation-attack-row"
                            data-attack="${escapeHtml(
                                displayName
                            )}"
                            style="
                                cursor: pointer;
                            "
                            title="Click to investigate ${escapeHtml(
                                displayName
                            )}"
                        >

                            <div class="attack-row-header">

                                <span class="attack-name">

                                    ${escapeHtml(
                                        displayName
                                    )}

                                </span>


                                <span class="attack-value">

                                    ${formatNumber(
                                        numericCount
                                    )}

                                    <span
                                        style="
                                            color: var(--text-secondary);
                                            font-weight: 400;
                                            margin-left: 8px;
                                        "
                                    >

                                        ${formatPercentage(
                                            percentage
                                        )}

                                    </span>

                                </span>

                            </div>


                            <div class="attack-bar">

                                <span
                                    style="
                                        width:
                                        ${percentage}%;
                                    "
                                ></span>

                            </div>

                        </div>

                    `;

                }
            )
            .join("");


    setupResultsAttackClicks(
        total
    );
}


// ============================================================
// RESULTS ATTACK CLICK SETUP
// ============================================================

function setupResultsAttackClicks(
    totalRecords
) {

    const container =
        $("result-attack-list");


    if (!container) {
        return;
    }


    container
        .querySelectorAll(
            ".investigation-attack-row"
        )
        .forEach(
            (row) => {

                row.addEventListener(
                    "click",
                    () => {

                        const attack =
                            row.dataset.attack;


                        showAttackInvestigation(
                            attack,
                            currentAnalysis,
                            totalRecords,
                            "results"
                        );

                    }
                );

            }
        );
}


// ============================================================
// FIND ATTACK RECOMMENDATIONS
// ============================================================

function findAttackRecommendations(
    data,
    attackName
) {

    if (!data) {
        return [];
    }


    const recommendations =
        data.recommendations;


    if (
        !recommendations ||
        typeof recommendations !== "object"
    ) {

        return [];
    }


    const target =
        cleanAttackName(
            attackName
        )
        .toLowerCase();


    for (
        const [
            key,
            items
        ]
        of Object.entries(
            recommendations
        )
    ) {

        const cleanedKey =
            cleanAttackName(
                key
            )
            .toLowerCase();


        if (
            cleanedKey === target ||
            cleanedKey.includes(target) ||
            target.includes(cleanedKey)
        ) {

            if (
                Array.isArray(items)
            ) {

                return items;

            }

        }

    }


    return [];
}


// ============================================================
// ATTACK INVESTIGATION PANEL
// ============================================================

function showAttackInvestigation(
    attackName,
    data,
    totalRecords,
    source
) {

    if (!data) {

        console.warn(
            "No analysis data available."
        );

        return;
    }


    const distribution =
        data.attack_distribution || {};


    let actualAttackName =
        attackName;


    let attackCount =
        0;


    for (
        const [
            key,
            value
        ]
        of Object.entries(
            distribution
        )
    ) {

        const cleanedKey =
            cleanAttackName(
                key
            );


        if (
            cleanedKey.toLowerCase() ===
            String(attackName).toLowerCase()
        ) {

            actualAttackName =
                cleanedKey;

            attackCount =
                Number(value || 0);

            break;

        }

    }


    if (
        attackCount === 0 &&
        distribution[attackName] !== undefined
    ) {

        attackCount =
            Number(
                distribution[
                    attackName
                ] || 0
            );

    }


    const total =
        Number(totalRecords) > 0
            ? Number(totalRecords)
            : Number(
                data.total_records || 0
            );


    const percentage =
        calculatePercentage(
            attackCount,
            total
        );


    const isBenign =
        actualAttackName
            .toUpperCase() ===
        "BENIGN";


    const classification =
        isBenign
            ? "BENIGN"
            : "MALICIOUS";


    const recommendations =
        findAttackRecommendations(
            data,
            actualAttackName
        );


    const highestSeverity =
        String(
            data.highest_severity ||
            "UNKNOWN"
        )
        .toUpperCase();


    const investigationSteps =
        getInvestigationSteps(
            actualAttackName,
            isBenign
        );


    const panelId =
        "attack-investigation-panel";


    let panel =
        $(panelId);


    if (!panel) {

        panel =
            document.createElement(
                "div"
            );

        panel.id =
            panelId;

    }


    panel.style.cssText = `

        margin-top: 20px;
        padding: 24px;
        border-radius: 14px;
        border: 1px solid var(--border-color, #2d3748);
        background: var(--card-background, #111827);
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.20);
        position: relative;

    `;


    const recommendationHtml =
        recommendations.length > 0

            ? recommendations
                .map(
                    (item) => `
                        <li
                            style="
                                margin-bottom: 8px;
                            "
                        >
                            ${escapeHtml(item)}
                        </li>
                    `
                )
                .join("")

            : `
                <li>
                    No specific recommendations
                    are available for this attack.
                </li>
            `;


    const investigationHtml =
        investigationSteps
            .map(
                (item) => `
                    <li
                        style="
                            margin-bottom: 8px;
                        "
                    >
                        ${escapeHtml(item)}
                    </li>
                `
            )
            .join("");


    panel.innerHTML = `

        <div
            style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 16px;
                margin-bottom: 20px;
            "
        >

            <div>

                <div
                    style="
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                        color: var(--text-secondary);
                        margin-bottom: 6px;
                    "
                >
                    Threat Investigation
                </div>

                <h3
                    style="
                        margin: 0;
                        font-size: 24px;
                    "
                >
                    ${escapeHtml(
                        actualAttackName
                    )}
                </h3>

            </div>


            <button
                type="button"
                id="close-attack-investigation"
                style="
                    border: none;
                    border-radius: 8px;
                    padding: 8px 12px;
                    cursor: pointer;
                    background: transparent;
                    color: var(--text-secondary);
                    font-size: 20px;
                "
                title="Close investigation"
            >
                Ã—
            </button>

        </div>


        <div
            style="
                display: grid;
                grid-template-columns:
                    repeat(
                        auto-fit,
                        minmax(160px, 1fr)
                    );
                gap: 12px;
                margin-bottom: 24px;
            "
        >

            <div
                style="
                    padding: 16px;
                    border-radius: 10px;
                    background: rgba(255,255,255,0.04);
                "
            >

                <div
                    style="
                        color: var(--text-secondary);
                        font-size: 12px;
                        margin-bottom: 6px;
                    "
                >
                    Detected Flows
                </div>

                <strong
                    style="
                        font-size: 22px;
                    "
                >
                    ${formatNumber(
                        attackCount
                    )}
                </strong>

            </div>


            <div
                style="
                    padding: 16px;
                    border-radius: 10px;
                    background: rgba(255,255,255,0.04);
                "
            >

                <div
                    style="
                        color: var(--text-secondary);
                        font-size: 12px;
                        margin-bottom: 6px;
                    "
                >
                    Traffic Percentage
                </div>

                <strong
                    style="
                        font-size: 22px;
                    "
                >
                    ${formatPercentage(
                        percentage
                    )}
                </strong>

            </div>


            <div
                style="
                    padding: 16px;
                    border-radius: 10px;
                    background: rgba(255,255,255,0.04);
                "
            >

                <div
                    style="
                        color: var(--text-secondary);
                        font-size: 12px;
                        margin-bottom: 6px;
                    "
                >
                    Classification
                </div>

                <strong
                    style="
                        font-size: 18px;
                    "
                >
                    ${classification}
                </strong>

            </div>


            <div
                style="
                    padding: 16px;
                    border-radius: 10px;
                    background: rgba(255,255,255,0.04);
                "
            >

                <div
                    style="
                        color: var(--text-secondary);
                        font-size: 12px;
                        margin-bottom: 6px;
                    "
                >
                    Highest Analysis Severity
                </div>

                <strong
                    style="
                        font-size: 18px;
                    "
                >
                    ${escapeHtml(
                        highestSeverity
                    )}
                </strong>

            </div>

        </div>


        <div
            style="
                margin-bottom: 22px;
            "
        >

            <h4>
                ${isBenign
                    ? "Traffic Assessment"
                    : "Recommended Actions"}
            </h4>


            ${
                isBenign

                    ? `
                        <p
                            style="
                                line-height: 1.7;
                                color: var(--text-secondary);
                            "
                        >
                            This traffic was classified
                            as benign by the SentinelAI
                            analysis. Continue normal
                            monitoring and maintain
                            existing security controls.
                        </p>
                    `

                    : `
                        <ol
                            style="
                                line-height: 1.6;
                                padding-left: 22px;
                            "
                        >
                            ${recommendationHtml}
                        </ol>
                    `
            }

        </div>


        <div>

            <h4>
                SOC Investigation Steps
            </h4>

            <ol
                style="
                    line-height: 1.6;
                    padding-left: 22px;
                "
            >

                ${investigationHtml}

            </ol>

        </div>


        <div
            style="
                margin-top: 20px;
                padding: 14px;
                border-radius: 10px;
                background: rgba(255,255,255,0.03);
                color: var(--text-secondary);
                font-size: 13px;
                line-height: 1.6;
            "
        >

            SentinelAI investigation data is based
            on the latest analyzed dataset:
            <strong>
                ${escapeHtml(
                    data.file_name ||
                    "Network Dataset"
                )}
            </strong>.

        </div>

    `;


    const closeButton =
        panel.querySelector(
            "#close-attack-investigation"
        );


    if (closeButton) {

        closeButton.addEventListener(
            "click",
            () => {

                panel.remove();

            }
        );

    }


    let container;


    if (
        source === "results"
    ) {

        container =
            $("result-attack-list");

    }

    else {

        container =
            $("attack-list");

    }


    if (!container) {
        return;
    }


    container.insertAdjacentElement(
        "afterend",
        panel
    );


    panel.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}


// ============================================================
// SOC INVESTIGATION STEPS
// ============================================================

function getInvestigationSteps(
    attackName,
    isBenign
) {

    if (isBenign) {

        return [

            "Continue normal network monitoring.",

            "Verify that the traffic pattern is consistent with expected activity.",

            "Maintain current firewall and security controls.",

            "Continue monitoring for changes or abnormal behavior."

        ];

    }


    const attack =
        String(
            attackName || ""
        )
        .toLowerCase();


    if (
        attack.includes("ddos")
    ) {

        return [

            "Investigate the source and destination of the DDoS traffic.",

            "Review firewall, IDS/IPS, and server logs around the affected activity.",

            "Check whether affected services experienced availability or performance problems.",

            "Look for abnormal spikes in traffic volume and connection rates.",

            "Determine whether rate limiting or DDoS mitigation controls should be applied."

        ];

    }


    if (
        attack.includes("portscan") ||
        attack.includes("port scan")
    ) {

        return [

            "Identify the source host responsible for the scanning activity.",

            "Review firewall and IDS/IPS logs for repeated scanning attempts.",

            "Determine which ports and services were targeted.",

            "Check whether any targeted ports expose unnecessary services.",

            "Restrict unnecessary open ports and management services."

        ];

    }


    if (
        attack.includes("xss")
    ) {

        return [

            "Identify the affected web application endpoint.",

            "Review web-server and application logs for suspicious requests.",

            "Check whether malicious input reached the application.",

            "Review input validation, output encoding, and sanitization controls.",

            "Check for additional related web-application vulnerabilities."

        ];

    }


    if (
        attack.includes("brute force")
    ) {

        return [

            "Review authentication and login logs.",

            "Identify the source addresses generating repeated attempts.",

            "Determine whether any accounts were successfully accessed.",

            "Check whether rate limiting, lockout, or progressive delays are enabled.",

            "Require strong authentication and MFA where appropriate."

        ];

    }


    if (
        attack.includes("ssh")
    ) {

        return [

            "Review SSH authentication logs.",

            "Identify source IP addresses associated with repeated attempts.",

            "Check whether any successful SSH authentication occurred.",

            "Restrict SSH access to trusted networks.",

            "Use SSH keys and disable password authentication when practical."

        ];

    }


    if (
        attack.includes("bot")
    ) {

        return [

            "Identify the affected host.",

            "Review running processes and unusual network connections.",

            "Check outbound connections for suspicious destinations.",

            "Review endpoint and security logs for malware indicators.",

            "Isolate the host if malicious activity is confirmed."

        ];

    }


    if (
        attack.includes("dos")
    ) {

        return [

            "Identify the affected service and traffic source.",

            "Review firewall and server logs.",

            "Check CPU, memory, connection, and service utilization.",

            "Apply rate limiting and appropriate traffic filtering.",

            "Monitor the affected service for availability problems."

        ];

    }


    return [

        `Investigate the source of the ${attackName} activity.`,

        "Review firewall, IDS/IPS, and relevant server logs.",

        "Identify the affected hosts, services, and network connections.",

        "Check for repeated or escalating malicious activity.",

        "Apply the security recommendations associated with this attack."

    ];
}


// ============================================================
// RESULTS SEVERITY DISTRIBUTION
// ============================================================

function updateResultsSeverityDistribution(
    distribution
) {

    if (!distribution) {
        distribution = {};
    }


    const severities = [

        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"

    ];


    const total =
        Object.values(
            distribution
        )
        .reduce(
            (sum, value) =>
                sum +
                Number(value || 0),
            0
        );


    severities.forEach(
        (severity) => {

            const lower =
                severity.toLowerCase();


            const count =
                Number(
                    distribution[
                        severity
                    ] || 0
                );


            const countElement =
                $(`result-${lower}`);


            const barElement =
                $(`result-${lower}-bar`);


            if (countElement) {

                countElement.textContent =
                    formatNumber(
                        count
                    );

            }


            if (barElement) {

                const percentage =
                    total > 0
                        ? (
                            count /
                            total
                        ) * 100
                        : 0;


                barElement.style.width =
                    `${percentage}%`;

            }

        }
    );
}


// ============================================================
// SECURITY RECOMMENDATIONS
// ============================================================

function updateRecommendations(
    recommendations
) {

    const container =
        $("recommendations-list");


    if (!container) {
        return;
    }


    if (
        !recommendations ||
        Object.keys(recommendations).length === 0
    ) {

        container.innerHTML = `

            <div class="empty-state">

                <p>
                    No security recommendations
                    available.
                </p>

            </div>

        `;

        return;
    }


    let html = "";


    if (
        Array.isArray(
            recommendations
        )
    ) {

        html = `

            <div class="recommendation-group">

                <h4>
                    Security Recommendations
                </h4>

                <ol>

                    ${recommendations
                        .map(
                            (item) => `

                                <li>
                                    ${escapeHtml(
                                        item
                                    )}
                                </li>

                            `
                        )
                        .join("")}

                </ol>

            </div>

        `;

    }

    else if (
        typeof recommendations ===
        "object"
    ) {

        Object.entries(
            recommendations
        )
        .forEach(
            ([attackType, items]) => {

                if (
                    !Array.isArray(items) ||
                    items.length === 0
                ) {

                    return;
                }


                html += `

                    <div
                        class="recommendation-group"
                    >

                        <h4>
                            ${escapeHtml(
                                cleanAttackName(
                                    attackType
                                )
                            )}
                        </h4>

                        <ol>

                            ${items
                                .map(
                                    (item) => `

                                        <li>
                                            ${escapeHtml(
                                                item
                                            )}
                                        </li>

                                    `
                                )
                                .join("")}

                        </ol>

                    </div>

                `;

            }
        );

    }


    if (!html) {

        html = `

            <div class="empty-state">

                <p>
                    No security recommendations
                    available.
                </p>

            </div>

        `;

    }


    container.innerHTML =
        html;
}


// ============================================================
// FILE SELECTION
// ============================================================

function handleFileSelection(
    file
) {

    if (!file) {
        return;
    }


    const error =
        $("upload-error");


    if (error) {

        error.classList.add(
            "hidden"
        );

        error.textContent = "";

    }


    if (
        !file.name
            .toLowerCase()
            .endsWith(".csv")
    ) {

        if (error) {

            error.textContent =
                "Please select a CSV file.";

            error.classList.remove(
                "hidden"
            );

        }

        return;
    }


    const maxSize =
        512 * 1024 * 1024;


    if (
        file.size >
        maxSize
    ) {

        if (error) {

            error.textContent =
                "The selected file is larger than 512 MB.";

            error.classList.remove(
                "hidden"
            );

        }

        return;
    }


    selectedFile =
        file;


    const fileName =
        $("file-name");

    const fileSize =
        $("file-size");

    const selectedFilePanel =
        $("selected-file");


    if (fileName) {

        fileName.textContent =
            file.name;

    }


    if (fileSize) {

        fileSize.textContent =
            `${(
                file.size /
                1024 /
                1024
            ).toFixed(2)} MB`;

    }


    if (selectedFilePanel) {

        selectedFilePanel.classList.remove(
            "hidden"
        );

    }


    console.log(
        "Selected CSV:",
        file.name
    );
}


// ============================================================
// ANALYZE CSV
// ============================================================

async function analyzeCSV() {

    if (!selectedFile) {

        const error =
            $("upload-error");


        if (error) {

            error.textContent =
                "Please choose a CSV file first.";

            error.classList.remove(
                "hidden"
            );

        }

        return;
    }


    const error =
        $("upload-error");

    const selectedPanel =
        $("selected-file");

    const progress =
        $("analysis-progress");


    if (error) {

        error.classList.add(
            "hidden"
        );

        error.textContent = "";

    }


    if (selectedPanel) {

        selectedPanel.classList.add(
            "hidden"
        );

    }


    if (progress) {

        progress.classList.remove(
            "hidden"
        );

    }


    const formData =
        new FormData();


    formData.append(
        "file",
        selectedFile
    );


    console.log(
        "Sending CSV to SentinelAI API..."
    );


    try {

        const response =
            await fetch(
                `${API_BASE}/api/analyze`,
                {
                    method: "POST",
                    body: formData
                }
            );


        const rawText =
            await response.text();


        let data;


        try {

            data =
                JSON.parse(
                    rawText
                );

        }

        catch {

            throw new Error(
                rawText ||
                "The API returned an invalid response."
            );

        }


        if (!response.ok) {

            throw new Error(
                data.detail ||
                data.message ||
                "Analysis failed."
            );

        }


        if (
            data.success === false
        ) {

            throw new Error(
                data.message ||
                data.detail ||
                "Analysis failed."
            );

        }


        console.log(
            "SentinelAI analysis completed.",
            data
        );


        currentAnalysis =
            data;


        localStorage.setItem(
            "sentinelai_last_analysis",
            JSON.stringify(data)
        );


        updateDashboard(
            data
        );


        updateResultsPage(
            data
        );


        if (progress) {

            progress.classList.add(
                "hidden"
            );

        }


        selectedFile =
            null;


        showPage(
            "results"
        );


        console.log(
            "CSV analysis completed successfully."
        );

    }

    catch (error) {

        console.error(
            "CSV analysis failed:",
            error
        );


        if (progress) {

            progress.classList.add(
                "hidden"
            );

        }


        if (selectedPanel) {

            selectedPanel.classList.remove(
                "hidden"
            );

        }


        const errorElement =
            $("upload-error");


        if (errorElement) {

            errorElement.textContent =
                `Analysis failed: ${error.message}`;

            errorElement.classList.remove(
                "hidden"
            );

        }

    }
}


// ============================================================
// LOAD SAVED ANALYSIS
// ============================================================

function loadSavedAnalysis() {

    try {

        const saved =
            localStorage.getItem(
                "sentinelai_last_analysis"
            );


        if (!saved) {
            return;
        }


        const data =
            JSON.parse(
                saved
            );


        if (!data) {
            return;
        }


        currentAnalysis =
            data;


        updateDashboard(
            data
        );


        updateResultsPage(
            data
        );


        console.log(
            "Previous SentinelAI analysis restored."
        );

    }

    catch (error) {

        console.error(
            "Could not restore saved analysis:",
            error
        );

    }
}


// ============================================================
// DRAG AND DROP
// ============================================================

function setupDragAndDrop() {

    const uploadZone =
        $("upload-zone");


    if (!uploadZone) {
        return;
    }


    uploadZone.addEventListener(
        "dragover",
        (event) => {

            event.preventDefault();

            uploadZone.classList.add(
                "drag-over"
            );

        }
    );


    uploadZone.addEventListener(
        "dragleave",
        () => {

            uploadZone.classList.remove(
                "drag-over"
            );

        }
    );


    uploadZone.addEventListener(
        "drop",
        (event) => {

            event.preventDefault();


            uploadZone.classList.remove(
                "drag-over"
            );


            const files =
                event.dataTransfer.files;


            if (
                files &&
                files.length > 0
            ) {

                handleFileSelection(
                    files[0]
                );

            }

        }
    );
}


// ============================================================
// AI ASSISTANT MESSAGE
// ============================================================

function addAssistantMessage(
    message,
    sender = "ai"
) {

    const chat =
        $("assistant-chat");


    if (!chat) {
        return;
    }


    const messageElement =
        document.createElement(
            "div"
        );


    messageElement.className =
        sender === "user"
            ? "assistant-message user-message"
            : "assistant-message";


    if (
        sender === "user"
    ) {

        messageElement.innerHTML = `

            <div class="assistant-avatar">
                You
            </div>

            <div>

                <strong>
                    You
                </strong>

                <p>
                    ${escapeHtml(
                        message
                    )}
                </p>

            </div>

        `;

    }

    else {

        messageElement.innerHTML = `

            <div class="assistant-avatar">
                AI
            </div>

            <div>

                <strong>
                    SentinelAI
                </strong>

                <p class="assistant-response-text">
                    ${formatAssistantMessage(
                        message
                    )}
                </p>

            </div>

        `;

    }


    chat.appendChild(
        messageElement
    );


    chat.scrollTop =
        chat.scrollHeight;
}


// ============================================================
// AI ASSISTANT LOADING
// ============================================================

function addAssistantLoading() {

    const chat =
        $("assistant-chat");


    if (!chat) {
        return;
    }


    const loading =
        document.createElement(
            "div"
        );


    loading.className =
        "assistant-message";


    loading.id =
        "assistant-loading";


    loading.innerHTML = `

        <div class="assistant-avatar">
            AI
        </div>

        <div>

            <strong>
                SentinelAI
            </strong>

            <p>
                Thinking...
            </p>

        </div>

    `;


    chat.appendChild(
        loading
    );


    chat.scrollTop =
        chat.scrollHeight;
}


// ============================================================
// REMOVE ASSISTANT LOADING
// ============================================================

function removeAssistantLoading() {

    const loading =
        $("assistant-loading");


    if (loading) {

        loading.remove();

    }
}


// ============================================================
// ASSISTANT HEALTH CHECK
// ============================================================

async function checkAssistantHealth() {

    const statusTitle =
        $("assistant-status-title");

    const statusMessage =
        $("assistant-status-message");


    try {

        const response =
            await fetch(
                `${ASSISTANT_API}/api/assistant/health`
            );


        if (!response.ok) {

            throw new Error(
                "Assistant health check failed."
            );

        }


        const data =
            await response.json();


        if (statusTitle) {

            statusTitle.textContent =
                "AI Assistant Connected";

        }


        if (statusMessage) {

            statusMessage.textContent =
                "SentinelAI cybersecurity assistant is ready.";

        }


        console.log(
            "AI Assistant connected:",
            data
        );


        return true;

    }

    catch (error) {

        if (statusTitle) {

            statusTitle.textContent =
                "AI Assistant Offline";

        }


        if (statusMessage) {

            statusMessage.textContent =
                "Unable to connect to the assistant service.";

        }


        console.error(
            "Assistant API error:",
            error
        );


        return false;
    }
}


// ============================================================
// SEND ASSISTANT QUESTION
// ============================================================

async function sendAssistantQuestion(
    question
) {

    const cleanQuestion =
        question.trim();


    if (!cleanQuestion) {
        return;
    }


    addAssistantMessage(
        cleanQuestion,
        "user"
    );


    const input =
        $("assistant-input");


    if (input) {

        input.value =
            "";

    }


    addAssistantLoading();


    try {

        const response =
            await fetch(
                `${ASSISTANT_API}/api/assistant/chat`,
                {
                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body: JSON.stringify({

                        question:
                            cleanQuestion

                    })

                }
            );


        const rawText =
            await response.text();


        let data;


        try {

            data =
                JSON.parse(
                    rawText
                );

        }

        catch {

            throw new Error(
                "Assistant returned invalid JSON."
            );

        }


        if (!response.ok) {

            throw new Error(
                data.detail ||
                data.message ||
                "Assistant request failed."
            );

        }


        removeAssistantLoading();


        const answer =
            data.response ||
            data.answer ||
            data.message ||
            "The assistant did not return an answer.";


        addAssistantMessage(
            answer,
            "ai"
        );

    }

    catch (error) {

        console.error(
            "Assistant request failed:",
            error
        );


        removeAssistantLoading();


        addAssistantMessage(
            `I could not connect to the assistant. ${error.message}`,
            "ai"
        );

    }
}


// ============================================================
// ASSISTANT SETUP
// ============================================================

function setupAssistant() {

    const questions =
        document.querySelectorAll(
            ".suggested-questions button"
        );


    questions.forEach(
        (button) => {

            button.addEventListener(
                "click",
                () => {

                    const input =
                        $("assistant-input");


                    if (!input) {
                        return;
                    }


                    input.value =
                        button.textContent.trim();


                    input.focus();

                }
            );

        }
    );


    const sendButton =
        $("assistant-send");

    const input =
        $("assistant-input");


    if (sendButton) {

        sendButton.addEventListener(
            "click",
            () => {

                if (!input) {
                    return;
                }


                const question =
                    input.value.trim();


                if (!question) {
                    return;
                }


                sendAssistantQuestion(
                    question
                );

            }
        );

    }


    if (input) {

        input.addEventListener(
            "keydown",
            (event) => {

                if (
                    event.key === "Enter"
                ) {

                    event.preventDefault();


                    const question =
                        input.value.trim();


                    if (!question) {
                        return;
                    }


                    sendAssistantQuestion(
                        question
                    );

                }

            }
        );

    }
}


// ============================================================
// FILE INPUT SETUP
// ============================================================

function setupFileInput() {

    const fileInput =
        $("csv-file");


    if (!fileInput) {
        return;
    }


    fileInput.addEventListener(
        "change",
        (event) => {

            const file =
                event.target.files[0];


            handleFileSelection(
                file
            );

        }
    );
}


// ============================================================
// ANALYZE BUTTON SETUP
// ============================================================

function setupAnalyzeButton() {

    const button =
        $("analyze-button");


    if (!button) {
        return;
    }


    button.addEventListener(
        "click",
        analyzeCSV
    );
}


// ============================================================
// SOC REPORT GENERATION
// ============================================================

async function generateSOCReport() {

    const button =
        $("generate-report-button");


    if (button) {

        button.disabled = true;

        button.dataset.originalText =
            button.textContent;

        button.textContent =
            "Generating Report...";

    }


    try {

        const response =
            await fetch(
                `${API_BASE}/api/report`,
                {
                    method: "POST"
                }
            );


        if (!response.ok) {

            let message =
                "Could not generate the SOC report.";


            try {

                const data =
                    await response.json();


                message =
                    data.detail ||
                    data.message ||
                    message;

            }

            catch {

                // Keep default error message.

            }


            throw new Error(
                message
            );

        }


        const blob =
            await response.blob();


        if (
            !blob ||
            blob.size === 0
        ) {

            throw new Error(
                "The generated SOC report is empty."
            );

        }


        const url =
            window.URL.createObjectURL(
                blob
            );


        const link =
            document.createElement(
                "a"
            );


        link.href =
            url;


        link.download =
            "SentinelAI_SOC_Report.pdf";


        document.body.appendChild(
            link
        );


        link.click();


        link.remove();


        window.URL.revokeObjectURL(
            url
        );


        console.log(
            "SentinelAI SOC report downloaded successfully."
        );

    }

    catch (error) {

        console.error(
            "SOC report generation failed:",
            error
        );


        alert(
            `SOC report generation failed: ${error.message}`
        );

    }

    finally {

        if (button) {

            button.disabled = false;


            button.textContent =
                button.dataset.originalText ||
                "Generate SOC Report";

        }

    }
}


// ============================================================
// SOC REPORT BUTTON SETUP
// ============================================================

function setupSOCReportButton() {

    const button =
        $("generate-report-button");


    if (!button) {

        console.warn(
            "Generate SOC Report button was not found."
        );

        return;
    }


    button.addEventListener(
        "click",
        generateSOCReport
    );
}


// ============================================================
// NAVIGATION SETUP
// ============================================================

function setupNavigation() {

    const navigationItems =
        document.querySelectorAll(
            "[data-page]"
        );


    navigationItems.forEach(
        (item) => {

            item.addEventListener(
                "click",
                () => {

                    const page =
                        item.dataset.page;


                    if (page) {

                        showPage(
                            page
                        );

                    }

                }
            );

        }
    );
}


// ============================================================
// APPLICATION INITIALIZATION
// ============================================================

async function initializeApp() {

    console.log(
        "=========================================="
    );

    console.log(
        "SentinelAI Frontend"
    );

    console.log(
        "Initializing application..."
    );

    console.log(
        "=========================================="
    );


    setupNavigation();

    setupFileInput();

    setupAnalyzeButton();

    setupDragAndDrop();

    setupAssistant();

    setupSOCReportButton();

    loadSavedAnalysis();

    await checkApiHealth();

    await checkAssistantHealth();

    showPage(
        "dashboard"
    );


    console.log(
        "SentinelAI frontend ready."
    );
}


// ============================================================
// START APPLICATION
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    initializeApp
);

// ============================================================
// AI MODEL PERFORMANCE
// ============================================================

function renderMLPerformance() {

    const dashboard =
        document.querySelector("#dashboard-page");

    if (!dashboard) {
        return;
    }

    // Prevent duplicate rendering.
    if (
        document.getElementById(
            "ml-performance-panel"
        )
    ) {
        return;
    }

    const modelMetrics = {

        model: "Random Forest",

        records: 234194,

        training_records: 187355,

        testing_records: 46839,

        features: 78,

        classes: 15,

        accuracy: 99.55165567155575,

        macro_precision: 92.97334829937667,

        macro_recall: 92.24944089801451,

        macro_f1: 92.55705980335575

    };


    const classPerformance = [

        {
            name: "BENIGN",
            precision: 99.79,
            recall: 99.59,
            f1: 99.69,
            support: 10000
        },

        {
            name: "Bot",
            precision: 94.66,
            recall: 99.74,
            f1: 97.14,
            support: 391
        },

        {
            name: "DDoS",
            precision: 99.97,
            recall: 99.92,
            f1: 99.94,
            support: 10000
        },

        {
            name: "DoS GoldenEye",
            precision: 99.66,
            recall: 100.00,
            f1: 99.83,
            support: 2057
        },

        {
            name: "DoS Hulk",
            precision: 99.91,
            recall: 99.90,
            f1: 99.90,
            support: 10000
        },

        {
            name: "DoS Slowhttptest",
            precision: 99.62,
            recall: 99.24,
            f1: 99.43,
            support: 1046
        },

        {
            name: "DoS slowloris",
            precision: 99.35,
            recall: 99.72,
            f1: 99.54,
            support: 1077
        },

        {
            name: "FTP-Patator",
            precision: 100.00,
            recall: 100.00,
            f1: 100.00,
            support: 1187
        },

        {
            name: "Heartbleed",
            precision: 100.00,
            recall: 100.00,
            f1: 100.00,
            support: 2
        },

        {
            name: "Infiltration",
            precision: 100.00,
            recall: 85.71,
            f1: 92.31,
            support: 7
        },

        {
            name: "PortScan",
            precision: 99.96,
            recall: 99.94,
            f1: 99.95,
            support: 10000
        },

        {
            name: "SSH-Patator",
            precision: 99.84,
            recall: 100.00,
            f1: 99.92,
            support: 644
        },

        {
            name: "Web Attack - Brute Force",
            precision: 75.97,
            recall: 79.59,
            f1: 77.74,
            support: 294
        },

        {
            name: "Web Attack - SQL Injection",
            precision: 75.00,
            recall: 75.00,
            f1: 75.00,
            support: 4
        },

        {
            name: "Web Attack - XSS",
            precision: 50.86,
            recall: 45.38,
            f1: 47.97,
            support: 130
        }

    ];


    const panel =
        document.createElement("section");

    panel.id =
        "ml-performance-panel";

    panel.className =
        "ml-performance-section";


    panel.innerHTML = `

        <div class="section-heading">

            <p class="eyebrow">
                ARTIFICIAL INTELLIGENCE
            </p>

            <h3>
                AI Model Performance
            </h3>

            <p class="ml-performance-description">
                Evaluation results of the Random Forest
                threat detection model on the held-out
                test dataset.
            </p>

        </div>


        <div class="ml-model-summary">

            <div class="ml-model-info">

                <div>

                    <span class="ml-label">
                        Detection Model
                    </span>

                    <strong>
                        ${modelMetrics.model}
                    </strong>

                </div>


                <div>

                    <span class="ml-label">
                        Features
                    </span>

                    <strong>
                        ${modelMetrics.features}
                    </strong>

                </div>


                <div>

                    <span class="ml-label">
                        Classes
                    </span>

                    <strong>
                        ${modelMetrics.classes}
                    </strong>

                </div>


                <div>

                    <span class="ml-label">
                        Test Records
                    </span>

                    <strong>
                        ${formatNumber(
                            modelMetrics.testing_records
                        )}
                    </strong>

                </div>

            </div>


            <div class="ml-metric-grid">


                <div class="ml-metric-card">

                    <span>
                        Accuracy
                    </span>

                    <strong>
                        ${modelMetrics.accuracy.toFixed(2)}%
                    </strong>

                </div>


                <div class="ml-metric-card">

                    <span>
                        Macro Precision
                    </span>

                    <strong>
                        ${modelMetrics.macro_precision.toFixed(2)}%
                    </strong>

                </div>


                <div class="ml-metric-card">

                    <span>
                        Macro Recall
                    </span>

                    <strong>
                        ${modelMetrics.macro_recall.toFixed(2)}%
                    </strong>

                </div>


                <div class="ml-metric-card">

                    <span>
                        Macro F1
                    </span>

                    <strong>
                        ${modelMetrics.macro_f1.toFixed(2)}%
                    </strong>

                </div>


            </div>

        </div>


        <article class="panel ml-class-panel">

            <div class="panel-header">

                <div>

                    <p class="eyebrow">
                        CLASSIFICATION RESULTS
                    </p>

                    <h3>
                        Class Performance
                    </h3>

                </div>

                <span class="panel-badge">
                    ${modelMetrics.classes} Classes
                </span>

            </div>


            <div class="ml-table-wrapper">

                <table class="ml-performance-table">

                    <thead>

                        <tr>

                            <th>
                                Attack / Class
                            </th>

                            <th>
                                Precision
                            </th>

                            <th>
                                Recall
                            </th>

                            <th>
                                F1-Score
                            </th>

                            <th>
                                Test Samples
                            </th>

                        </tr>

                    </thead>


                    <tbody>

                        ${classPerformance
                            .map((item) => {

                                const performanceClass =
                                    item.f1 < 60
                                        ? "ml-low"
                                        : item.f1 < 80
                                            ? "ml-medium"
                                            : "ml-good";

                                return `

                                    <tr>

                                        <td>
                                            <strong>
                                                ${escapeHtml(
                                                    item.name
                                                )}
                                            </strong>
                                        </td>

                                        <td>
                                            ${item.precision.toFixed(2)}%
                                        </td>

                                        <td>
                                            ${item.recall.toFixed(2)}%
                                        </td>

                                        <td>

                                            <span
                                                class="
                                                    ml-score
                                                    ${performanceClass}
                                                "
                                            >
                                                ${item.f1.toFixed(2)}%
                                            </span>

                                        </td>

                                        <td>
                                            ${formatNumber(
                                                item.support
                                            )}
                                        </td>

                                    </tr>

                                `;

                            })
                            .join("")}

                    </tbody>

                </table>

            </div>


            <div class="ml-performance-note">

                <strong>
                    Evaluation insight:
                </strong>

                SentinelAI performs strongly on
                high-volume traffic classes such as
                DDoS and PortScan. Lower performance
                is observed for some minority web-attack
                classes, particularly XSS, where the
                available test samples are limited.

            </div>

        </article>

    `;


    // Insert the new section before Quick Actions.
    const quickActions =
        dashboard.querySelector(
            ".quick-actions"
        );


    if (quickActions) {

        quickActions.before(
            panel
        );

    }

    else {

        dashboard.appendChild(
            panel
        );

    }

}


// ============================================================
// AI MODEL PERFORMANCE STYLES
// ============================================================

function addMLPerformanceStyles() {

    if (
        document.getElementById(
            "ml-performance-styles"
        )
    ) {
        return;
    }


    const style =
        document.createElement("style");

    style.id =
        "ml-performance-styles";


    style.textContent = `

        .ml-performance-section {

            margin-top: 34px;

        }


        .ml-performance-description {

            color: var(--text-secondary);

            margin-top: 6px;

            line-height: 1.6;

        }


        .ml-model-summary {

            margin-top: 18px;

            padding: 22px;

            border: 1px solid var(--border-color, #2d3748);

            border-radius: 14px;

            background:
                var(
                    --card-background,
                    #111827
                );

        }


        .ml-model-info {

            display: grid;

            grid-template-columns:
                repeat(
                    4,
                    minmax(140px, 1fr)
                );

            gap: 14px;

            margin-bottom: 18px;

        }


        .ml-model-info > div {

            padding: 15px;

            border-radius: 10px;

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.035
                );

        }


        .ml-label {

            display: block;

            color:
                var(
                    --text-secondary
                );

            font-size: 12px;

            margin-bottom: 7px;

            text-transform:
                uppercase;

            letter-spacing: 0.7px;

        }


        .ml-model-info strong {

            font-size: 19px;

        }


        .ml-metric-grid {

            display: grid;

            grid-template-columns:
                repeat(
                    4,
                    minmax(150px, 1fr)
                );

            gap: 14px;

        }


        .ml-metric-card {

            padding: 20px;

            border-radius: 12px;

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.045
                );

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.06
                );

        }


        .ml-metric-card span {

            display: block;

            color:
                var(
                    --text-secondary
                );

            font-size: 13px;

            margin-bottom: 8px;

        }


        .ml-metric-card strong {

            font-size: 28px;

        }


        .ml-class-panel {

            margin-top: 18px;

        }


        .ml-table-wrapper {

            width: 100%;

            overflow-x: auto;

        }


        .ml-performance-table {

            width: 100%;

            border-collapse:
                collapse;

            min-width: 720px;

        }


        .ml-performance-table th {

            text-align: left;

            padding: 13px 12px;

            color:
                var(
                    --text-secondary
                );

            font-size: 12px;

            text-transform:
                uppercase;

            letter-spacing: 0.6px;

            border-bottom:
                1px solid
                var(
                    --border-color,
                    #2d3748
                );

        }


        .ml-performance-table td {

            padding: 13px 12px;

            border-bottom:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.05
                );

            font-size: 14px;

        }


        .ml-performance-table tbody tr:hover {

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.025
                );

        }


        .ml-score {

            display: inline-block;

            min-width: 68px;

            text-align: center;

            padding: 5px 8px;

            border-radius: 7px;

            font-weight: 700;

            font-size: 12px;

        }


        .ml-good {

            background:
                rgba(
                    34,
                    197,
                    94,
                    0.14
                );

        }


        .ml-medium {

            background:
                rgba(
                    245,
                    158,
                    11,
                    0.15
                );

        }


        .ml-low {

            background:
                rgba(
                    239,
                    68,
                    68,
                    0.15
                );

        }


        .ml-performance-note {

            margin-top: 18px;

            padding: 14px 16px;

            border-radius: 10px;

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.035
                );

            color:
                var(
                    --text-secondary
                );

            font-size: 13px;

            line-height: 1.7;

        }


        @media (max-width: 900px) {

            .ml-model-info {

                grid-template-columns:
                    repeat(
                        2,
                        minmax(
                            140px,
                            1fr
                        )
                    );

            }


            .ml-metric-grid {

                grid-template-columns:
                    repeat(
                        2,
                        minmax(
                            140px,
                            1fr
                        )
                    );

            }

        }


        @media (max-width: 520px) {

            .ml-model-info,
            .ml-metric-grid {

                grid-template-columns:
                    1fr;

            }

        }

    `;


    document.head.appendChild(
        style
    );

}


// ============================================================
// INITIALIZE AI MODEL PERFORMANCE
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        addMLPerformanceStyles();

        renderMLPerformance();

    }
);

// ============================================================
// COMPACT CONFUSION MATRIX
// ============================================================

function renderConfusionMatrix() {

    const mlPanel =
        document.getElementById(
            "ml-performance-panel"
        );


    if (!mlPanel) {
        return;
    }


    // Prevent duplicate rendering.
    if (
        document.getElementById(
            "confusion-matrix-panel"
        )
    ) {
        return;
    }


    const labels = [

        "BENIGN",
        "Bot",
        "DDoS",
        "DoS GoldenEye",
        "DoS Hulk",
        "DoS Slowhttptest",
        "DoS slowloris",
        "FTP-Patator",
        "Heartbleed",
        "Infiltration",
        "PortScan",
        "SSH-Patator",
        "Web Attack - Brute Force",
        "Web Attack - SQL Injection",
        "Web Attack - XSS"

    ];


    // Actual SentinelAI evaluation confusion matrix.
    // Rows = actual class.
    // Columns = predicted class.

    const matrix = [

        [9959,22,1,3,5,3,0,0,0,0,3,1,2,1,0],

        [1,390,0,0,0,0,0,0,0,0,0,0,0,0,0],

        [7,0,9992,0,1,0,0,0,0,0,0,0,0,0,0],

        [0,0,0,2057,0,0,0,0,0,0,0,0,0,0,0],

        [4,0,2,3,9990,0,0,0,0,0,1,0,0,0,0],

        [2,0,0,1,0,1038,5,0,0,0,0,0,0,0,0],

        [1,0,0,0,0,1,1074,0,0,0,0,0,1,0,0],

        [0,0,0,0,0,0,0,1187,0,0,0,0,0,0,0],

        [0,0,0,0,0,0,0,0,2,0,0,0,0,0,0],

        [1,0,0,0,0,0,0,0,0,6,0,0,0,0,0],

        [2,0,0,0,3,0,1,0,0,0,9994,0,0,0,0],

        [0,0,0,0,0,0,0,0,0,0,0,644,0,0,0],

        [2,0,0,0,0,0,1,0,0,0,0,0,234,0,57],

        [0,0,0,0,0,0,0,0,0,0,0,0,1,3,0],

        [1,0,0,0,0,0,0,0,0,0,0,0,70,0,59]

    ];


    const panel =
        document.createElement(
            "article"
        );


    panel.id =
        "confusion-matrix-panel";


    panel.className =
        "panel confusion-matrix-panel";


    panel.innerHTML = `

        <div class="panel-header">

            <div>

                <p class="eyebrow">
                    MODEL EVALUATION
                </p>

                <h3>
                    Confusion Matrix
                </h3>

            </div>

            <span class="panel-badge">
                15 Ã— 15
            </span>

        </div>


        <p class="confusion-description">

            The matrix shows how SentinelAI's Random
            Forest classifier predicted each traffic
            class during model testing.

            <strong>
                Rows represent actual classes;
                columns represent predicted classes.
            </strong>

        </p>


        <div class="confusion-layout">

            <div class="confusion-heatmap-wrapper">

                <div class="confusion-axis-title predicted-title">
                    PREDICTED CLASS
                </div>


                <div
                    class="confusion-grid"
                    id="confusion-grid"
                ></div>


                <div class="confusion-axis-title actual-title">
                    ACTUAL CLASS
                </div>

            </div>


            <div
                class="confusion-detail"
                id="confusion-detail"
            >

                <p class="eyebrow">
                    CELL DETAILS
                </p>

                <h4>
                    Select a cell
                </h4>

                <p>
                    Click a matrix cell to inspect
                    the actual and predicted class.
                </p>

            </div>

        </div>


        <div class="confusion-legend">

            <span>
                Low
            </span>

            <span class="legend-gradient"></span>

            <span>
                High
            </span>

            <span class="legend-correct">
                â–  Correct classification
            </span>

            <span class="legend-error">
                â–  Misclassification
            </span>

        </div>

    `;


    const classPanel =
        document.getElementById(
            "ml-performance-panel"
        );


    classPanel.appendChild(
        panel
    );


    const grid =
        document.getElementById(
            "confusion-grid"
        );


    if (!grid) {
        return;
    }


    // Find the largest value for heatmap scaling.
    const maxValue =
        Math.max(
            ...matrix.flat()
        );


    matrix.forEach(
        (row, rowIndex) => {

            row.forEach(
                (value, columnIndex) => {

                    const cell =
                        document.createElement(
                            "button"
                        );


                    cell.type =
                        "button";


                    cell.className =
                        "confusion-cell";


                    const intensity =
                        maxValue > 0
                            ? Math.sqrt(
                                value /
                                maxValue
                            )
                            : 0;


                    const alpha =
                        value === 0
                            ? 0.025
                            : 0.12 +
                                (
                                    intensity *
                                    0.78
                                );


                    cell.style.background =
                        `rgba(56, 189, 248, ${alpha})`;


                    if (
                        rowIndex ===
                        columnIndex
                    ) {

                        cell.classList.add(
                            "correct"
                        );

                    }

                    else if (
                        value > 0
                    ) {

                        cell.classList.add(
                            "misclassified"
                        );

                    }


                    cell.textContent =
                        value;


                    cell.title =
                        `Actual: ${labels[rowIndex]} | Predicted: ${labels[columnIndex]} | ${formatNumber(value)} samples`;


                    cell.addEventListener(
                        "click",
                        () => {

                            showConfusionCellDetails(
                                rowIndex,
                                columnIndex,
                                value,
                                labels
                            );

                        }
                    );


                    grid.appendChild(
                        cell
                    );

                }
            );

        }
    );


    // Add row/column labels.
    addConfusionLabels(
        grid,
        labels
    );

}


// ============================================================
// CONFUSION MATRIX LABELS
// ============================================================

function addConfusionLabels(
    grid,
    labels
) {

    const labelContainer =
        document.createElement(
            "div"
        );


    labelContainer.className =
        "confusion-labels";


    labelContainer.innerHTML = labels
        .map(
            (label, index) => `

                <span
                    title="${escapeHtml(label)}"
                >
                    ${index + 1}
                </span>

            `
        )
        .join("");


    grid.parentElement.insertBefore(
        labelContainer,
        grid
    );

}


// ============================================================
// CONFUSION MATRIX CELL DETAILS
// ============================================================

function showConfusionCellDetails(
    actualIndex,
    predictedIndex,
    value,
    labels
) {

    const detail =
        document.getElementById(
            "confusion-detail"
        );


    if (!detail) {
        return;
    }


    const actual =
        labels[actualIndex];


    const predicted =
        labels[predictedIndex];


    const isCorrect =
        actualIndex ===
        predictedIndex;


    detail.innerHTML = `

        <p class="eyebrow">
            CELL DETAILS
        </p>


        <h4>
            ${isCorrect
                ? "Correct Classification"
                : "Misclassification"}
        </h4>


        <div class="confusion-detail-row">

            <span>
                Actual Class
            </span>

            <strong>
                ${escapeHtml(actual)}
            </strong>

        </div>


        <div class="confusion-detail-row">

            <span>
                Predicted Class
            </span>

            <strong>
                ${escapeHtml(predicted)}
            </strong>

        </div>


        <div class="confusion-detail-count">

            <span>
                Test Samples
            </span>

            <strong>
                ${formatNumber(value)}
            </strong>

        </div>


        <p class="confusion-detail-message">

            ${
                isCorrect

                    ? "The model correctly classified these network-flow records."

                    : "These records belonged to the actual class but were predicted as another class."
            }

        </p>

    `;

}


// ============================================================
// CONFUSION MATRIX STYLES
// ============================================================

function addConfusionMatrixStyles() {

    if (
        document.getElementById(
            "confusion-matrix-styles"
        )
    ) {
        return;
    }


    const style =
        document.createElement(
            "style"
        );


    style.id =
        "confusion-matrix-styles";


    style.textContent = `

        .confusion-matrix-panel {

            margin-top: 18px;

            overflow: hidden;

        }


        .confusion-description {

            color:
                var(
                    --text-secondary
                );

            line-height: 1.7;

            margin:
                0 0 22px;

            max-width: 900px;

        }


        .confusion-layout {

            display: grid;

            grid-template-columns:
                minmax(
                    0,
                    1fr
                )
                260px;

            gap: 22px;

            align-items: start;

        }


        .confusion-heatmap-wrapper {

            min-width: 0;

            overflow-x: auto;

            padding-bottom: 6px;

        }


        .confusion-axis-title {

            color:
                var(
                    --text-secondary
                );

            font-size: 11px;

            letter-spacing: 1px;

            font-weight: 700;

            text-align: center;

        }


        .predicted-title {

            margin-bottom: 10px;

        }


        .actual-title {

            margin-top: 10px;

        }


        .confusion-grid {

            display: grid;

            grid-template-columns:
                repeat(
                    15,
                    minmax(
                        34px,
                        1fr
                    )
                );

            gap: 3px;

            min-width: 585px;

        }


        .confusion-cell {

            aspect-ratio: 1 / 1;

            border: 1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.07
                );

            border-radius: 4px;

            color: #e5f3ff;

            font-size: 9px;

            font-weight: 700;

            padding: 2px;

            cursor: pointer;

            transition:
                transform 0.12s ease,
                border-color 0.12s ease,
                box-shadow 0.12s ease;

            overflow: hidden;

        }


        .confusion-cell:hover {

            transform:
                scale(1.12);

            border-color:
                rgba(
                    255,
                    255,
                    255,
                    0.7
                );

            box-shadow:
                0 4px 14px
                rgba(
                    0,
                    0,
                    0,
                    0.25
                );

            position: relative;

            z-index: 2;

        }


        .confusion-cell.correct {

            border:
                1px solid
                rgba(
                    34,
                    197,
                    94,
                    0.45
                );

        }


        .confusion-cell.misclassified {

            border:
                1px solid
                rgba(
                    248,
                    113,
                    113,
                    0.35
                );

        }


        .confusion-labels {

            display: grid;

            grid-template-columns:
                repeat(
                    15,
                    minmax(
                        34px,
                        1fr
                    )
                );

            gap: 3px;

            min-width: 585px;

            margin-bottom: 5px;

        }


        .confusion-labels span {

            text-align: center;

            color:
                var(
                    --text-secondary
                );

            font-size: 9px;

            font-weight: 700;

        }


        .confusion-detail {

            padding: 18px;

            border-radius: 12px;

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.035
                );

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.07
                );

            min-height: 230px;

        }


        .confusion-detail h4 {

            margin:
                6px 0 16px;

        }


        .confusion-detail > p:not(.eyebrow) {

            color:
                var(
                    --text-secondary
                );

            line-height: 1.6;

            font-size: 13px;

        }


        .confusion-detail-row {

            display: flex;

            flex-direction: column;

            gap: 4px;

            padding:
                10px 0;

            border-bottom:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.06
                );

        }


        .confusion-detail-row span,
        .confusion-detail-count span {

            color:
                var(
                    --text-secondary
                );

            font-size: 11px;

            text-transform:
                uppercase;

            letter-spacing:
                0.5px;

        }


        .confusion-detail-row strong {

            font-size: 13px;

            line-height: 1.4;

        }


        .confusion-detail-count {

            display: flex;

            justify-content:
                space-between;

            align-items:
                center;

            padding-top: 14px;

        }


        .confusion-detail-count strong {

            font-size: 20px;

        }


        .confusion-detail-message {

            margin-top: 16px;

        }


        .confusion-legend {

            display: flex;

            align-items: center;

            flex-wrap: wrap;

            gap: 9px;

            margin-top: 18px;

            color:
                var(
                    --text-secondary
                );

            font-size: 11px;

        }


        .legend-gradient {

            width: 100px;

            height: 8px;

            border-radius: 99px;

            background:
                linear-gradient(
                    to right,
                    rgba(
                        56,
                        189,
                        248,
                        0.05
                    ),
                    rgba(
                        56,
                        189,
                        248,
                        0.9
                    )
                );

        }


        .legend-correct {

            margin-left: 12px;

            color:
                rgba(
                    134,
                    239,
                    172,
                    0.9
                );

        }


        .legend-error {

            color:
                rgba(
                    252,
                    165,
                    165,
                    0.9
                );

        }


        @media (max-width: 900px) {

            .confusion-layout {

                grid-template-columns:
                    1fr;

            }


            .confusion-detail {

                min-height: auto;

            }

        }

    `;


    document.head.appendChild(
        style
    );

}


// ============================================================
// INITIALIZE CONFUSION MATRIX
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        addConfusionMatrixStyles();

        // renderMLPerformance creates the parent
        // section first, so render the matrix after it.
        setTimeout(
            renderConfusionMatrix,
            100
        );

    }
);

// ============================================================
// SYNC ML DASHBOARD WITH BACKEND API
// ============================================================

async function syncMLPerformanceFromAPI() {

    try {

        const response = await fetch(
            `${API_BASE}/api/model-performance`
        );


        if (!response.ok) {

            throw new Error(
                `ML performance API returned ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                "ML performance API returned an unsuccessful response."
            );

        }


        // ====================================================
        // OVERALL MODEL INFORMATION
        // ====================================================

        const modelInfo =
            document.querySelectorAll(
                ".ml-model-info > div strong"
            );


        if (modelInfo.length >= 4) {

            modelInfo[0].textContent =
                data.model || "Unknown";

            modelInfo[1].textContent =
                data.features ?? 0;

            modelInfo[2].textContent =
                data.classes ?? 0;

            modelInfo[3].textContent =
                formatNumber(
                    data.testing_records ?? 0
                );

        }


        // ====================================================
        // OVERALL METRICS
        // ====================================================

        const metricValues =
            document.querySelectorAll(
                ".ml-metric-card strong"
            );


        const metrics = [

            data.accuracy,

            data.macro_precision,

            data.macro_recall,

            data.macro_f1

        ];


        metricValues.forEach(
            (element, index) => {

                if (
                    metrics[index] !== undefined
                ) {

                    element.textContent =
                        `${Number(
                            metrics[index]
                        ).toFixed(2)}%`;

                }

            }
        );


        // ====================================================
        // CLASS PERFORMANCE
        // ====================================================

        const classRows =
            document.querySelectorAll(
                ".ml-performance-table tbody tr"
            );


        const classPerformance =
            data.class_performance || [];


        classRows.forEach(
            (row, index) => {

                const item =
                    classPerformance[index];


                if (!item) {
                    return;
                }


                const cells =
                    row.querySelectorAll("td");


                if (cells.length < 5) {
                    return;
                }


                // Attack/class name
                const nameElement =
                    cells[0].querySelector("strong");


                if (nameElement) {

                    nameElement.textContent =
                        cleanMLAttackName(
                            item.name
                        );

                }


                // Precision
                cells[1].textContent =
                    `${Number(
                        item.precision
                    ).toFixed(2)}%`;


                // Recall
                cells[2].textContent =
                    `${Number(
                        item.recall
                    ).toFixed(2)}%`;


                // F1
                const f1 =
                    Number(item.f1);


                const f1Element =
                    cells[3].querySelector(
                        ".ml-score"
                    );


                if (f1Element) {

                    f1Element.textContent =
                        `${f1.toFixed(2)}%`;


                    f1Element.classList.remove(
                        "ml-low",
                        "ml-medium",
                        "ml-good"
                    );


                    if (f1 < 60) {

                        f1Element.classList.add(
                            "ml-low"
                        );

                    }

                    else if (f1 < 80) {

                        f1Element.classList.add(
                            "ml-medium"
                        );

                    }

                    else {

                        f1Element.classList.add(
                            "ml-good"
                        );

                    }

                }


                // Test samples
                cells[4].textContent =
                    formatNumber(
                        item.support
                    );

            }
        );


        // ====================================================
        // CONFUSION MATRIX
        // ====================================================

        const confusionCells =
            document.querySelectorAll(
                ".confusion-cell"
            );


        const confusionMatrix =
            data.confusion_matrix || [];


        const confusionLabels =
            data.confusion_labels || [];


        confusionCells.forEach(
            (cell, index) => {

                const size =
                    confusionLabels.length;


                if (!size) {
                    return;
                }


                const rowIndex =
                    Math.floor(
                        index / size
                    );


                const columnIndex =
                    index % size;


                const value =
                    confusionMatrix[
                        rowIndex
                    ]?.[
                        columnIndex
                    ] ?? 0;


                cell.textContent =
                    value;


                cell.title =
                    `Actual: ${
                        cleanMLAttackName(
                            confusionLabels[
                                rowIndex
                            ] || ""
                        )
                    } | Predicted: ${
                        cleanMLAttackName(
                            confusionLabels[
                                columnIndex
                            ] || ""
                        )
                    } | ${
                        formatNumber(value)
                    } samples`;

            }
        );


        console.log(
            "SentinelAI ML evaluation synchronized from backend."
        );

    }

    catch (error) {

        // Keep the existing dashboard values as fallback.
        console.warn(
            "Could not synchronize ML evaluation from backend:",
            error
        );

    }

}


// ============================================================
// CLEAN ML ATTACK NAMES
// ============================================================

function cleanMLAttackName(name) {

    if (!name) {
        return "";
    }


    let value =
        String(name);


    const replacements = {

        "Ã¯Â¿Â½": "â€“",

        "ÃƒÂ¯Ã‚Â¿Ã‚Â½": "â€“",

        "Ã¢â‚¬â€œ": "â€“",

        "Ã¢â‚¬â€": "â€”",

        "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“": "â€“",

        "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬": "â€“"

    };


    Object.entries(
        replacements
    ).forEach(
        ([bad, good]) => {

            value =
                value.replace(
                    bad,
                    good
                );

        }
    );


    return value;

}


// ============================================================
// START ML API SYNCHRONIZATION
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        // The ML dashboard is created by the
        // existing initialization functions.
        // Give them time to finish first.

        setTimeout(
            syncMLPerformanceFromAPI,
            500
        );

    }
);

// ============================================================
// DYNAMIC CONFUSION MATRIX - BACKEND DATA
// ============================================================

let sentinelMLPerformanceData = null;


async function loadDynamicMLPerformanceData() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/model-performance`
            );


        if (!response.ok) {

            throw new Error(
                `ML performance API returned ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                "ML performance API returned unsuccessful data."
            );

        }


        sentinelMLPerformanceData =
            data;


        console.log(
            "Dynamic ML performance data loaded:",
            data
        );


        return data;

    }

    catch (error) {

        console.warn(
            "Could not load dynamic ML performance data:",
            error
        );


        return null;

    }

}


// ============================================================
// CONFUSION MATRIX BACKEND CLICK HANDLER
// ============================================================

function setupDynamicConfusionMatrix() {

    document.addEventListener(
        "click",
        async (event) => {

            const cell =
                event.target.closest(
                    ".confusion-cell"
                );


            if (!cell) {
                return;
            }


            const data =
                sentinelMLPerformanceData ||
                await loadDynamicMLPerformanceData();


            if (!data) {
                return;
            }


            const labels =
                data.confusion_labels || [];


            const matrix =
                data.confusion_matrix || [];


            if (!labels.length) {
                return;
            }


            const cells =
                document.querySelectorAll(
                    ".confusion-cell"
                );


            const cellIndex =
                Array.from(cells).indexOf(
                    cell
                );


            if (cellIndex < 0) {
                return;
            }


            const size =
                labels.length;


            const rowIndex =
                Math.floor(
                    cellIndex / size
                );


            const columnIndex =
                cellIndex % size;


            const actual =
                cleanMLAttackName(
                    labels[rowIndex] || "Unknown"
                );


            const predicted =
                cleanMLAttackName(
                    labels[columnIndex] || "Unknown"
                );


            const value =
                Number(
                    matrix[rowIndex]?.[columnIndex] || 0
                );


            // Store the latest backend-based
            // cell information on the element.
            cell.dataset.actual =
                actual;


            cell.dataset.predicted =
                predicted;


            cell.dataset.value =
                value;


            cell.title =
                `Actual: ${actual} | ` +
                `Predicted: ${predicted} | ` +
                `${formatNumber(value)} samples`;


            console.log(
                "Confusion matrix cell:",
                {
                    actual,
                    predicted,
                    value
                }
            );

        },
        true
    );

}


// ============================================================
// INITIALIZE DYNAMIC ML DATA
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupDynamicConfusionMatrix();

        loadDynamicMLPerformanceData();

    }
);

// ============================================================
// SENTINELAI - MODEL EVALUATION SUMMARY
// ============================================================

function renderModelEvaluationSummary(data) {

    if (!data) {
        return;
    }

    const existing =
        document.getElementById(
            "sentinel-model-evaluation-summary"
        );

    if (existing) {
        existing.remove();
    }

    const accuracy =
        Number(data.accuracy || 0);

    const macroPrecision =
        Number(data.macro_precision || 0);

    const macroRecall =
        Number(data.macro_recall || 0);

    const macroF1 =
        Number(data.macro_f1 || 0);

    const weightedF1 =
        Number(data.weighted_f1 || 0);

    const container =
        document.createElement("section");

    container.id =
        "sentinel-model-evaluation-summary";

    container.className =
        "sentinel-evaluation-summary";

    container.innerHTML = `
        <div class="sentinel-evaluation-header">
            <div>
                <h2>Model Evaluation Summary</h2>
                <p>
                    Performance of the Random Forest
                    threat classification model on the
                    held-out test dataset.
                </p>
            </div>
        </div>

        <div class="sentinel-evaluation-grid">

            <div class="sentinel-evaluation-card">
                <span>Accuracy</span>
                <strong>${accuracy.toFixed(2)}%</strong>
                <small>Overall correct predictions</small>
            </div>

            <div class="sentinel-evaluation-card">
                <span>Macro Precision</span>
                <strong>${macroPrecision.toFixed(2)}%</strong>
                <small>Average precision across classes</small>
            </div>

            <div class="sentinel-evaluation-card">
                <span>Macro Recall</span>
                <strong>${macroRecall.toFixed(2)}%</strong>
                <small>Average recall across classes</small>
            </div>

            <div class="sentinel-evaluation-card">
                <span>Macro F1</span>
                <strong>${macroF1.toFixed(2)}%</strong>
                <small>Balanced class-level F1 score</small>
            </div>

            <div class="sentinel-evaluation-card">
                <span>Weighted F1</span>
                <strong>${weightedF1.toFixed(2)}%</strong>
                <small>F1 weighted by class support</small>
            </div>

        </div>

        <div class="sentinel-evaluation-details">

            <div>
                <strong>Model</strong>
                <span>${escapeHtml(data.model || "Unknown")}</span>
            </div>

            <div>
                <strong>Features</strong>
                <span>${formatNumber(data.features || 0)}</span>
            </div>

            <div>
                <strong>Classes</strong>
                <span>${formatNumber(data.classes || 0)}</span>
            </div>

            <div>
                <strong>Training Records</strong>
                <span>${formatNumber(data.training_records || 0)}</span>
            </div>

            <div>
                <strong>Testing Records</strong>
                <span>${formatNumber(data.testing_records || 0)}</span>
            </div>

        </div>

        <div class="sentinel-evaluation-note">
            <strong>Interpretation:</strong>
            The overall accuracy is very high, but macro-level
            metrics provide a more balanced view because they
            give equal importance to each attack class.
        </div>
    `;

    const quickActions =
        document.querySelector(".quick-actions");

    if (quickActions) {

        quickActions.parentNode.insertBefore(
            container,
            quickActions
        );

    } else {

        const dashboard =
            document.querySelector(".dashboard") ||
            document.querySelector("main");

        if (dashboard) {
            dashboard.appendChild(container);
        }

    }

}


// ============================================================
// LOAD EVALUATION SUMMARY FROM BACKEND
// ============================================================

async function loadModelEvaluationSummary() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/model-performance`
            );

        if (!response.ok) {
            throw new Error(
                `API returned ${response.status}`
            );
        }

        const data =
            await response.json();

        if (!data.success) {
            throw new Error(
                "Backend returned unsuccessful result."
            );
        }

        renderModelEvaluationSummary(data);

        console.log(
            "SentinelAI model evaluation summary loaded."
        );

    } catch (error) {

        console.warn(
            "Could not load model evaluation summary:",
            error
        );

    }

}


document.addEventListener(
    "DOMContentLoaded",
    () => {

        setTimeout(
            loadModelEvaluationSummary,
            700
        );

    }
);

// ============================================================
// SENTINELAI - MODEL FINDINGS & LIMITATIONS
// ============================================================

function renderModelFindings(data) {

    if (!data) {
        return;
    }

    const existing =
        document.getElementById(
            "sentinel-model-findings"
        );

    if (existing) {
        existing.remove();
    }

    const classPerformance =
        data.class_performance || [];

    const sortedClasses =
        [...classPerformance]
            .sort(
                (a, b) =>
                    Number(a.f1 || 0) -
                    Number(b.f1 || 0)
            );

    const weakest =
        sortedClasses.slice(0, 3);

    const strongest =
        [...classPerformance]
            .sort(
                (a, b) =>
                    Number(b.f1 || 0) -
                    Number(a.f1 || 0)
            )
            .slice(0, 3);

    const weakestHTML =
        weakest.map(item => `
            <div class="sentinel-finding-row">
                <strong>
                    ${escapeHtml(
                        cleanMLAttackName(item.name)
                    )}
                </strong>
                <span>
                    F1: ${Number(item.f1 || 0).toFixed(2)}%
                </span>
            </div>
        `).join("");

    const strongestHTML =
        strongest.map(item => `
            <div class="sentinel-finding-row">
                <strong>
                    ${escapeHtml(
                        cleanMLAttackName(item.name)
                    )}
                </strong>
                <span>
                    F1: ${Number(item.f1 || 0).toFixed(2)}%
                </span>
            </div>
        `).join("");

    const section =
        document.createElement("section");

    section.id =
        "sentinel-model-findings";

    section.className =
        "sentinel-model-findings";

    section.innerHTML = `

        <div class="sentinel-findings-header">
            <div>
                <h2>Model Findings & Limitations</h2>
                <p>
                    Key observations identified from the
                    Random Forest evaluation results.
                </p>
            </div>
        </div>

        <div class="sentinel-findings-grid">

            <div class="sentinel-finding-card">

                <h3>Weakest Classes</h3>

                <div class="sentinel-finding-list">
                    ${weakestHTML}
                </div>

            </div>


            <div class="sentinel-finding-card">

                <h3>Strongest Classes</h3>

                <div class="sentinel-finding-list">
                    ${strongestHTML}
                </div>

            </div>


            <div class="sentinel-finding-card">

                <h3>Key Observation</h3>

                <p>
                    Overall accuracy is very high, but
                    performance varies between attack classes.
                    Minority web-attack categories show lower
                    F1 scores than the dominant classes.
                </p>

            </div>

        </div>


        <div class="sentinel-limitation-box">

            <h3>Important Model Limitation</h3>

            <p>
                The evaluation shows that Web Attack - XSS
                is the most difficult class for the model.
                Its current F1 score is approximately
                47.97%.
            </p>

            <p>
                The confusion matrix shows that a significant
                number of XSS samples were classified as
                Web Attack - Brute Force. This indicates that
                these traffic patterns can be difficult for
                the current feature set and classifier to
                distinguish.
            </p>

            <p>
                Future improvement can focus on additional
                feature engineering, better representation of
                web-application traffic, class balancing and
                comparison with other machine-learning models.
            </p>

        </div>

    `;


    const evaluationSection =
        document.getElementById(
            "sentinel-model-evaluation-summary"
        );


    if (evaluationSection) {

        evaluationSection.insertAdjacentElement(
            "afterend",
            section
        );

    } else {

        const dashboard =
            document.querySelector(".dashboard") ||
            document.querySelector("main");

        if (dashboard) {
            dashboard.appendChild(section);
        }

    }

}


// ============================================================
// LOAD FINDINGS FROM REAL BACKEND RESULTS
// ============================================================

async function loadModelFindings() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/model-performance`
            );

        if (!response.ok) {

            throw new Error(
                `API returned ${response.status}`
            );

        }

        const data =
            await response.json();

        if (!data.success) {

            throw new Error(
                "Backend returned unsuccessful result."
            );

        }

        renderModelFindings(data);

        console.log(
            "SentinelAI model findings loaded."
        );

    } catch (error) {

        console.warn(
            "Could not load model findings:",
            error
        );

    }

}


document.addEventListener(
    "DOMContentLoaded",
    () => {

        setTimeout(
            loadModelFindings,
            900
        );

    }
);



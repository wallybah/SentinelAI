from typing import Dict, List


# ---------------------------------------------------------
# Security recommendations by attack type
# ---------------------------------------------------------

RECOMMENDATIONS: Dict[str, List[str]] = {

    "DDoS": [
        "Enable rate limiting for incoming network traffic.",
        "Apply firewall rules to restrict suspicious traffic sources.",
        "Use DDoS mitigation or traffic filtering services.",
        "Monitor traffic volume and connection rates for abnormal spikes.",
        "Review affected services and verify their availability.",
    ],

    "PortScan": [
        "Investigate the source of the scanning activity.",
        "Restrict unnecessary open ports using firewall rules.",
        "Disable unused network services.",
        "Review firewall and IDS/IPS logs for repeated scanning attempts.",
        "Consider restricting management services to trusted networks.",
    ],

    "Bot": [
        "Investigate the affected host for signs of malware.",
        "Check running processes and unusual network connections.",
        "Update operating systems and security software.",
        "Review outbound connections from the affected system.",
        "Isolate the host if malicious activity is confirmed.",
    ],

    "DoS GoldenEye": [
        "Investigate the source of the denial-of-service traffic.",
        "Apply rate limiting and traffic filtering.",
        "Review firewall rules for suspicious connections.",
        "Monitor affected services for availability problems.",
        "Consider DDoS/DoS mitigation controls.",
    ],

    "DoS Hulk": [
        "Apply rate limiting to affected services.",
        "Block or restrict suspicious traffic sources.",
        "Review web-server and firewall logs.",
        "Monitor server resource utilization.",
        "Deploy appropriate DoS mitigation controls.",
    ],

    "DoS Slowhttptest": [
        "Review slow HTTP connection activity.",
        "Configure appropriate connection and request timeouts.",
        "Apply rate limiting to suspicious clients.",
        "Review web-server resource utilization.",
        "Use firewall or reverse-proxy protections where appropriate.",
    ],

    "DoS slowloris": [
        "Configure web-server connection timeouts.",
        "Limit the number of concurrent connections per client.",
        "Apply rate limiting to suspicious sources.",
        "Monitor long-lived HTTP connections.",
        "Review reverse-proxy and firewall configuration.",
    ],

    "FTP-Patator": [
        "Review FTP authentication logs.",
        "Enable account lockout or login throttling.",
        "Restrict FTP access to trusted networks where possible.",
        "Disable unnecessary FTP services.",
        "Require strong authentication credentials.",
    ],

    "SSH-Patator": [
        "Review SSH authentication logs.",
        "Enable login throttling or account lockout controls.",
        "Restrict SSH access to trusted IP addresses.",
        "Disable password authentication when appropriate.",
        "Use strong authentication and SSH keys.",
    ],

    "Heartbleed": [
        "Verify that affected systems are not running vulnerable OpenSSL versions.",
        "Patch or upgrade vulnerable SSL/TLS software.",
        "Rotate potentially exposed credentials and secrets.",
        "Review systems that may have been exposed to the vulnerability.",
        "Monitor for suspicious access following remediation.",
    ],

    "Infiltration": [
        "Investigate the affected host immediately.",
        "Review network and system logs for unauthorized activity.",
        "Check for malware, persistence mechanisms, and unusual processes.",
        "Isolate the affected system if compromise is suspected.",
        "Reset potentially compromised credentials after investigation.",
    ],

    "Web Attack � Brute Force": [
        "Enable authentication rate limiting.",
        "Review login and authentication logs.",
        "Use account lockout or progressive delays.",
        "Require strong passwords and multi-factor authentication.",
        "Investigate repeated requests from suspicious sources.",
    ],

    "Web Attack � Sql Injection": [
        "Use parameterized queries and prepared statements.",
        "Validate and sanitize application input.",
        "Review application and database logs.",
        "Apply a web application firewall where appropriate.",
        "Test affected applications for additional injection vulnerabilities.",
    ],

    "Web Attack � XSS": [
        "Apply proper input validation and output encoding.",
        "Use appropriate Content Security Policy controls.",
        "Review affected web application endpoints.",
        "Sanitize untrusted user input.",
        "Test the application for additional cross-site scripting vulnerabilities.",
    ],

    "BENIGN": [
        "No immediate malicious activity was detected.",
        "Continue normal network monitoring.",
        "Maintain current firewall and security controls.",
        "Keep systems and security software updated.",
    ],
}


# ---------------------------------------------------------
# Default recommendations
# ---------------------------------------------------------

DEFAULT_RECOMMENDATIONS = [
    "Investigate the detected network activity.",
    "Review relevant firewall and system logs.",
    "Check the affected systems for unusual behavior.",
    "Maintain current security controls and monitoring.",
]


# ---------------------------------------------------------
# Recommendation engine
# ---------------------------------------------------------

class RecommendationEngine:

    def __init__(self):

        self.recommendations = RECOMMENDATIONS

    # -----------------------------------------------------
    # Get recommendations for one attack type
    # -----------------------------------------------------

    def get_recommendations(
        self,
        attack_type: str,
    ) -> List[str]:

        return self.recommendations.get(
            attack_type,
            DEFAULT_RECOMMENDATIONS,
        )

    # -----------------------------------------------------
    # Get recommendations for an analysis
    # -----------------------------------------------------

    def get_analysis_recommendations(
        self,
        attack_distribution: Dict[str, int],
    ) -> Dict[str, List[str]]:

        result = {}

        for attack_type in attack_distribution:

            result[attack_type] = (
                self.get_recommendations(
                    attack_type
                )
            )

        return result


# ---------------------------------------------------------
# Test
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("SentinelAI - Security Recommendation Engine")
    print("=" * 70)

    engine = RecommendationEngine()

    # Test attack types.
    test_attacks = [
        "DDoS",
        "PortScan",
        "Web Attack � XSS",
        "BENIGN",
    ]

    for attack in test_attacks:

        print("\n" + "-" * 70)
        print(f"Attack Type: {attack}")
        print("-" * 70)

        recommendations = (
            engine.get_recommendations(
                attack
            )
        )

        for number, recommendation in enumerate(
            recommendations,
            start=1,
        ):

            print(
                f"{number}. {recommendation}"
            )

    print("\n" + "=" * 70)
    print("Recommendation engine working successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()
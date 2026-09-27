function normalizeFindings(findings, category) {

    return (findings || []).map((finding) => {

        return {
            category: category,

            type:
                finding.type ||
                "UNKNOWN",

            severity:
                finding.severity ||
                "LOW",

            reason:
                finding.reason ||
                "No reason provided"
        };

    });

}
const severityWeight = {
    SAFE: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
};


function getSeverityWeight(severity) {

    return (
        severityWeight[severity] ??
        severityWeight.LOW
    );

}

function applyCorrelationRules(findings) {

    const correlationReasons = [];

    const hasFinding = (category, type) => {

        return findings.some(
            finding =>
                finding.category === category &&
                finding.type === type
        );

    };


    // =====================================
    // RULE 1 — Suspicious URL + Password
    // =====================================

    const suspiciousURL =
        findings.some(
            finding =>
                finding.category === "URL" &&
                (
                    finding.severity === "HIGH" ||
                    finding.reason
                        .toLowerCase()
                        .includes("suspicious") ||
                    finding.reason
                        .toLowerCase()
                        .includes("punycode")
                )
        );

    const passwordField =
        hasFinding(
            "FORM",
            "PASSWORD_FIELD"
        );


    if (
        suspiciousURL &&
        passwordField
    ) {

        correlationReasons.push(
            "Suspicious URL combined with a password field"
        );

    }


    // =====================================
    // RULE 2 — Suspicious URL + Password
    //           + Cross-Origin Form
    // =====================================

    const crossOriginForm =
        hasFinding(
            "FORM",
            "CROSS_ORIGIN_ACTION"
        );


    if (
        suspiciousURL &&
        passwordField &&
        crossOriginForm
    ) {

        correlationReasons.push(
            "Suspicious URL, password field, and cross-origin form submission detected together"
        );

    }


    // =====================================
    // RULE 3 — Prompt Injection + Credentials
    // =====================================

    const credentialRequest =
        hasFinding(
            "PROMPT_INJECTION",
            "CREDENTIAL_REQUEST"
        );

    const promptInjection =
        findings.some(
            finding =>
                finding.category ===
                "PROMPT_INJECTION" &&
                finding.severity === "HIGH"
        );


    if (
        promptInjection &&
        credentialRequest
    ) {

        correlationReasons.push(
            "Prompt injection indicators are combined with a credential request"
        );

    }


    // =====================================
    // RULE 4 — Sensitive Token + Credential Request
    // =====================================

    const sensitiveToken =
        findings.some(
            finding =>
                finding.category ===
                "SENSITIVE_DATA" &&
                (
                    finding.type === "JWT" ||
                    finding.type === "TOKEN_OR_SECRET" ||
                    finding.type === "AWS_ACCESS_KEY"
                )
        );


    if (
        sensitiveToken &&
        credentialRequest
    ) {

        correlationReasons.push(
            "Sensitive token or secret detected together with a credential request"
        );

    }


    // =====================================
    // RULE 5 — Suspicious Script + Cross-Origin
    //          Iframe
    // =====================================

    const suspiciousScript =
        hasFinding(
            "SCRIPT",
            "SUSPICIOUS_SCRIPT_SOURCE"
        );

    const crossOriginIframe =
        hasFinding(
            "IFRAME",
            "CROSS_ORIGIN_IFRAME"
        );


    if (
        suspiciousScript &&
        crossOriginIframe
    ) {

        correlationReasons.push(
            "Suspicious script source combined with a cross-origin iframe"
        );

    }


    return correlationReasons;

}
function calculateOverallRisk(findings) {

    // =====================================
    // NO FINDINGS
    // =====================================

    if (!findings || findings.length === 0) {

        return {
            level: "SAFE",
            reasons: [
                "No security findings detected"
            ]
        };

    }


    // =====================================
    // HIGHEST SEVERITY
    // =====================================

    let highestWeight = 0;

    findings.forEach((finding) => {

        const weight =
            getSeverityWeight(
                finding.severity
            );

        if (weight > highestWeight) {
            highestWeight = weight;
        }

    });


    // =====================================
    // CORRELATION
    // =====================================

    const correlationReasons =
        applyCorrelationRules(
            findings
        );


    // =====================================
    // RISK LEVEL
    // =====================================

    let level = "SAFE";


    if (highestWeight >= 4) {

        level = "CRITICAL";

    } else if (highestWeight === 3) {

        level = "HIGH";

    } else if (highestWeight === 2) {

        level = "MEDIUM";

    } else if (highestWeight === 1) {

        level = "LOW";

    }


    // =====================================
    // CORRELATION CAN INCREASE RISK
    // =====================================

    if (
        correlationReasons.length >= 2 &&
        level === "MEDIUM"
    ) {

        level = "HIGH";

    }


    if (
        correlationReasons.length >= 3 &&
        (
            level === "HIGH" ||
            level === "MEDIUM"
        )
    ) {

        level = "CRITICAL";

    }


    // =====================================
    // WHY?
    // =====================================

    const informationalTypes = [
        "NO_SUSPICIOUS_DOM_PATTERN",
        "NO_FORM_SECURITY_ISSUE",
        "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
        "NO_SENSITIVE_DATA",
        "NO_PROMPT_INJECTION",
        "NO_SUSPICIOUS_URL_PATTERN"
    ];

    const reasons = findings
        .filter(
            finding =>
                finding.severity !== "LOW" &&
                !informationalTypes.includes(
                    finding.type
                )
        )
        .map(
            finding =>
                finding.reason
        );


    correlationReasons.forEach(
        reason => {

            if (
                !reasons.includes(reason)
            ) {

                reasons.push(reason);

            }

        }
    );


    // Remove duplicate reasons

    const uniqueReasons =
        [...new Set(reasons)];


    // =====================================
    // FINAL RESULT
    // =====================================

    return {
        level: level,
        reasons:
            uniqueReasons.length > 0
                ? uniqueReasons
                : [
                    "No significant security indicators detected"
                ]
    };

}
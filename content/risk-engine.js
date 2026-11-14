function normalizeFindings(findings, category) {

    return (findings || []).map((finding) => {

        const normalized = {
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

        if (finding.details) {
            normalized.details = finding.details;
        }

        return normalized;
    });

}

const informationalTypes = [
    "NO_SUSPICIOUS_DOM_PATTERN",
    "NO_FORM_SECURITY_ISSUE",
    "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
    "NO_SENSITIVE_DATA",
    "NO_PROMPT_INJECTION",
    "NO_SUSPICIOUS_URL_PATTERN",
    "NO_WEB_VULNERABILITY",
    "VERIFIED_THIRD_PARTY_IFRAME"
];

const purelyInformationalTypes = new Set([
    ...informationalTypes,
    "PASSWORD_FIELD",              // On HTTPS, password field is standard informational
    "SENSITIVE_INPUT",             // Standard inputs (email, text)
    "FORMS",                       // Standard HTML forms
    "EXTERNAL_SCRIPTS",            // Standard third-party scripts
    "VERIFIED_THIRD_PARTY_IFRAME", // Verified CAPTCHA / Payment / Media embeds
    "ENCODED_CHARACTERS"           // Standard URL encoding (e.g. %20 space in search)
]);

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
                finding.type !== "NO_SUSPICIOUS_URL_PATTERN" &&
                finding.severity !== "LOW" &&
                (
                    finding.severity === "HIGH" ||
                    (
                        typeof finding.reason === "string" &&
                        !finding.reason.toLowerCase().startsWith("no suspicious") &&
                        (
                            finding.reason.toLowerCase().includes("suspicious") ||
                            finding.reason.toLowerCase().includes("punycode")
                        )
                    )
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


        // =====================================
    // RULE 6 — SQL Injection Endpoint + Form
    // =====================================
    const sqliEndpoint =
        hasFinding(
            "WEB_VULNERABILITY",
            "SQL_INJECTION_ENDPOINT"
        );

    const sqliForm =
        hasFinding(
            "WEB_VULNERABILITY",
            "POTENTIAL_SQL_INJECTION_FORM"
        );

    const sqliDbError =
        hasFinding(
            "WEB_VULNERABILITY",
            "SQL_INJECTION_ERROR"
        );

    if (sqliEndpoint && sqliForm) {
        correlationReasons.push(
            "SQL Injection vulnerable endpoint combined with interactive query form input"
        );
    }

    if (sqliDbError) {
        correlationReasons.push(
            "Active database error disclosure confirming SQL injection vulnerability"
        );
    }

        // =====================================
    // RULE 7 — Critical PHP CGI Injection (CVE-2024-4577)
    // =====================================
    const phpCgi = hasFinding("WEB_VULNERABILITY", "PHP_CGI_ARGUMENT_INJECTION");
    if (phpCgi) {
        correlationReasons.push(
            "Critical PHP CGI argument injection vulnerability (CVE-2024-4577 / Remote Code Execution)"
        );
    }

    // =====================================
    // RULE 8 — Insecure Password Transmission
    // =====================================
    const insecurePass = hasFinding("WEB_VULNERABILITY", "INSECURE_PASSWORD_TRANSMISSION");
    if (insecurePass) {
        correlationReasons.push(
            "User credentials or passwords transmitted insecurely over GET method or cleartext HTTP"
        );
    }

    // =====================================
    // RULE 9 — SSRF Internal / Cloud Metadata Target
    // =====================================
    const ssrfParam = hasFinding("WEB_VULNERABILITY", "POTENTIAL_SSRF_PARAMETER");
    if (ssrfParam) {
        correlationReasons.push(
            "Potential Server-Side Request Forgery (SSRF) target accessing internal/cloud endpoints"
        );
    }

    // =====================================
    // RULE 10 — Path Traversal / File Inclusion
    // =====================================
    const pathTraversal = hasFinding("WEB_VULNERABILITY", "PATH_TRAVERSAL_PAYLOAD") ||
                          hasFinding("WEB_VULNERABILITY", "FILE_INCLUSION_ENDPOINT");
    if (pathTraversal) {
        correlationReasons.push(
            "Path Traversal or Local File Inclusion vulnerability exposing server filesystem files"
        );
    }

    // =====================================
    // RULE 11 — Exposed Admin & Misconfiguration
    // =====================================
    const exposedAdmin = hasFinding("WEB_VULNERABILITY", "EXPOSED_ADMIN_INTERFACE");
    const misconfig = hasFinding("WEB_VULNERABILITY", "VERBOSE_ERROR_DISCLOSURE") ||
                      hasFinding("WEB_VULNERABILITY", "DIRECTORY_LISTING_ENABLED");
    if (exposedAdmin && misconfig) {
        correlationReasons.push(
            "Exposed administrative interface combined with active system error or directory disclosures"
        );
    }

    return correlationReasons;

}

function calculateOverallRisk(findings) {

    // Filter out purely informational passed-checks
    const actualFindings = (findings || []).filter(
        (f) => f && !informationalTypes.includes(f.type)
    );

    // Filter out findings that are purely informational context on HTTPS pages (not threats)
    const actionableRiskFindings = actualFindings.filter(
        (f) => !(purelyInformationalTypes.has(f.type) && f.severity === "LOW")
    );

    // =====================================
    // NO ACTIONABLE RISK FINDINGS -> SAFE
    // =====================================
    if (actionableRiskFindings.length === 0) {
        return {
            level: "SAFE",
            reasons: [
                "No significant security indicators detected"
            ]
        };
    }

    // =====================================
    // HIGHEST SEVERITY AMONG ACTIONABLE FINDINGS
    // =====================================
    let highestWeight = 0;

    actionableRiskFindings.forEach((finding) => {
        const weight = getSeverityWeight(finding.severity);
        if (weight > highestWeight) {
            highestWeight = weight;
        }
    });

    // =====================================
    // CORRELATION
    // =====================================
    const correlationReasons = applyCorrelationRules(actionableRiskFindings);

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
    // CORRELATION ELEVATIONS
    // =====================================
    if (correlationReasons.length >= 2 && level === "MEDIUM") {
        level = "HIGH";
    }

    if (
        correlationReasons.length >= 3 &&
        (level === "HIGH" || level === "MEDIUM")
    ) {
        level = "CRITICAL";
    }

    // =====================================
    // REASONS
    // =====================================
    const reasons = actionableRiskFindings
        .filter((finding) => finding.severity !== "LOW")
        .map((finding) => finding.reason);

    correlationReasons.forEach((reason) => {
        if (!reasons.includes(reason)) {
            reasons.push(reason);
        }
    });

    const uniqueReasons = [...new Set(reasons)];

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

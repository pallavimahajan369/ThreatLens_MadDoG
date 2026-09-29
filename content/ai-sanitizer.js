console.log("SentinelAI AI Sanitizer loaded");


function sanitizeFindings(findings) {

    return (findings || []).map((finding) => {

        return {
            category:
                finding.category ||
                "UNKNOWN",

            type:
                finding.type ||
                "UNKNOWN",

            severity:
                finding.severity ||
                "LOW",

            reason:
                sanitizeReason(
                    finding.reason ||
                    "No reason provided"
                )
        };

    });

}


function sanitizeReason(reason) {

    if (!reason) {
        return "No reason provided";
    }

    let sanitized =
        String(reason);

    /*
     * Remove JWT-like values
     */
    sanitized =
        sanitized.replace(
            /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
            "[REDACTED]"
        );


    /*
     * Remove AWS access-key-like values
     */
    sanitized =
        sanitized.replace(
            /\bAKIA[0-9A-Z]{16}\b/g,
            "[REDACTED]"
        );


    /*
     * Remove common token / secret assignments
     */
    sanitized =
        sanitized.replace(
            /\b(?:token|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{8,}["']?/gi,
            "[REDACTED]"
        );


    /*
     * Remove password assignments
     */
    sanitized =
        sanitized.replace(
            /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi,
            "[REDACTED]"
        );


    return sanitized;

}


function sanitizeCorrelations(correlations) {

    return (correlations || [])
        .map(
            correlation =>
                sanitizeReason(
                    correlation
                )
        )
        .filter(
            correlation =>
                correlation.length > 0
        );

}


function buildAISecurityPayload(scan) {

    if (!scan) {

        return {
            overallRisk: "SAFE",
            websiteRisk: "SAFE",
            extensionRisk: "SAFE",
            findings: [],
            correlations: []
        };

    }


    const findings = [

        ...(scan.urlFindings || []),

        ...(scan.domFindings || []),

        ...(scan.formFindings || []),

        ...(scan.scriptIframeFindings || []),

        ...(scan.sensitiveDataFindings || []),

        ...(scan.promptInjectionFindings || [])

    ];


    const sanitizedFindings =
        sanitizeFindings(
            findings
        );


    const correlations =
        scan.risk?.reasons || [];


    const sanitizedCorrelations =
        sanitizeCorrelations(
            correlations
        );


    return {

        overallRisk:
            scan.overallRisk ||
            scan.risk?.level ||
            "SAFE",

        websiteRisk:
            scan.risk?.level ||
            "SAFE",

        extensionRisk:
            scan.extensionScan?.some(
                extension =>
                    extension.risk === "HIGH"
            )
                ? "HIGH"
                : scan.extensionScan?.some(
                    extension =>
                        extension.risk === "MEDIUM"
                )
                    ? "MEDIUM"
                    : "LOW",

        findings:
            sanitizedFindings,

        correlations:
            sanitizedCorrelations

    };

}
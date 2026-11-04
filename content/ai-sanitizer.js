
console.log("TreatLens AI Sanitizer loaded");

// Allow only known security levels.
const ALLOWED_RISKS = new Set([
    "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
]);

const ALLOWED_SEVERITIES = new Set([
    "LOW", "MEDIUM", "HIGH", "CRITICAL"
]);

function safeEnum(value, allowed, fallback) {
    const normalized = String(value || "").toUpperCase();
    return allowed.has(normalized) ? normalized : fallback;
}

// Remove common secrets and unnecessary identifying data.

function sanitizeReason(reason) {
    if (typeof reason !== "string") {
        return "Security indicator detected";
    }

    let value = reason.slice(0, 1000);

    return value
        // JWT-like tokens
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED]")
        // AWS access key IDs
        .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
        // Authorization credentials
        .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, "$1 [REDACTED]")
        // Secrets and API tokens: token=abc, api_key: "abc"
        .replace(/\b(token|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?[^"' \t\r\n,;]+["']?/gi, "$1=[REDACTED]")
        // Password assignments
        .replace(/\b(password|passwd|pwd)\b\s*[:=]\s*["']?[^"' \t\r\n,;]+["']?/gi, "$1=[REDACTED]")
        // Email addresses
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
        // URLs
        .replace(/https?:\/\/[^\s"'<>]+/gi, "[URL]")
        // IPv4 addresses
        .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP]")
        // Common private-key block markers and contents
        .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, "[REDACTED_PRIVATE_KEY]")
        .slice(0, 500);
}


function sanitizeFindings(findings) {
    if (!Array.isArray(findings)) return [];

    return findings.slice(0, 100).map(finding => ({
        category: sanitizeReason(
            typeof finding?.category === "string"
                ? finding.category
                : "UNKNOWN"
        ).slice(0, 80),

        type: sanitizeReason(
            typeof finding?.type === "string"
                ? finding.type
                : "UNKNOWN"
        ).slice(0, 80),

        severity: safeEnum(
            finding?.severity,
            ALLOWED_SEVERITIES,
            "LOW"
        ),

        reason: sanitizeReason(finding?.reason)
    }));
}

function sanitizeCorrelations(correlations) {
    if (!Array.isArray(correlations)) return [];

    return correlations
        .slice(0, 30)
        .filter(item => typeof item === "string")
        .map(sanitizeReason);
}

function buildAISecurityPayload(scan) {
    const source = scan || {};

    const findings = [
        ...(Array.isArray(source.urlFindings)
            ? source.urlFindings : []),
        ...(Array.isArray(source.domFindings)
            ? source.domFindings : []),
        ...(Array.isArray(source.formFindings)
            ? source.formFindings : []),
        ...(Array.isArray(source.scriptIframeFindings)
            ? source.scriptIframeFindings : []),
        ...(Array.isArray(source.sensitiveDataFindings)
            ? source.sensitiveDataFindings : []),
        ...(Array.isArray(source.promptInjectionFindings)
            ? source.promptInjectionFindings : [])
    ];

    const extensions = Array.isArray(source.extensionScan)
        ? source.extensionScan
        : [];

    let extensionRisk = "LOW";

    if (extensions.some(e => e?.risk === "CRITICAL")) {
        extensionRisk = "CRITICAL";
    } else if (extensions.some(e => e?.risk === "HIGH")) {
        extensionRisk = "HIGH";
    } else if (extensions.some(e => e?.risk === "MEDIUM")) {
        extensionRisk = "MEDIUM";
    }

    const websiteRisk = safeEnum(
        source.risk?.level || source.overallRisk,
        ALLOWED_RISKS,
        "SAFE"
    );

    return {
        overallRisk: safeEnum(
            source.overallRisk || websiteRisk,
            ALLOWED_RISKS,
            "SAFE"
        ),

        websiteRisk,
        extensionRisk,

        findings: sanitizeFindings(findings),

        correlations: sanitizeCorrelations(
            source.risk?.reasons
        )
    };
}

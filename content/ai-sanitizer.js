console.log("ThreatLens AI Sanitizer loaded");

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
        // Strip HTML tags and DOM elements
        .replace(/<[^>]*>/g, "[DOM_ELEMENT]")
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
        // Common private-key block markers and contents
        .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, "[REDACTED_PRIVATE_KEY]")
        .slice(0, 400);
}

function sanitizeFindings(findings) {
    if (!Array.isArray(findings)) return [];

    // Filter out non-threat informational signals
    const threats = findings.filter(f => f && f.type && !f.type.startsWith("NO_"));
    const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const uniqueMap = new Map();

    for (const f of threats) {
        const key = `${f.category || "GEN"}_${f.type || "UNKNOWN"}`;
        const sev = safeEnum(f.severity, ALLOWED_SEVERITIES, "LOW");

        let location = "";
        let preview = "";
        if (f.details?.items && f.details.items.length > 0) {
            const firstItem = f.details.items[0];
            location = firstItem.location || firstItem.domPath || firstItem.fileName || "";
            preview = (firstItem.preview || firstItem.title || "").slice(0, 120);
        }

        if (!uniqueMap.has(key)) {
            uniqueMap.set(key, {
                category: sanitizeReason(String(f.category || "UNKNOWN")).slice(0, 30),
                type: sanitizeReason(String(f.type || "UNKNOWN")).slice(0, 40),
                severity: sev,
                reason: sanitizeReason(f.reason || "").slice(0, 150),
                location: sanitizeReason(location).slice(0, 100),
                preview: sanitizeReason(preview).slice(0, 120),
                occurrences: 1
            });
        } else {
            const existing = uniqueMap.get(key);
            existing.occurrences += 1;
            if (!existing.location && location) existing.location = sanitizeReason(location).slice(0, 100);
            if (!existing.preview && preview) existing.preview = sanitizeReason(preview).slice(0, 120);
            if ((severityRank[sev] || 0) > (severityRank[existing.severity] || 0)) {
                existing.severity = sev;
            }
        }
    }

    return Array.from(uniqueMap.values())
        .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
        .slice(0, 8);
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
    let pageUrl = source.url || "";
    let hostname = "";
    let port = "";
    let pathname = "";
    try {
        if (pageUrl && pageUrl.startsWith("http")) {
            const parsed = new URL(pageUrl);
            hostname = parsed.hostname;
            port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
            pathname = parsed.pathname;
        }
    } catch (e) {}

    const findings = [
        ...(Array.isArray(source.urlFindings) ? source.urlFindings : []),
        ...(Array.isArray(source.domFindings) ? source.domFindings : []),
        ...(Array.isArray(source.formFindings) ? source.formFindings : []),
        ...(Array.isArray(source.scriptIframeFindings) ? source.scriptIframeFindings : []),
        ...(Array.isArray(source.sensitiveDataFindings) ? source.sensitiveDataFindings : []),
        ...(Array.isArray(source.promptInjectionFindings) ? source.promptInjectionFindings : [])
    ];

    const extensions = Array.isArray(source.extensionScan) ? source.extensionScan : [];
    const notableExtensions = extensions.filter(e => (e?.risk === "HIGH" || e?.risk === "MEDIUM" || (e?.permissions && e.permissions.length > 3)))
        .slice(0, 5)
        .map(e => ({
            name: e.name || "Unknown Extension",
            risk: e.risk || "MEDIUM",
            permissions: (e.permissions || []).slice(0, 6)
        }));

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
        pageUrl: sanitizeReason(pageUrl).slice(0, 200),
        hostname,
        port,
        pathname,
        overallRisk: safeEnum(source.overallRisk || websiteRisk, ALLOWED_RISKS, "SAFE"),
        websiteRisk,
        extensionRisk,
        findings: sanitizeFindings(findings),
        extensions: notableExtensions,
        correlations: sanitizeCorrelations(source.risk?.reasons)
    };
}
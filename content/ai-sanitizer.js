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

/**
 * Sanitizes URLs to remove sensitive credentials, session IDs, and tokens from query parameters.
 * E.g., strips PHPSESSID, JSESSIONID, auth tokens, passwords, and userinfo.
 * @param {string} rawUrl 
 * @returns {string} Sanitized URL safe for AI analysis
 */
function sanitizeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") return "";
    try {
        const u = new URL(rawUrl);
        // Strip user:pass authentication credentials from URL (e.g., http://admin:admin@site.com)
        u.username = "";
        u.password = "";

        // Strip hash fragment if it contains access tokens, sessions, or credentials
        if (u.hash && /(token|session|auth|key|secret|pass)/i.test(u.hash)) {
            u.hash = "#[REDACTED_HASH_FRAGMENT]";
        }

        // Sensitive query parameter names that must be redacted
        const sensitiveParamRegex = /^(?:phpsessid|jsessionid|aspsessionid|connect\.sid|session_?id|sessid|sid|session|token|access_?token|id_?token|refresh_?token|csrf_?token|xsrf_?token|user_?token|csrftoken|auth|authtoken|auth_?token|key|api_?key|apikey|secret|password|passwd|pwd|pass|sig|signature|hash)$/i;

        const keysToRedact = [];
        u.searchParams.forEach((val, key) => {
            if (sensitiveParamRegex.test(key) || /(?:session|token|auth|secret|pass|key)/i.test(key)) {
                keysToRedact.push(key);
            } else if (/^[a-f0-9]{24,64}$/i.test(val) || /^eyJ[A-Za-z0-9_-]+\./.test(val)) {
                // Parameter value itself is a raw session token or JWT hash
                keysToRedact.push(key);
            }
        });

        keysToRedact.forEach(key => {
            u.searchParams.set(key, "[REDACTED_SESSION_OR_SECRET]");
        });

        return u.toString();
    } catch (e) {
        // Fallback regex replacement for non-standard or partial URLs
        return rawUrl
            .replace(/\b(phpsessid|jsessionid|aspsessionid|session_?id|sessid|sid|token|csrf_?token|auth|key|secret|password|pwd)\b=[^&\s]+/gi, "$1=[REDACTED_SESSION_OR_SECRET]")
            .replace(/:\/\/[^:]+:[^@]+@/, "://");
    }
}

/**
 * Strips common secrets, session IDs, auth tokens, passwords, and DOM code from strings.
 * @param {string} reason 
 * @returns {string} Sanitized string safe for AI prompts
 */
function sanitizeReason(reason) {
    if (typeof reason !== "string") {
        return "Security indicator detected";
    }

    let value = reason.slice(0, 1000);

    return value
        // Strip script tags and their inner content
        .replace(/<script[\s\S]*?<\/script>/gi, "[SCRIPT_STRIPPED]")
        // Strip all other HTML tags and DOM elements
        .replace(/<[^>]*>/g, "[DOM_ELEMENT]")
        // Session IDs (PHPSESSID, JSESSIONID, ASPSESSIONID, connect.sid, session_id, sid)
        .replace(/\b(phpsessid|jsessionid|aspsessionid|connect\.sid|session_?id|sessid|sid)\b\s*[:=]\s*["']?[^"' \t\r\n,;&]+["']?/gi, "$1=[REDACTED_SESSION_ID]")
        // CSRF and anti-forgery tokens
        .replace(/\b(csrf[_-]?token|xsrf[_-]?token|user[_-]?token|auth[_-]?token|authtoken)\b\s*[:=]\s*["']?[^"' \t\r\n,;&]+["']?/gi, "$1=[REDACTED_TOKEN]")
        // Cookie headers and assignments
        .replace(/\b(set-cookie|cookie)\b\s*[:=]\s*["']?[^"' \t\r\n]+["']?/gi, "$1=[REDACTED_COOKIE]")
        // JWT-like tokens
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]")
        // AWS access key IDs
        .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]")
        // Authorization credentials (Bearer, Basic)
        .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, "$1 [REDACTED_AUTH]")
        // Secrets and API tokens: token=abc, api_key: "abc"
        .replace(/\b(token|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?[^"' \t\r\n,;&]+["']?/gi, "$1=[REDACTED_SECRET]")
        // Password assignments: password=..., passwd: "..."
        .replace(/\b(password|passwd|pwd|pass)\b\s*[:=]\s*["']?[^"' \t\r\n,;&]+["']?/gi, "$1=[REDACTED_PASSWORD]")
        // Input values and form values
        .replace(/\b(value|val)\b\s*[:=]\s*["']?[^"' \t\r\n,;&]+["']?/gi, "$1=[REDACTED_VALUE]")
        // Email addresses
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
        // Common private-key block markers and contents
        .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, "[REDACTED_PRIVATE_KEY]")
        // Truncate to safe length
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

/**
 * Builds a strictly sanitized, minimal AI security payload.
 * Guarantees:
 * 1. Zero raw cookies, zero session IDs (PHPSESSID, JSESSIONID, etc.).
 * 2. Zero raw HTML/DOM code trees, zero input values/typed text.
 * 3. Stripped credentials, tokens, emails, and secrets.
 * 4. All URLs pass through sanitizeUrl to strip session query parameters.
 * @param {Object} scan Raw scan result from page
 * @returns {Object} Cleaned, minimal payload safe for Gemini AI
 */
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
        ...(Array.isArray(source.webVulnerabilityFindings) ? source.webVulnerabilityFindings : []),
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
        pageUrl: sanitizeUrl(pageUrl).slice(0, 200),
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

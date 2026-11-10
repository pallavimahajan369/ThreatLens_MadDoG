
/**
 * Performs passive, client-side ethical security auditing and attack surface reconnaissance:
 * 1. Technology stack fingerprinting (CMS, web servers, frontend/backend frameworks).
 * 2. Attack surface discovery (hidden form parameters, disabled controls, sensitive comments, API routes).
 * 3. Security headers and cookie hygiene audit (missing HttpOnly flags, CSP meta tags, mixed content).
 * 4. CVSS v3.1 scoring and ethical verification guides.
 * @returns {Object} Comprehensive security audit results
 */

// ============================================================================
// CONTENT SECURITY POLICY (CSP) ANALYSIS & PARSER
// ============================================================================

/**
 * Standardized Content Security Policy parser & effectiveness analyzer.
 * Evaluates whether an active CSP policy successfully mitigates XSS, DOM sinks, and dynamic eval.
 * @param {string} cspString Raw CSP string from HTTP header or meta tag
 * @param {string} source "HTTP Header" | "Meta Tag"
 * @returns {Object|null}
 */
function parseCspString(cspString, source = "HTTP Header") {
    if (!cspString || typeof cspString !== "string") return null;
    const directives = {};
    const parts = cspString.split(";");
    for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        const tokens = trimmed.split(/\s+/);
        const name = tokens[0].toLowerCase();
        const values = tokens.slice(1).map(v => v.toLowerCase().replace(/['"]/g, ""));
        directives[name] = values;
    }

    const scriptSrc = directives["script-src"] || directives["script-src-elem"] || directives["default-src"] || [];
    const objectSrc = directives["object-src"] || directives["default-src"] || [];
    const frameAncestors = directives["frame-ancestors"] || [];

    const hasUnsafeInline = scriptSrc.includes("unsafe-inline");
    const hasUnsafeEval = scriptSrc.includes("unsafe-eval");
    const hasWildcardScript = scriptSrc.includes("*") || scriptSrc.includes("https:") || scriptSrc.includes("http:");
    const hasNonceOrHash = scriptSrc.some(v => v.startsWith("nonce-") || v.startsWith("sha256-") || v.startsWith("sha384-") || v.startsWith("sha512-"));

    const bypassDomains = ["pastebin.com", "hastebin.com", "raw.githubusercontent.com", "api.github.com", "ajax.googleapis.com", "cdnjs.cloudflare.com"];
    const matchedBypassDomains = scriptSrc.filter(s => bypassDomains.some(bd => s.includes(bd)));
    const isBypassable = hasUnsafeInline || hasWildcardScript || matchedBypassDomains.length > 0;

    let bypassReason = "";
    if (hasUnsafeInline) bypassReason = "Allows 'unsafe-inline' script execution";
    else if (hasWildcardScript) bypassReason = "Permissive wildcard script source (* or https:)";
    else if (matchedBypassDomains.length > 0) bypassReason = `Permits script injection via hosted payload source (${matchedBypassDomains.join(", ")})`;

    const isStrictScript = scriptSrc.length > 0 && !hasUnsafeInline && !hasWildcardScript;
    const blocksEval = scriptSrc.length > 0 && !hasUnsafeEval;
    const blocksObjects = objectSrc.includes("none") || (objectSrc.length > 0 && !objectSrc.includes("*"));

    let summary = "Permissive CSP";
    if (isStrictScript) {
        summary = hasNonceOrHash ? "Strict Nonce/Hash CSP" : "Strict Self CSP (Inline Blocked)";
    } else if (hasUnsafeInline) {
        summary = "Permissive CSP (Allows 'unsafe-inline')";
    } else if (scriptSrc.length > 0) {
        summary = "Custom Origin CSP";
    }

    return {
        raw: cspString,
        source: source,
        directives,
        scriptSrc,
        hasUnsafeInline,
        hasUnsafeEval,
        hasNonceOrHash,
        isStrictScript,
        blocksEval,
        blocksObjects,
        isBypassable,
        bypassReason,
        summary,
        isActive: Object.keys(directives).length > 0
    };
}

/**
 * Detects active CSP from document meta tags or cached window headers.
 * @returns {Object|null}
 */
function detectAndParseActiveCsp() {
    // 1. Check window headers injected by background / content script
    if (typeof window !== "undefined" && window.__threatlens_headers && window.__threatlens_headers.csp) {
        return parseCspString(window.__threatlens_headers.csp, "HTTP Header");
    }

    // 2. Check meta tags in DOM
    if (typeof document !== "undefined" && typeof document.querySelector === "function") {
        const cspMeta = document.querySelector("meta[http-equiv='Content-Security-Policy' i], meta[http-equiv='Content-Security-Policy-Report-Only' i]");
        if (cspMeta) {
            const content = cspMeta.getAttribute("content") || "";
            if (content) {
                return parseCspString(content, "Meta Tag");
            }
        }
    }

    return null;
}

/**
 * Universal CSP Mitigation Evaluator.
 * Adjusts findings to LOW / MITIGATED when protected by an active Content Security Policy.
 * @param {Object} scan
 * @param {Object} cspInfo
 * @returns {Object}
 */
function applyCspMitigations(scan, cspInfo) {
    if (!scan || !cspInfo || !cspInfo.isActive) return scan;

    const mitigateFinding = (f) => {
        if (!f || !f.type) return f;
        const type = String(f.type).toUpperCase();

        // 1. Script execution vulnerabilities (XSS, DOM Sinks, Inline Scripts)
        const isScriptVuln = 
            type.includes("XSS") || 
            type.includes("DOM_SINK") || 
            type.includes("INLINE_SCRIPT") ||
            type === "DOM_XSS_ENDPOINT" ||
            type === "REFLECTED_XSS_ENDPOINT" ||
            type === "STORED_XSS_ENDPOINT" ||
            type === "DANGEROUS_DOM_SINK";

        if (isScriptVuln && cspInfo.isStrictScript) {
            f.severity = "LOW";
            f.isMitigated = true;
            if (typeof f.reason === "string" && !f.reason.includes("[MITIGATED BY CSP]")) {
                f.reason = `${f.reason} [MITIGATED BY CSP: ${cspInfo.summary}]`;
            }
            if (f.details) {
                if (typeof f.details.title === "string" && !f.details.title.includes("[MITIGATED BY CSP]")) {
                    f.details.title = `[MITIGATED BY CSP] ${f.details.title}`;
                }
                f.details.cspMitigation = {
                    status: "MITIGATED",
                    protectionType: "Content Security Policy Enforced",
                    policySummary: cspInfo.summary,
                    details: "This finding's active exploitability is neutralized because the page enforces a strict Content Security Policy (script-src without 'unsafe-inline') which prevents arbitrary script execution in the browser."
                };
            }
        }

        // 2. Dangerous APIs (eval, Function, setTimeout string)
        if (type === "DANGEROUS_API" && cspInfo.blocksEval) {
            f.severity = "LOW";
            f.isMitigated = true;
            if (typeof f.reason === "string" && !f.reason.includes("[MITIGATED BY CSP]")) {
                f.reason = `${f.reason} [MITIGATED BY CSP: 'unsafe-eval' blocked]`;
            }
            if (f.details) {
                if (typeof f.details.title === "string" && !f.details.title.includes("[MITIGATED BY CSP]")) {
                    f.details.title = `[MITIGATED BY CSP] ${f.details.title}`;
                }
                f.details.cspMitigation = {
                    status: "MITIGATED",
                    protectionType: "CSP 'unsafe-eval' Blocked",
                    policySummary: cspInfo.summary,
                    details: "Execution of dynamic string code via eval() or Function() is actively blocked by the browser's Content Security Policy."
                };
            }
        }

        // 3. CSP Bypass Endpoint (e.g. DVWA /vulnerabilities/csp/)
        if (type === "CSP_BYPASS_VULNERABILITY") {
            if (!cspInfo.isBypassable && cspInfo.isStrictScript) {
                f.severity = "LOW";
                f.isMitigated = true;
                f.reason = `Content Security Policy active & verified: ${cspInfo.summary} (No bypass patterns observed)`;
                if (f.details) {
                    f.details.title = "[SECURE] Content Security Policy Enforced";
                    f.details.riskExplanation = "The current endpoint enforces a strict Content Security Policy without known bypass directives ('unsafe-inline' and wildcard origins are disabled).";
                    f.details.cspMitigation = {
                        status: "SECURE",
                        policySummary: cspInfo.summary,
                        details: "The Content Security Policy on this page was analyzed and verified to enforce strict script origin boundaries."
                    };
                }
            } else if (cspInfo.isBypassable) {
                f.reason = `Content Security Policy bypass weakness detected: ${cspInfo.bypassReason}`;
            }
        }

        return f;
    };

    if (Array.isArray(scan.webVulnerabilityFindings)) {
        // Eliminate false-positive CSP_BYPASS when CSP is strict & not bypassable
        if (!cspInfo.isBypassable && (cspInfo.isStrictScript || cspInfo.isActive)) {
            scan.webVulnerabilityFindings = scan.webVulnerabilityFindings.filter(f => f.type !== "CSP_BYPASS_VULNERABILITY");
        }
        scan.webVulnerabilityFindings.forEach(mitigateFinding);
    }
    if (Array.isArray(scan.domFindings)) {
        scan.domFindings.forEach(mitigateFinding);
    }
    if (Array.isArray(scan.scriptIframeFindings)) {
        scan.scriptIframeFindings.forEach(mitigateFinding);
    }

    return scan;
}

function analyzeSecurityAudit() {
    const audit = {
        technologies: [],
        attackSurface: {
            hiddenInputs: [],
            disabledControls: [],
            sensitiveComments: [],
            discoveredEndpoints: []
        },
        headerCookieAudit: {
            protocol: window.location.protocol || "",
            isHttps: window.location.protocol === "https:",
            missingCsp: true,
            mixedContent: [],
            cookieHygiene: {
                totalAccessible: 0,
                insecureCookies: []
            }
        }
    };

    const pageHtml = (document.documentElement ? document.documentElement.innerHTML : "").slice(0, 200000);
    const bodyText = (document.body ? (document.body.innerText || document.body.textContent || "") : "");
    const scripts = Array.from(document.querySelectorAll("script"));
    const scriptSrcs = scripts.map(s => s.getAttribute("src") || "").filter(Boolean);

    // ==========================================
    // 1. TECHNOLOGY STACK PROFILER
    // ==========================================
    const techSignatures = [
        // CMS & Platforms
        { name: "WordPress", category: "CMS", test: () => /wp-content|wp-includes/i.test(pageHtml) || /<meta name="generator" content="WordPress/i.test(pageHtml) },
        { name: "Drupal", category: "CMS", test: () => /drupal\.js|drupalSettings/i.test(pageHtml) || /<meta name="generator" content="Drupal/i.test(pageHtml) },
        { name: "Joomla", category: "CMS", test: () => /<meta name="generator" content="Joomla/i.test(pageHtml) || /\/media\/jui\//i.test(pageHtml) },
        { name: "Shopify", category: "E-Commerce", test: () => /cdn\.shopify\.com/i.test(pageHtml) || /window\.Shopify/i.test(pageHtml) },

        // Frontend Frameworks
        { name: "React", category: "Frontend Framework", test: () => typeof window.React !== "undefined" || !!document.querySelector("[data-reactroot], [data-reactid]") || /react(?:\.production|\.development)?\.js/i.test(pageHtml) },
        { name: "Next.js", category: "Frontend Framework", test: () => !!document.querySelector("#__next") || /_next\/static/i.test(pageHtml) },
        { name: "Vue.js", category: "Frontend Framework", test: () => typeof window.Vue !== "undefined" || !!document.querySelector("[data-v-]") || /vue(?:\.runtime|\.min)?\.js/i.test(pageHtml) },
        { name: "Nuxt.js", category: "Frontend Framework", test: () => !!document.querySelector("#__nuxt") || /_nuxt\//i.test(pageHtml) },
        { name: "Angular", category: "Frontend Framework", test: () => typeof window.angular !== "undefined" || !!document.querySelector("[ng-app], [ng-controller], [ng-version]") || /angular(?:\.min)?\.js/i.test(pageHtml) },
        { name: "Svelte", category: "Frontend Framework", test: () => /svelte-/i.test(pageHtml) },

        // JavaScript & UI Libraries
        { name: "jQuery", category: "JavaScript Library", test: () => typeof window.jQuery !== "undefined" || typeof window.$ !== "undefined" || /jquery[.-]([0-9.]+)/i.test(pageHtml) },
        { name: "Bootstrap", category: "UI Framework", test: () => /bootstrap(?:\.min)?\.(?:js|css)/i.test(pageHtml) || !!document.querySelector("[class*='col-md-'], [class*='navbar-']") },
        { name: "Tailwind CSS", category: "UI Framework", test: () => !!document.querySelector("[class*='flex'], [class*='text-'], [class*='bg-'], [class*='p-']") && /tailwind/i.test(pageHtml) },

        // Web Servers & Reverse Proxies
        { name: "Apache HTTP Server", category: "Web Server", test: () => /apache\/(?:2\.[0-9]+)/i.test(bodyText) || /apache server at/i.test(bodyText) },
        { name: "Nginx", category: "Web Server", test: () => /nginx\/(?:1\.[0-9]+)/i.test(bodyText) || /nginx/i.test(bodyText) },
        { name: "Cloudflare", category: "CDN / WAF", test: () => /cloudflare/i.test(pageHtml) || /__cfduid|cf-ray/i.test(pageHtml) },

        // Backend Languages & Runtimes
        { name: "PHP", category: "Backend Runtime", test: () => /\.php\b/i.test(window.location.href) || /x-powered-by:\s*php/i.test(pageHtml) || /php version/i.test(bodyText) },
        { name: "Node.js / Express", category: "Backend Runtime", test: () => /express/i.test(pageHtml) || /connect\.sid/i.test(document.cookie) },
        { name: "Python / Django", category: "Backend Runtime", test: () => /csrftoken/i.test(document.cookie) || /django/i.test(bodyText) },
        { name: "ASP.NET", category: "Backend Runtime", test: () => /asp\.net/i.test(bodyText) || /__VIEWSTATE/i.test(pageHtml) || /\.aspx\b/i.test(window.location.href) }
    ];

    techSignatures.forEach(sig => {
        try {
            if (sig.test()) {
                audit.technologies.push({
                    name: sig.name,
                    category: sig.category,
                    confidence: "HIGH"
                });
            }
        } catch (e) {}
    });

    // ==========================================
    // 2. ATTACK SURFACE: HIDDEN INPUTS & CONTROLS
    // ==========================================
    const hiddenInputs = Array.from(document.querySelectorAll("input[type='hidden']"));
    hiddenInputs.forEach((inp, idx) => {
        if (idx < 25) { // Cap for memory/performance
            const name = inp.name || inp.id || `hidden_${idx}`;
            const form = inp.closest("form");
            const formAction = form ? (form.getAttribute("action") || "#") : "standalone";
            audit.attackSurface.hiddenInputs.push({
                name: name,
                valueSnippet: (/token|csrf|xsrf|session|auth|secret|key|password|pass|hash/i.test(name) ? "[REDACTED_TOKEN]" : (inp.value || "").slice(0, 40)),
                formAction: formAction
            });
        }
    });

    const disabledControls = Array.from(document.querySelectorAll("input:disabled, button:disabled, select:disabled"));
    disabledControls.forEach((el, idx) => {
        if (idx < 15) {
            audit.attackSurface.disabledControls.push({
                tag: el.tagName.toLowerCase(),
                name: el.name || el.id || el.textContent.trim().slice(0, 20) || "unnamed"
            });
        }
    });

    // ==========================================
    // 3. SENSITIVE HTML COMMENTS INSPECTION
    // ==========================================
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let commentMatch;
    let commentCount = 0;
    while ((commentMatch = commentRegex.exec(pageHtml)) !== null && commentCount < 10) {
        const commentContent = commentMatch[1].trim();
        if (/todo|fixme|password|passwd|admin|debug|token|secret|api_key|auth|internal|db_|config/i.test(commentContent)) {
            audit.attackSurface.sensitiveComments.push(commentContent.slice(0, 150).replace(/\s+/g, " "));
            commentCount++;
        }
    }

    // ==========================================
    // 4. DISCOVERED API ENDPOINTS & ROUTES
    // ==========================================
    const endpointRegex = /(?:["']|\b)(\/(?:api|v[1-9]|rest|graphql|auth|oauth|users|admin|account|login|dashboard)\/[a-zA-Z0-9_\-\/]+)(?:["']|\b)/g;
    const discoveredSet = new Set();

    // Scan inline scripts and links
    let epMatch;
    while ((epMatch = endpointRegex.exec(pageHtml)) !== null) {
        const ep = epMatch[1];
        if (ep && !ep.endsWith(".js") && !ep.endsWith(".css") && !ep.endsWith(".png") && discoveredSet.size < 20) {
            discoveredSet.add(ep);
        }
    }
    audit.attackSurface.discoveredEndpoints = Array.from(discoveredSet);

    // ==========================================
    // 5. SECURITY HEADERS & COOKIE HYGIENE
    // ==========================================
    // Check for active CSP (HTTP header or meta tag)
    const detectedCsp = typeof detectAndParseActiveCsp === "function" ? detectAndParseActiveCsp() : null;
    if (detectedCsp && detectedCsp.isActive) {
        audit.headerCookieAudit.csp = detectedCsp;
        audit.headerCookieAudit.missingCsp = false;
    } else {
        audit.headerCookieAudit.missingCsp = true;
    }

    // Mixed Content checks (HTTP assets on HTTPS origin)
    if (audit.headerCookieAudit.isHttps) {
        const insecureElements = Array.from(document.querySelectorAll("script[src^='http://'], link[rel='stylesheet'][href^='http://'], img[src^='http://'], iframe[src^='http://']"));
        audit.headerCookieAudit.mixedContent = insecureElements.slice(0, 10).map(el => {
            return (el.src || el.href || "").slice(0, 100);
        });
    }

    // Cookie Inspection (Cookies accessible by JavaScript lack HttpOnly)
    try {
        const rawCookies = document.cookie ? document.cookie.split(";") : [];
        audit.headerCookieAudit.cookieHygiene.totalAccessible = rawCookies.length;
        rawCookies.forEach(c => {
            const parts = c.trim().split("=");
            const cookieName = (parts[0] || "").trim();
            if (/session|jwt|token|auth|id|user|admin|key/i.test(cookieName)) {
                audit.headerCookieAudit.cookieHygiene.insecureCookies.push({
                    name: cookieName,
                    warning: "Accessible to client scripts (Missing HttpOnly flag)"
                });
            }
        });
    } catch (e) {}

    return audit;
}

/**
 * Standard CVSS v3.1 Scoring, Vector & Ethical Verification Guide repository
 * @param {string} vulnType Standardized vulnerability type
 * @returns {Object} CVSS score, vector, and verification methodology
 */
function getVulnerabilityCvssAndGuide(vulnType) {
    if (typeof getRegisteredVulnerability === "function") {
        const reg = getRegisteredVulnerability(vulnType);
        if (reg) {
            return {
                cvssScore: reg.cvssScore || "5.0",
                cvssSeverity: reg.severity || "MEDIUM",
                cvssVector: reg.cvssVector || "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                guide: {
                    title: `${reg.title} Verification Guide`,
                    steps: reg.verificationSteps || [
                        "1. Observe the flagged DOM element or URL pattern.",
                        "2. Validate compliance with OWASP Top 10 guidelines.",
                        "3. Verify remediation in staging environment."
                    ]
                }
            };
        }
    }

    const registry = {
        BRUTE_FORCE_SUSCEPTIBLE_LOGIN: {
            cvssScore: "7.5",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            guide: {
                title: "Brute-Force Vulnerability Verification Guide",
                steps: [
                    "1. Observe login form behavior under rapid consecutive attempts.",
                    "2. Check if rate-limiting or lockout mechanisms trigger after failed attempts.",
                    "3. Verify that passwords are submitted via encrypted POST rather than GET."
                ]
            }
        },
        CROSS_SITE_REQUEST_FORGERY: {
            cvssScore: "8.8",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            guide: {
                title: "CSRF Vulnerability Verification Guide",
                steps: [
                    "1. Inspect state-changing forms (e.g. password change) for unpredictable anti-CSRF tokens.",
                    "2. Check if requests succeed when submitted from external origins or without token parameters.",
                    "3. Verify server enforcement of SameSite=Lax/Strict cookie attributes."
                ]
            }
        },
        UNRESTRICTED_FILE_UPLOAD: {
            cvssScore: "9.8",
            cvssSeverity: "CRITICAL",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            guide: {
                title: "Unrestricted File Upload Verification Guide",
                steps: [
                    "1. Inspect file upload form accept attributes and client-side constraints.",
                    "2. In an authorized testing environment, verify if server accepts and executes non-image file extensions.",
                    "3. Verify upload directory script execution restrictions (e.g. php_flag engine off)."
                ]
            }
        },
        INSECURE_CAPTCHA_BYPASS: {
            cvssScore: "6.5",
            cvssSeverity: "MEDIUM",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            guide: {
                title: "Insecure CAPTCHA Logic Bypass Guide",
                steps: [
                    "1. Inspect multi-step parameters (e.g. step=1 vs step=2) during form submission.",
                    "2. Check if submitting step=2 directly bypasses CAPTCHA validation.",
                    "3. Verify that CAPTCHA validation is enforced strictly server-side."
                ]
            }
        },
        BLIND_SQL_INJECTION_ENDPOINT: {
            cvssScore: "8.6",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            guide: {
                title: "Blind SQL Injection Verification Guide",
                steps: [
                    "1. Identify database query parameter (e.g. ?id=1).",
                    "2. Test boolean conditions (e.g. id=1' AND 1=1# vs id=1' AND 1=2#) to observe differences in page responses.",
                    "3. Test time-based response delays in authorized staging environments (e.g. ' OR SLEEP(2)#)."
                ]
            }
        },
        WEAK_SESSION_ID_GENERATION: {
            cvssScore: "8.1",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            guide: {
                title: "Weak Session ID Verification Guide",
                steps: [
                    "1. Inspect session cookie values across multiple sequential login attempts.",
                    "2. Check if tokens increment sequentially (e.g. 1, 2, 3) or use low-entropy timestamps.",
                    "3. Verify that CSPRNG generators (random_bytes) are used for session generation."
                ]
            }
        },
        DOM_XSS_ENDPOINT: {
            cvssScore: "7.2",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            guide: {
                title: "DOM XSS Verification Guide",
                steps: [
                    "1. Trace client script inputs from location.search/hash to DOM execution sinks.",
                    "2. Verify whether characters like <, >, &quot;, &apos; are filtered before insertion into the DOM.",
                    "3. Verify replacement of innerHTML with textContent or DOMPurify."
                ]
            }
        },
        REFLECTED_XSS_ENDPOINT: {
            cvssScore: "7.2",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            guide: {
                title: "Reflected XSS Verification Guide",
                steps: [
                    "1. Submit benign marker strings into input parameter and inspect HTML source.",
                    "2. Check if characters are reflected without HTML entity encoding.",
                    "3. Verify server-side htmlspecialchars(input, ENT_QUOTES, 'UTF-8')."
                ]
            }
        },
        STORED_XSS_ENDPOINT: {
            cvssScore: "8.0",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            guide: {
                title: "Stored XSS Verification Guide",
                steps: [
                    "1. Submit benign HTML tags (<b>test</b>) in comment/message fields.",
                    "2. Reload page to verify if tags persist and render as active HTML elements.",
                    "3. Verify stored entity encoding and Content Security Policy enforcement."
                ]
            }
        },
        CSP_BYPASS_VULNERABILITY: {
            cvssScore: "6.5",
            cvssSeverity: "MEDIUM",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            guide: {
                title: "CSP Policy Bypass Verification Guide",
                steps: [
                    "1. Inspect Content-Security-Policy response headers.",
                    "2. Check for presence of 'unsafe-inline', 'unsafe-eval', or wildcard origins.",
                    "3. Verify migration to nonce-based or strict hash-based CSP."
                ]
            }
        },
        CLIENT_SIDE_SECURITY_BYPASS: {
            cvssScore: "5.3",
            cvssSeverity: "MEDIUM",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            guide: {
                title: "Client-Side Logic Bypass Verification Guide",
                steps: [
                    "1. Inspect inline JavaScript functions calculating tokens or validation flags.",
                    "2. Check if submitting arbitrary tokens directly to server endpoint succeeds.",
                    "3. Verify server-side re-computation and enforcement of business logic."
                ]
            }
        },
        DATABASE_SETUP_EXPOSURE: {
            cvssScore: "7.5",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
            guide: {
                title: "Database Setup Exposure Verification Guide",
                steps: [
                    "1. Verify if /setup.php is accessible without authentication.",
                    "2. Verify server configuration blocking direct web access to installation scripts."
                ]
            }
        },
        SQL_INJECTION_ENDPOINT: {
            cvssScore: "8.6",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            guide: {
                title: "SQL Injection Verification Guide (Ethical Auditor)",
                steps: [
                    "1. Confirm Input Parameter: Identify the parameter transmitting data to the database (e.g. GET /vulnerabilities/sqli/?id=1).",
                    "2. Non-Destructive Payload Verification: In an authorized testing environment, submit an arithmetic anomaly test (e.g. id=1' AND 1=1-- vs id=1' AND 1=2--) to verify boolean reflection changes.",
                    "3. Error-Based Signature Check: Observe if database engine error strings (MySQL, PostgreSQL) leak into DOM responses.",
                    "4. Remediation Verification: Verify that replacing dynamic concatenation with PDO prepared statements renders metacharacters harmless as literal string data."
                ]
            }
        },
        POTENTIAL_SQL_INJECTION_FORM: {
            cvssScore: "8.6",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            guide: {
                title: "Form SQL Injection Verification Guide",
                steps: [
                    "1. Inspect form inputs accepting query IDs or search strings without HTML5 validation patterns.",
                    "2. Submit benign single quote (') to verify if input is sanitized or rejected.",
                    "3. Verify backend enforcement of parameterized prepared statements."
                ]
            }
        },
        SQL_INJECTION_ERROR: {
            cvssScore: "9.8",
            cvssSeverity: "CRITICAL",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            guide: {
                title: "Active Database Error Leak Verification",
                steps: [
                    "1. Review exposed DOM text for exact SQL error messages disclosing database tables/columns.",
                    "2. Verify server-side configuration: Ensure display_errors = Off in php.ini."
                ]
            }
        },
        PHP_CGI_ARGUMENT_INJECTION: {
            cvssScore: "9.8",
            cvssSeverity: "CRITICAL",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            guide: {
                title: "PHP CGI Argument Injection (CVE-2024-4577) Guide",
                steps: [
                    "1. Check Windows / Apache environment running PHP in CGI or Action mode.",
                    "2. Inspect query parameters for soft-hyphen (%ad) or -d command line flags.",
                    "3. Remediation Verification: Upgrade PHP to 8.3.8+, 8.2.20+, or 8.1.29+, and verify Apache rewrite rules block %ad queries."
                ]
            }
        },
        XSS_TARGET_ENDPOINT: {
            cvssScore: "7.2",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            guide: {
                title: "Cross-Site Scripting (XSS) Verification Guide",
                steps: [
                    "1. Input benign boundary markers (e.g. test<>\"') into parameter and inspect page source.",
                    "2. Verify whether characters are escaped as &lt;&gt;&quot; or reflected verbatim.",
                    "3. Remediation Verification: Ensure htmlspecialchars(string, ENT_QUOTES, 'UTF-8') and CSP script-src 'self' are active."
                ]
            }
        },
        COMMAND_INJECTION_ENDPOINT: {
            cvssScore: "9.8",
            cvssSeverity: "CRITICAL",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            guide: {
                title: "OS Command Injection Verification Guide",
                steps: [
                    "1. Test parameter accepting hostnames or filenames.",
                    "2. Verify if shell metacharacters (;, |, &&) trigger execution anomalies.",
                    "3. Remediation: Verify parameter array execution (execFile) without shell spawning."
                ]
            }
        },
        FILE_INCLUSION_ENDPOINT: {
            cvssScore: "8.6",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            guide: {
                title: "Path Traversal / Local File Inclusion Guide",
                steps: [
                    "1. Observe file parameter handling (e.g. ?page=include.php).",
                    "2. Verify if directory traversal characters (../) are rejected by basename() sanitization.",
                    "3. Ensure allow_url_include is set to Off in php.ini."
                ]
            }
        },
        POTENTIAL_SSRF_PARAMETER: {
            cvssScore: "8.6",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            guide: {
                title: "Server-Side Request Forgery (SSRF) Verification",
                steps: [
                    "1. Inspect URL parameters fetching remote resources.",
                    "2. Verify that loopback (127.0.0.1) and cloud metadata IPs (169.254.169.254) are rejected by server-side resolution filters.",
                    "3. Verify domain whitelist enforcement before making outbound HTTP connections."
                ]
            }
        },
        EXPOSED_ADMIN_INTERFACE: {
            cvssScore: "7.5",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            guide: {
                title: "Exposed Administrative Interface Verification",
                steps: [
                    "1. Verify if admin endpoint requires VPN, IP allowlist, or MFA.",
                    "2. Ensure web server blocks direct access to dotfiles (.git, .env)."
                ]
            }
        },
        DIRECTORY_LISTING_ENABLED: {
            cvssScore: "5.3",
            cvssSeverity: "MEDIUM",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            guide: {
                title: "Directory Listing Verification Guide",
                steps: [
                    "1. Navigate to directory paths lacking index.html to observe if file trees are displayed.",
                    "2. Remediation: Set Options -Indexes in Apache or autoindex off in Nginx."
                ]
            }
        },
        INSECURE_PASSWORD_TRANSMISSION: {
            cvssScore: "7.4",
            cvssSeverity: "HIGH",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            guide: {
                title: "Insecure Password Transmission Verification",
                steps: [
                    "1. Check form method attribute: MUST be POST, never GET.",
                    "2. Ensure protocol is HTTPS with active HSTS headers."
                ]
            }
        },
        MISSING_CSRF_PROTECTION: {
            cvssScore: "6.5",
            cvssSeverity: "MEDIUM",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            guide: {
                title: "Cross-Site Request Forgery (CSRF) Verification",
                steps: [
                    "1. Inspect state-changing POST forms for unpredictable tokens.",
                    "2. Verify SameSite=Lax/Strict cookie attributes and token validation."
                ]
            }
        }
    };

    return registry[vulnType] || {
        cvssScore: "5.0",
        cvssSeverity: "MEDIUM",
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        guide: {
            title: "Security Finding Verification Guide",
            steps: [
                "1. Observe the flagged DOM element or URL pattern.",
                "2. Validate compliance with OWASP Top 10 guidelines.",
                "3. Verify remediation in staging environment."
            ]
        }
    };
}


const _globalAuditorScope = typeof window !== "undefined" ? window : (typeof self !== "undefined" ? self : globalThis);
_globalAuditorScope.parseCspString = parseCspString;
_globalAuditorScope.detectAndParseActiveCsp = detectAndParseActiveCsp;
_globalAuditorScope.applyCspMitigations = applyCspMitigations;

function scanPage(reason = "page-load") {
    try {
        const currentURL = window.location.href;

        // Detect active Content Security Policy (meta tag or window headers)
        let activeCsp = null;
        try {
            if (typeof detectAndParseActiveCsp === "function") {
                activeCsp = detectAndParseActiveCsp();
            }
        } catch (e) {
            activeCsp = null;
        }

        // ===============================
        // BASIC PAGE INFORMATION
        // ===============================
        const result = {
            url: currentURL,
            title: document.title || "",
            forms: document.forms?.length || 0,
            scripts: document.scripts?.length || 0,
            iframes: document.querySelectorAll("iframe").length,
            timestamp: new Date().toISOString(),
            reason: reason
        };

        // ===============================
        // URL SECURITY ANALYSIS
        // ===============================
        let urlFindings = [];
        try {
            urlFindings = analyzeURL(currentURL);
        } catch (e) {
            console.error("ThreatLens: analyzeURL error:", e);
        }
        result.urlFindings = urlFindings;

        // ===============================
        // DOM SECURITY ANALYSIS
        // ===============================
        let domFindings = [];
        try {
            domFindings = analyzeDOM(activeCsp);
        } catch (e) {
            console.error("ThreatLens: analyzeDOM error:", e);
        }
        result.domFindings = domFindings;

        // ===============================
        // FORM SECURITY ANALYSIS
        // ===============================
        let formFindings = [];
        try {
            formFindings = analyzeFormSecurity();
        } catch (e) {
            console.error("ThreatLens: analyzeFormSecurity error:", e);
        }
        result.formFindings = formFindings;

        // ===============================
        // SCRIPT & IFRAME SECURITY
        // ===============================
        let scriptIframeFindings = [];
        try {
            scriptIframeFindings = analyzeScriptIframeSecurity(activeCsp);
        } catch (e) {
            console.error("ThreatLens: analyzeScriptIframeSecurity error:", e);
        }
        result.scriptIframeFindings = scriptIframeFindings;

        // ===============================
        // SENSITIVE DATA SECURITY
        // ===============================
        let sensitiveDataFindings = [];
        try {
            sensitiveDataFindings = analyzeSensitiveData();
        } catch (e) {
            console.error("ThreatLens: analyzeSensitiveData error:", e);
        }
        result.sensitiveDataFindings = sensitiveDataFindings;

        // ===============================
        // WEB VULNERABILITY SECURITY (SQLi, XSS, EXEC, LFI)
        // ===============================
        let webVulnerabilityFindings = [];
        try {
            if (typeof analyzeWebVulnerabilities === "function") {
                webVulnerabilityFindings = analyzeWebVulnerabilities(activeCsp);
            }
        } catch (e) {
            console.error("ThreatLens: analyzeWebVulnerabilities error:", e);
        }
        result.webVulnerabilityFindings = webVulnerabilityFindings;

        // ===============================
        // PROMPT INJECTION SECURITY
        // ===============================
        let promptInjectionFindings = [];
        try {
            promptInjectionFindings = analyzePromptInjection();
        } catch (e) {
            console.error("ThreatLens: analyzePromptInjection error:", e);
        }
        result.promptInjectionFindings = promptInjectionFindings;

        // ===============================
        // PHISHING SECURITY
        // ===============================
        let phishingRisk = { score: 0, risk: "LOW", signals: [] };
        try {
            phishingRisk = analyzePhishingRisk(
                urlFindings,
                domFindings,
                formFindings,
                scriptIframeFindings
            );
        } catch (e) {
            console.error("ThreatLens: analyzePhishingRisk error:", e);
        }
        result.phishingRisk = phishingRisk;

        // ===============================
        // SECURITY AUDITOR & RECON SUITE
        // ===============================
        let securityAudit = null;
        try {
            if (typeof analyzeSecurityAudit === "function") {
                securityAudit = analyzeSecurityAudit();
            }
        } catch (e) {
            console.error("ThreatLens: analyzeSecurityAudit error:", e);
        }
        result.securityAudit = securityAudit;

        // ===============================
        // APPLY CSP MITIGATIONS (BEFORE OVERALL RISK CALCULATION)
        // ===============================
        if (activeCsp && activeCsp.isActive && typeof applyCspMitigations === "function") {
            try {
                applyCspMitigations(result, activeCsp);
            } catch (e) {
                console.error("ThreatLens: applyCspMitigations error:", e);
            }
        }

        // ===============================
        // RISK ENGINE
        // ===============================
        const allFindings = [
            ...normalizeFindings(webVulnerabilityFindings, "WEB_VULNERABILITY"),
            ...normalizeFindings(urlFindings, "URL"),
            ...normalizeFindings(domFindings, "DOM"),
            ...normalizeFindings(formFindings, "FORM"),
            ...normalizeFindings(scriptIframeFindings, "SCRIPT_IFRAME"),
            ...normalizeFindings(sensitiveDataFindings, "SENSITIVE_DATA"),
            ...normalizeFindings(promptInjectionFindings, "PROMPT_INJECTION")
        ];

        let riskResult = { level: "SAFE", reasons: ["No significant security indicators detected"] };
        try {
            riskResult = calculateOverallRisk(allFindings);
        } catch (e) {
            console.error("ThreatLens: calculateOverallRisk error:", e);
        }
        result.risk = riskResult;

        if (!chrome.runtime?.id) {
            return result;
        }

        try {
            chrome.runtime.sendMessage(
                {
                    type: "SCAN_RESULT",
                    data: result
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.warn(
                            "ThreatLens: Message delivery:",
                            chrome.runtime.lastError.message
                        );
                        return;
                    }
                }
            );
        } catch (msgErr) {
            console.warn("ThreatLens: Failed to send SCAN_RESULT:", msgErr.message);
        }

        return result;
    } catch (err) {
        console.error("ThreatLens: scanPage critical error:", err);
    }
}

// Listen for on-demand scan requests (from popup or dashboard)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request && (request.action === "REQUEST_SCAN" || request.type === "REQUEST_SCAN")) {
        const res = scanPage("on-demand");
        sendResponse({ success: true, data: res });
        return true;
    }
});

// Query live HTTP response headers (e.g. CSP) from background service worker
try {
    if (chrome.runtime?.id) {
        chrome.runtime.sendMessage({ type: "GET_SECURITY_HEADERS" }, (resp) => {
            if (resp && resp.headers) {
                if (typeof window !== "undefined") {
                    window.__threatlens_headers = resp.headers;
                }
                const currentCsp = typeof detectAndParseActiveCsp === "function" ? detectAndParseActiveCsp() : null;
                if (currentCsp && currentCsp.isActive) {
                    scanPage("headers-loaded");
                }
            }
        });
    }
} catch (e) {}

// START INITIAL SCAN
scanPage("page-load");

// ===============================
// MUTATION OBSERVER
// ===============================

let mutationTimer = null;
let scanScheduled = false;

function isSecurityRelevantMutation(mutations) {

    return mutations.some((mutation) => {

        if (
            mutation.type !== "childList" ||
            mutation.addedNodes.length === 0
        ) {
            return false;
        }

        for (const node of mutation.addedNodes) {

            if (node.nodeType !== Node.ELEMENT_NODE) {
                continue;
            }

            const element =
                /** @type {Element} */ (node);

            // Security-relevant elements
            if (
                element.matches(
                    "form, input, textarea, iframe, script, a, button"
                )
            ) {
                return true;
            }

            // Check descendants
            if (
                element.querySelector(
                    "form, input, textarea, iframe, script, a, button"
                )
            ) {
                return true;
            }
        }

        return false;
    });
}

const domObserver =
    new MutationObserver((mutations) => {

        if (
            !isSecurityRelevantMutation(
                mutations
            )
        ) {
            return;
        }

        clearTimeout(mutationTimer);

        mutationTimer = setTimeout(() => {

            if (scanScheduled) {
                return;
            }

            scanScheduled = true;

            scanPage("dom-mutation");

            scanScheduled = false;

        }, 500);
    });

if (document.documentElement) {

    domObserver.observe(
        document.documentElement,
        {
            childList: true,
            subtree: true
        }
    );
}
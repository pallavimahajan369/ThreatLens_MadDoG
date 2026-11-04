function scanPage(reason = "page-load") {
    try {
        const currentURL = window.location.href;

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
            console.error("SentinelAI: analyzeURL error:", e);
        }
        result.urlFindings = urlFindings;

        // ===============================
        // DOM SECURITY ANALYSIS
        // ===============================
        let domFindings = [];
        try {
            domFindings = analyzeDOM();
        } catch (e) {
            console.error("SentinelAI: analyzeDOM error:", e);
        }
        result.domFindings = domFindings;

        // ===============================
        // FORM SECURITY ANALYSIS
        // ===============================
        let formFindings = [];
        try {
            formFindings = analyzeFormSecurity();
        } catch (e) {
            console.error("SentinelAI: analyzeFormSecurity error:", e);
        }
        result.formFindings = formFindings;

        // ===============================
        // SCRIPT & IFRAME SECURITY
        // ===============================
        let scriptIframeFindings = [];
        try {
            scriptIframeFindings = analyzeScriptIframeSecurity();
        } catch (e) {
            console.error("SentinelAI: analyzeScriptIframeSecurity error:", e);
        }
        result.scriptIframeFindings = scriptIframeFindings;

        // ===============================
        // SENSITIVE DATA SECURITY
        // ===============================
        let sensitiveDataFindings = [];
        try {
            sensitiveDataFindings = analyzeSensitiveData();
        } catch (e) {
            console.error("SentinelAI: analyzeSensitiveData error:", e);
        }
        result.sensitiveDataFindings = sensitiveDataFindings;

        // ===============================
        // PROMPT INJECTION SECURITY
        // ===============================
        let promptInjectionFindings = [];
        try {
            promptInjectionFindings = analyzePromptInjection();
        } catch (e) {
            console.error("SentinelAI: analyzePromptInjection error:", e);
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
            console.error("SentinelAI: analyzePhishingRisk error:", e);
        }
        result.phishingRisk = phishingRisk;

        // ===============================
        // RISK ENGINE
        // ===============================
        const allFindings = [
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
            console.error("SentinelAI: calculateOverallRisk error:", e);
        }
        result.risk = riskResult;

        console.log("SentinelAI Scan Result:", result);

        try {
            chrome.runtime.sendMessage(
                {
                    type: "SCAN_RESULT",
                    data: result
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.warn(
                            "SentinelAI: Message delivery:",
                            chrome.runtime.lastError.message
                        );
                        return;
                    }
                    console.log(
                        "SentinelAI: Service Worker response:",
                        response
                    );
                }
            );
        } catch (msgErr) {
            console.warn("SentinelAI: Failed to send SCAN_RESULT:", msgErr.message);
        }

        return result;
    } catch (err) {
        console.error("SentinelAI: scanPage critical error:", err);
    }
}

// Listen for on-demand scan requests (from popup or dashboard)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request && (request.action === "REQUEST_SCAN" || request.type === "REQUEST_SCAN")) {
        console.log("SentinelAI: Handling on-demand REQUEST_SCAN");
        const res = scanPage("on-demand");
        sendResponse({ success: true, data: res });
        return true;
    }
});

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

            console.log(
                "SentinelAI: Relevant DOM mutation detected. Re-scanning..."
            );

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

    console.log(
        "SentinelAI: MutationObserver started"
    );
}
function scanPage(reason = "page-load") {

    const currentURL = window.location.href;


    // ===============================
    // BASIC PAGE INFORMATION
    // ===============================

    const result = {

        url: currentURL,

        title: document.title,

        forms: document.forms.length,

        scripts: document.scripts.length,

        iframes:
            document.querySelectorAll("iframe").length,

        timestamp:
            new Date().toISOString(),

        reason: reason
    };


    // ===============================
    // URL SECURITY ANALYSIS
    // ===============================

    const urlFindings =
        analyzeURL(currentURL);


    result.urlFindings = urlFindings;

    const domFindings = analyzeDOM();

    result.domFindings = domFindings;

    const formFindings = analyzeFormSecurity();

    result.formFindings = formFindings;

    const scriptIframeFindings =
        analyzeScriptIframeSecurity();

    result.scriptIframeFindings =
        scriptIframeFindings;

    const sensitiveDataFindings =
        analyzeSensitiveData();

    result.sensitiveDataFindings =
        sensitiveDataFindings;

    const promptInjectionFindings =
        analyzePromptInjection();

    result.promptInjectionFindings =
        promptInjectionFindings;
    
    
    const phishingRisk =
        analyzePhishingRisk(
            urlFindings,
            domFindings,
            formFindings,
            scriptIframeFindings
        );

    result.phishingRisk =
        phishingRisk;

    // ===============================
    // RISK ENGINE
    // ===============================

    const allFindings = [

        ...normalizeFindings(
            urlFindings,
            "URL"
        ),

        ...normalizeFindings(
            domFindings,
            "DOM"
        ),

        ...normalizeFindings(
            formFindings,
            "FORM"
        ),

        ...normalizeFindings(
            scriptIframeFindings,
            "SCRIPT_IFRAME"
        ),

        ...normalizeFindings(
            sensitiveDataFindings,
            "SENSITIVE_DATA"
        ),

        ...normalizeFindings(
            promptInjectionFindings,
            "PROMPT_INJECTION"
        )

    ];


    const riskResult =
        calculateOverallRisk(
            allFindings
        );


    result.risk = riskResult;


    console.log(
        "SentinelAI Risk Result:",
        riskResult
    );

    

    

    // ===============================
    // CONSOLE
    // ===============================

    console.log(
        "SentinelAI Scan Result:",
        result
    );

    chrome.runtime.sendMessage({
        type: "SCAN_RESULT",
        data: result
    });

    console.log(
        "SentinelAI: SCAN_RESULT message sent to Service Worker"
    );


}

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
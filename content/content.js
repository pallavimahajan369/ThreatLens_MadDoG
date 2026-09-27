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


    // ===============================
    // SEND TO SERVICE WORKER
    // ===============================

    chrome.runtime.sendMessage({

        type: "SCAN_RESULT",

        data: result

    });

}

// START INITIAL SCAN
scanPage("page-load");
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
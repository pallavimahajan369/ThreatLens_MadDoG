console.log("SentinelAI loaded");

let lastUrl = window.location.href;


// ------------------------------------
// PAGE SCAN
// ------------------------------------

function scanPage(reason = "initial") {

    const result = {
        url: window.location.href,
        title: document.title,
        forms: document.forms.length,
        scripts: document.scripts.length,
        iframes: document.querySelectorAll("iframe").length,
        timestamp: new Date().toISOString(),
        reason: reason
    };

    console.log("SentinelAI Scan Result:", result);


    // Send result safely to Service Worker

    try {

        chrome.runtime.sendMessage(
            {
                type: "SCAN_RESULT",
                data: result
            },
            () => {

                if (chrome.runtime.lastError) {

                    console.log(
                        "SentinelAI message error:",
                        chrome.runtime.lastError.message
                    );

                }

            }
        );

    } catch (error) {

        console.log(
            "SentinelAI communication error:",
            error.message
        );

    }
}


// ------------------------------------
// INITIAL AUTOMATIC SCAN
// ------------------------------------

scanPage("page-load");


// ------------------------------------
// DOM CHANGE MONITORING
// ------------------------------------

let scanTimer;

const observer = new MutationObserver(() => {

    clearTimeout(scanTimer);

    scanTimer = setTimeout(() => {

        scanPage("dom-change");

    }, 1000);

});


observer.observe(
    document.documentElement,
    {
        childList: true,
        subtree: true
    }
);


// ------------------------------------
// URL CHANGE DETECTION
// ------------------------------------

setInterval(() => {

    const currentUrl = window.location.href;


    if (currentUrl !== lastUrl) {

        lastUrl = currentUrl;

        console.log(
            "SentinelAI detected URL change"
        );

        scanPage("url-change");

    }

}, 1000);

document.addEventListener("DOMContentLoaded", () => {

    const currentUrlElement =
        document.getElementById("currentUrl");

    const riskLevelElement =
        document.getElementById("riskLevel");

    const riskIconElement =
        document.getElementById("riskIcon");

    const websiteFindingsElement =
        document.getElementById("websiteFindings");

    const extensionFindingsElement =
        document.getElementById("extensionFindings");

    const aiStatusElement =
        document.getElementById("aiStatus");

    const privacyStatusElement =
        document.getElementById("privacyStatus");


    /*
     * Get active tab
     */
    chrome.tabs.query(
        {
            active: true,
            currentWindow: true
        },
        (tabs) => {

            if (!tabs || !tabs.length) {
                return;
            }

            const currentTab = tabs[0];

            const tabId = currentTab.id;

            const currentUrl =
                currentTab.url || "Unknown";


            /*
             * Display current website
             */
            if (currentUrlElement) {

                currentUrlElement.textContent =
                    currentUrl;
            }


            /*
             * Read current scan + extension scan
             */
            chrome.storage.local.get(
                [
                    `scan_${tabId}`,
                    "extensionScan",
                    "privacyMode"
                ],
                (result) => {

                    const scan =
                        result[`scan_${tabId}`];

                    const extensionScan =
                        result.extensionScan || [];


                    /*
                     * Website risk
                     */
                    const websiteRisk =
                        scan?.risk?.level ||
                        "LOW";


                    /*
                     * Overall risk
                     *
                     * Extension risk should not
                     * automatically increase
                     * website/overall risk.
                     */
                    const overallRisk =
                        scan?.overallRisk ||
                        websiteRisk;


                    if (riskLevelElement) {

                        riskLevelElement.textContent =
                            `${overallRisk} RISK`;
                    }


                    /*
                     * Risk icon
                     */
                    if (riskIconElement) {

                        if (
                            overallRisk === "CRITICAL" ||
                            overallRisk === "HIGH"
                        ) {

                            riskIconElement.textContent =
                                "🔴";

                        } else if (
                            overallRisk === "MEDIUM"
                        ) {

                            riskIconElement.textContent =
                                "🟠";

                        } else if (
                            overallRisk === "LOW"
                        ) {

                            riskIconElement.textContent =
                                "🟡";

                        } else {

                            riskIconElement.textContent =
                                "🟢";
                        }
                    }


                    /*
                     * Website findings
                     */
                    const websiteFindings = [

                        ...(scan?.urlFindings || []),

                        ...(scan?.domFindings || []),

                        ...(scan?.formFindings || []),

                        ...(scan?.scriptIframeFindings || []),

                        ...(scan?.sensitiveDataFindings || []),

                        ...(scan?.promptInjectionFindings || [])

                    ];


                    if (websiteFindingsElement) {

                        websiteFindingsElement.textContent =
                            websiteFindings.length;
                    }


                    /*
                     * Extension findings
                     */
                    let totalExtensionFindings = 0;

                    extensionScan.forEach(
                        (extension) => {

                            totalExtensionFindings +=
                                (
                                    extension.findings || []
                                ).length;

                        }
                    );


                    if (extensionFindingsElement) {

                        extensionFindingsElement.textContent =
                            totalExtensionFindings;
                    }


                    /*
                     * AI status
                     */
                    if (aiStatusElement) {

                        aiStatusElement.textContent =
                            "ON";
                    }


                    /*
                     * Privacy Mode status
                     */
                    const privacyMode =
                        result.privacyMode === true;


                    if (privacyStatusElement) {

                        privacyStatusElement.textContent =
                            privacyMode
                                ? "ON"
                                : "OFF";

                        privacyStatusElement.className =
                            privacyMode
                                ? "enabled"
                                : "disabled";
                    }

                }
            );

        }
    );


    /*
     * View Details
     */
    const detailsButton =
        document.getElementById("detailsBtn");


    if (detailsButton) {

        detailsButton.addEventListener(
            "click",
            () => {

                chrome.tabs.query(
                    {
                        active: true,
                        currentWindow: true
                    },
                    (tabs) => {

                        if (!tabs || !tabs.length) {
                            return;
                        }

                        const currentTab =
                            tabs[0];


                        const dashboardUrl =
                            chrome.runtime.getURL(
                                "dashboard/dashboard.html"
                            ) +
                            "?tabId=" +
                            currentTab.id +
                            "&url=" +
                            encodeURIComponent(
                                currentTab.url || ""
                            );


                        chrome.tabs.create({
                            url: dashboardUrl
                        });

                    }
                );

            }
        );

    }

});


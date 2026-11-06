console.log("ThreatLens Popup script loaded");

const informationalTypes = [
    "NO_SUSPICIOUS_DOM_PATTERN",
    "NO_FORM_SECURITY_ISSUE",
    "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
    "NO_SENSITIVE_DATA",
    "NO_PROMPT_INJECTION",
    "NO_SUSPICIOUS_URL_PATTERN"
];

function isRestrictedUrl(url) {
    if (!url) return false;
    const lower = url.toLowerCase();
    return (
        lower.startsWith("chrome://") ||
        lower.startsWith("chrome-extension://") ||
        lower.startsWith("edge://") ||
        lower.startsWith("about:") ||
        lower.startsWith("devtools://") ||
        lower.startsWith("view-source:") ||
        lower.includes("chromewebstore.google.com") ||
        lower.includes("chrome.google.com/webstore")
    );
}

function isSamePage(urlA, urlB) {
    if (!urlA || !urlB) return false;
    try {
        const a = new URL(urlA);
        const b = new URL(urlB);
        return a.origin === b.origin;
    } catch (e) {
        return urlA === urlB;
    }
}

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

    const detailsButton =
        document.getElementById("detailsBtn");

    function renderPopup(liveScan = null) {
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
                const currentUrl = currentTab.url || "Unknown";
                const isRestricted = isRestrictedUrl(currentUrl);

                /*
                 * Display current website URL
                 */
                if (currentUrlElement) {
                    currentUrlElement.textContent = currentUrl;
                }

                chrome.storage.local.get(
                    [
                        `scan_${tabId}`,
                        "lastScan",
                        "extensionScan",
                        "privacyMode",
                        "aiEnabled",
                        "aiConsent"
                    ],
                    (result) => {

                        let scan = liveScan;
                        if (!scan) {
                            const tabScan = result[`scan_${tabId}`];
                            // Only use tabScan if it matches current page origin
                            if (tabScan && (!tabScan.url || isSamePage(tabScan.url, currentUrl))) {
                                scan = tabScan;
                            }
                        }
                        // Only fallback to lastScan if it genuinely belongs to this website
                        if (!scan && result.lastScan) {
                            if (!isRestricted && isSamePage(result.lastScan.url, currentUrl)) {
                                scan = result.lastScan;
                            }
                        }

                        // If not scanned yet or URL changed, request live scan from tab content script
                        if (!scan && !isRestricted && tabId) {
                            try {
                                chrome.tabs.sendMessage(
                                    tabId,
                                    { action: "REQUEST_SCAN" },
                                    (resp) => {
                                        if (chrome.runtime.lastError) {
                                            // Tab content script not reachable yet
                                        } else if (resp && resp.data) {
                                            renderPopup(resp.data);
                                        }
                                    }
                                );
                            } catch (e) {
                                // Ignore message delivery errors
                            }
                        }

                        /*
                         * Website risk & Overall risk
                         */
                        const websiteRisk =
                            scan?.risk?.level ||
                            (isRestricted ? "SAFE" : "SAFE");

                        const overallRisk =
                            scan?.overallRisk ||
                            websiteRisk;

                        if (riskLevelElement) {
                            if (isRestricted) {
                                riskLevelElement.textContent = "SYSTEM PROTECTED";
                            } else if (overallRisk === "SAFE") {
                                riskLevelElement.textContent = "SAFE";
                            } else {
                                riskLevelElement.textContent = `${overallRisk} RISK`;
                            }
                        }

                        /*
                         * Risk icon
                         */
                        if (riskIconElement) {
                            if (isRestricted) {
                                riskIconElement.textContent = "🔒";
                            } else if (
                                overallRisk === "CRITICAL" ||
                                overallRisk === "HIGH"
                            ) {
                                riskIconElement.textContent = "🔴";
                            } else if (overallRisk === "MEDIUM") {
                                riskIconElement.textContent = "🟠";
                            } else if (overallRisk === "LOW") {
                                riskIconElement.textContent = "🟡";
                            } else {
                                riskIconElement.textContent = "🟢";
                            }
                        }

                        /*
                         * Website findings count (Actual security indicators only)
                         */
                        const allRawFindings = [
                            ...(scan?.urlFindings || []),
                            ...(scan?.domFindings || []),
                            ...(scan?.formFindings || []),
                            ...(scan?.scriptIframeFindings || []),
                            ...(scan?.sensitiveDataFindings || []),
                            ...(scan?.promptInjectionFindings || [])
                        ];

                        const actualFindings = allRawFindings.filter(
                            (f) => f && !informationalTypes.includes(f.type)
                        );

                        if (websiteFindingsElement) {
                            websiteFindingsElement.textContent =
                                isRestricted ? 0 : actualFindings.length;
                        }

                        /*
                         * Extension findings count
                         */
                        const extensionScan =
                            result.extensionScan || [];

                        let totalExtensionFindings = 0;
                        extensionScan.forEach((extension) => {
                            totalExtensionFindings +=
                                (extension.findings || []).length;
                        });

                        if (extensionFindingsElement) {
                            extensionFindingsElement.textContent =
                                totalExtensionFindings;
                        }

                        /*
                         * AI status
                         */
                        const hasGeminiKey = !!result.geminiApiKey?.trim();

                        if (aiStatusElement) {
                            aiStatusElement.textContent =
                                hasGeminiKey ? "READY" : "OFFLINE";
                            aiStatusElement.className =
                                hasGeminiKey ? "enabled" : "disabled";
                        }

                        /*
                         * Privacy Mode status
                         */
                        if (privacyStatusElement) {
                            privacyStatusElement.textContent = "ON";
                            privacyStatusElement.className = "enabled";
                        }

                    }
                );

            }
        );
    }

    renderPopup();

    // Listen for storage changes in the background while popup is open
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "local") {
            renderPopup();
        }
    });

    /*
     * View Details
     */
    if (detailsButton) {
        detailsButton.addEventListener("click", () => {
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
                    const dashboardUrl =
                        chrome.runtime.getURL("dashboard/dashboard.html") +
                        "?tabId=" +
                        currentTab.id +
                        "&url=" +
                        encodeURIComponent(currentTab.url || "");

                    chrome.tabs.create({
                        url: dashboardUrl
                    });
                }
            );
        });
    }

});

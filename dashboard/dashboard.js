console.log("SentinelAI Dashboard loaded");

const params = new URLSearchParams(window.location.search);
const tabId = params.get("tabId");
const currentWebsite = params.get("url");

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

// ==================================
// SETTINGS HANDLERS
// ==================================

const aiToggle = document.getElementById("aiAnalysisToggle");

function updateAiAndLocalStatus() {
    chrome.storage.local.get(
        ["privacyMode", "aiEnabled", "aiConsent"],
        (settings) => {
            const aiEnabled = settings.aiEnabled === true;
            const aiConsent = settings.aiConsent === true;
            const aiIsActive = aiEnabled && aiConsent;

            const aiStatus =
                document.getElementById("aiAnalysisStatus");

            const localStatus =
                document.getElementById("localOnlyStatus");

            const privacyStatusOverview =
                document.getElementById("privacyStatusOverview");

            const privacyStatusSettings =
                document.getElementById("privacyStatusSettings");

            if (aiToggle) {
                aiToggle.checked = aiIsActive;
            }

            if (aiStatus) {
                aiStatus.textContent = aiIsActive ? "ON" : "OFF";
                aiStatus.className =
                    aiIsActive ? "enabled" : "disabled";
            }

            if (localStatus) {
                localStatus.textContent = "ON";
                localStatus.className = "enabled";
            }

            if (privacyStatusOverview) {
                privacyStatusOverview.textContent = "ON";
                privacyStatusOverview.className = "enabled";
            }

            if (privacyStatusSettings) {
                privacyStatusSettings.textContent = "ON";
                privacyStatusSettings.className = "enabled";
            }
        }
    );
}

if (aiToggle) {
    aiToggle.addEventListener("change", () => {
        const enabled = aiToggle.checked;
        chrome.storage.local.set(
            {
                aiEnabled: enabled,
                aiConsent: enabled,
                privacyMode: true
            },
            () => {
                updateAiAndLocalStatus();
                loadDashboardData();
            }
        );
    });
}

updateAiAndLocalStatus();

// ==================================
// MAIN DASHBOARD DATA RENDERER
// ==================================

function renderDashboardWithScan(scan, extensionScan, aiAnalysis, pageUrl) {
    const isRestricted = isRestrictedUrl(pageUrl);

    // ----------------------------------
    // WEBSITE URL
    // ----------------------------------
    const urlElement = document.getElementById("websiteUrl");
    if (urlElement) {
        urlElement.textContent = pageUrl || "Unknown";
    }

    // ----------------------------------
    // OVERVIEW
    // ----------------------------------
    const calculatedRisk =
        scan?.risk?.level ||
        (isRestricted ? "SAFE" : "SAFE");

    const finalOverallRisk =
        scan?.overallRisk ||
        calculatedRisk;

    const overallRiskElement = document.getElementById("overallRisk");
    if (overallRiskElement) {
        overallRiskElement.textContent = finalOverallRisk;
    }

    const websiteRiskElement = document.getElementById("websiteRisk");
    if (websiteRiskElement) {
        websiteRiskElement.textContent = calculatedRisk;
    }

    // ----------------------------------
    // BASIC DOM INFORMATION
    // ----------------------------------
    const formsCountElement = document.getElementById("formsCount");
    if (formsCountElement) {
        formsCountElement.textContent = scan ? (scan.forms ?? 0) : 0;
    }

    const scriptsCountElement = document.getElementById("scriptsCount");
    if (scriptsCountElement) {
        scriptsCountElement.textContent = scan ? (scan.scripts ?? 0) : 0;
    }

    const iframesCountElement = document.getElementById("iframesCount");
    if (iframesCountElement) {
        iframesCountElement.textContent = scan ? (scan.iframes ?? 0) : 0;
    }

    const domStatusElement = document.getElementById("domStatus");
    if (domStatusElement) {
        domStatusElement.textContent = scan
            ? "Available"
            : (isRestricted ? "System Protected" : "Available");
    }

    // ----------------------------------
    // PHISHING RISK
    // ----------------------------------
    const phishingStatusElement = document.getElementById("phishingStatus");
    if (phishingStatusElement) {
        if (scan?.phishingRisk) {
            phishingStatusElement.textContent = scan.phishingRisk.risk;
        } else {
            phishingStatusElement.textContent = isRestricted ? "N/A (System Page)" : "LOW";
        }
    }

    // ----------------------------------
    // PROMPT INJECTION
    // ----------------------------------
    const promptFindings = (scan?.promptInjectionFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const promptInjectionDetected = promptFindings.some(
        (finding) => finding.type !== "NO_PROMPT_INJECTION"
    );

    const promptStatusElement = document.getElementById("promptStatus");
    if (promptStatusElement) {
        promptStatusElement.textContent = promptInjectionDetected
            ? "Possible Injection"
            : "No injection detected";
    }

    // ----------------------------------
    // EXTENSION SECURITY
    // ----------------------------------
    const extensionCountElement = document.getElementById("extensionCount");
    if (extensionCountElement) {
        extensionCountElement.textContent = extensionScan.length;
    }

    let totalPermissions = 0;
    extensionScan.forEach((extension) => {
        totalPermissions += (extension.permissions || []).length;
    });

    const permissionCountElement = document.getElementById("permissionCount");
    if (permissionCountElement) {
        permissionCountElement.textContent = totalPermissions;
    }

    const hasHighRiskExtension = extensionScan.some(
        (ext) => ext.risk === "HIGH"
    );
    const hasMediumRiskExtension = extensionScan.some(
        (ext) => ext.risk === "MEDIUM"
    );

    let extensionOverallRisk = "LOW";
    if (hasHighRiskExtension) {
        extensionOverallRisk = "HIGH";
    } else if (hasMediumRiskExtension) {
        extensionOverallRisk = "MEDIUM";
    }

    const extensionRiskElement = document.getElementById("extensionRisk");
    if (extensionRiskElement) {
        extensionRiskElement.textContent = extensionOverallRisk;
    }

    const extensionRiskDetailElement =
        document.getElementById("extensionRiskDetail");
    if (extensionRiskDetailElement) {
        extensionRiskDetailElement.textContent = extensionOverallRisk;
    }

    let extensionFindingCount = 0;
    extensionScan.forEach((extension) => {
        extensionFindingCount += (extension.findings || []).length;
    });

    const extensionFindingsCountElement =
        document.getElementById("extensionFindings");
    if (extensionFindingsCountElement) {
        extensionFindingsCountElement.textContent = extensionFindingCount;
    }

    // ----------------------------------
    // EXTENSION FINDINGS DETAILS CONTAINER
    // ----------------------------------
    const extensionFindingsContainer = document.getElementById(
        "extensionFindingsContainer"
    );

    if (extensionFindingsContainer) {
        extensionFindingsContainer.replaceChildren();

        if (extensionScan.length === 0) {
            extensionFindingsContainer.textContent =
                "No installed extensions found.";
        } else {
            const fragment = document.createDocumentFragment();

            extensionScan.forEach((extension) => {
                const extensionCard = document.createElement("div");
                extensionCard.className = "extension-finding-card";

                const extensionName = document.createElement("h4");
                extensionName.textContent =
                    extension.name || "Unknown Extension";
                extensionCard.appendChild(extensionName);

                const risk = document.createElement("p");
                risk.textContent = `Risk: ${extension.risk || "LOW"}`;
                extensionCard.appendChild(risk);

                const findingsTitle = document.createElement("strong");
                findingsTitle.textContent = "Findings:";
                extensionCard.appendChild(findingsTitle);

                const findings = extension.findings || [];

                if (findings.length === 0) {
                    const noFindings = document.createElement("p");
                    noFindings.textContent = "No specific findings detected.";
                    extensionCard.appendChild(noFindings);
                } else {
                    findings.forEach((finding) => {
                        const findingItem = document.createElement("div");
                        findingItem.className = "extension-finding-item";

                        const severity = document.createElement("strong");
                        severity.textContent = finding.severity || "LOW";

                        const reason = document.createElement("span");
                        reason.textContent =
                            finding.reason || "No reason provided";

                        findingItem.appendChild(severity);
                        findingItem.appendChild(document.createTextNode(" "));
                        findingItem.appendChild(reason);

                        extensionCard.appendChild(findingItem);
                    });
                }

                fragment.appendChild(extensionCard);
            });

            extensionFindingsContainer.appendChild(fragment);
        }
    }

    // ----------------------------------
    // WEBSITE SECURITY FINDINGS (Actual Security Indicators Only)
    // ----------------------------------
    const urlFindings = (scan?.urlFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const domFindings = (scan?.domFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const formFindings = (scan?.formFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const scriptIframeFindings = (scan?.scriptIframeFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const sensitiveDataFindings = (scan?.sensitiveDataFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );

    const findings = [
        ...urlFindings,
        ...domFindings,
        ...formFindings,
        ...scriptIframeFindings,
        ...sensitiveDataFindings,
        ...promptFindings
    ];

    const urlFindingsElement = document.getElementById("urlFindings");
    if (urlFindingsElement) {
        urlFindingsElement.textContent = urlFindings.length;
    }

    const findingsContainer = document.getElementById("findingsContainer");
    if (findingsContainer) {
        findingsContainer.replaceChildren();

        if (findings.length === 0) {
            findingsContainer.textContent = "No security findings detected. Website appears safe.";
        } else {
            findings.forEach((finding) => {
                const item = document.createElement("div");
                item.className = "finding-item";

                const severity = document.createElement("strong");
                severity.textContent = finding.severity || "LOW";

                const reason = document.createElement("span");
                reason.textContent = finding.reason || "No reason provided";

                item.appendChild(severity);
                item.appendChild(document.createTextNode(" "));
                item.appendChild(reason);

                findingsContainer.appendChild(item);
            });
        }
    }

    // ----------------------------------
    // AI ANALYSIS
    // ----------------------------------
    const aiSummaryElement = document.getElementById("aiSummary");
    const aiWhyElement = document.getElementById("aiWhy");
    const aiRecommendationsElement = document.getElementById(
        "aiRecommendations"
    );
    const aiUserMessageElement = document.getElementById("aiUserMessage");

    if (aiAnalysis && aiAnalysis.success && aiAnalysis.analysis) {
        const analysis = aiAnalysis.analysis;

        if (aiSummaryElement) {
            aiSummaryElement.textContent =
                analysis.summary || "No AI summary available.";
        }

        if (aiWhyElement) {
            aiWhyElement.replaceChildren();
            const why = Array.isArray(analysis.why) ? analysis.why : [];
            if (why.length === 0) {
                aiWhyElement.textContent =
                    "No additional explanation available.";
            } else {
                why.forEach((reason) => {
                    const item = document.createElement("div");
                    item.textContent = "• " + reason;
                    aiWhyElement.appendChild(item);
                });
            }
        }

        if (aiRecommendationsElement) {
            aiRecommendationsElement.replaceChildren();
            const recommendations = Array.isArray(analysis.recommendations)
                ? analysis.recommendations
                : [];
            if (recommendations.length === 0) {
                aiRecommendationsElement.textContent =
                    "No specific recommendations available.";
            } else {
                recommendations.forEach((rec) => {
                    const item = document.createElement("div");
                    const priority = rec.priority || "INFO";
                    const action = rec.action || "No action provided";
                    item.textContent = `• ${priority}: ${action}`;
                    aiRecommendationsElement.appendChild(item);
                });
            }
        }

        if (aiUserMessageElement) {
            aiUserMessageElement.textContent =
                analysis.user_message || "No additional message available.";
        }
    } else if (aiAnalysis && aiAnalysis.success === false) {
        if (aiSummaryElement) {
            aiSummaryElement.textContent =
                "AI analysis is temporarily unavailable. Local security analysis is still active.";
        }
        if (aiWhyElement) aiWhyElement.textContent = "";
        if (aiRecommendationsElement) aiRecommendationsElement.textContent = "";
        if (aiUserMessageElement) {
            aiUserMessageElement.textContent =
                "You can continue using SentinelAI. Core security detection does not depend on AI.";
        }
    } else {
        if (aiSummaryElement) {
            aiSummaryElement.textContent = isRestricted
                ? "AI analysis is not applicable for browser internal pages."
                : "AI analysis is not available for this scan.";
        }
        if (aiWhyElement) aiWhyElement.textContent = "AI explanation will appear here.";
        if (aiRecommendationsElement) aiRecommendationsElement.textContent = "AI recommendations will appear here.";
        if (aiUserMessageElement) aiUserMessageElement.textContent = "Continue browsing normally.";
    }
}

function loadDashboardData() {
    chrome.storage.local.get(
        [
            tabId ? `scan_${tabId}` : null,
            "lastScan",
            "extensionScan",
            tabId ? `ai_analysis_${tabId}` : null,
            "privacyMode"
        ].filter(Boolean),
        (result) => {
            let scan = null;
            const tabScan = tabId ? result[`scan_${tabId}`] : null;

            // Only use tabScan if it matches the requested URL origin
            if (tabScan && (!currentWebsite || isSamePage(tabScan.url, currentWebsite))) {
                scan = tabScan;
            }

            // Only fallback to lastScan if it genuinely belongs to this website
            if (!scan && result.lastScan && currentWebsite && isSamePage(result.lastScan.url, currentWebsite)) {
                scan = result.lastScan;
            }

            const extensionScan = result.extensionScan || [];
            const aiAnalysis =
                (tabId ? result[`ai_analysis_${tabId}`] : null) || null;
            const pageUrl = currentWebsite || scan?.url || "Unknown";

            // If no scan exists for this specific website yet, request live scan from tab content script
            if (!scan && tabId) {
                const numericTabId = parseInt(tabId, 10);
                if (!isNaN(numericTabId)) {
                    try {
                        chrome.tabs.sendMessage(
                            numericTabId,
                            { action: "REQUEST_SCAN" },
                            (resp) => {
                                if (chrome.runtime.lastError) {
                                    // Content script initializing or tab not reachable
                                } else if (resp && resp.data) {
                                    renderDashboardWithScan(
                                        resp.data,
                                        extensionScan,
                                        aiAnalysis,
                                        pageUrl
                                    );
                                }
                            }
                        );
                    } catch (e) {
                        // Ignore message delivery errors
                    }
                }
            }

            renderDashboardWithScan(
                scan,
                extensionScan,
                aiAnalysis,
                pageUrl
            );
        }
    );
}

// Initial load
loadDashboardData();

// Listen for storage changes in the background and update live
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local") {
        if (
            (tabId && changes[`scan_${tabId}`]) ||
            changes.lastScan ||
            (tabId && changes[`ai_analysis_${tabId}`]) ||
            changes.extensionScan
        ) {
            console.log("SentinelAI: Storage updated, re-rendering dashboard");
            loadDashboardData();
        }
    }
});

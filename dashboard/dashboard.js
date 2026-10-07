
console.log("SentinelAI Dashboard loaded");


const params =
    new URLSearchParams(
        window.location.search
    );


const tabId =
    params.get("tabId");


const currentWebsite =
    params.get("url");


if (!tabId) {

    console.log(
        "No original tab ID provided"
    );

} else {

    chrome.storage.local.get(
        [
            `scan_${tabId}`,
            "extensionScan",
            `ai_analysis_${tabId}`,
            "privacyMode"
        ],
        (result) => {

            const scan =
                result[`scan_${tabId}`];

            const extensionScan =
                result.extensionScan || [];

            const aiAnalysis =
                result[`ai_analysis_${tabId}`] || null; 


            if (!scan) {

                console.log(
                    "No scan data for tab:",
                    tabId
                );

                return;

            }

            const privacyMode =
                result.privacyMode === true;

            const privacyStatusElement =
                document.getElementById("privacyStatus");

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


            // ==================================
            // WEBSITE
            // ==================================

            document.getElementById(
                "websiteUrl"
            ).textContent =
                currentWebsite ||
                scan.url ||
                "Unknown";


            // ==================================
            // BASIC DOM INFORMATION
            // ==================================

            document.getElementById(
                "formsCount"
            ).textContent =
                scan.forms || 0;


            document.getElementById(
                "scriptsCount"
            ).textContent =
                scan.scripts || 0;


            document.getElementById(
                "iframesCount"
            ).textContent =
                scan.iframes || 0;


            document.getElementById(
                "domStatus"
            ).textContent =
                "Available";


            // ==================================
            // PHISHING RISK
            // ==================================

            const phishingRisk =
                scan.phishingRisk;


            if (phishingRisk) {

                document.getElementById(
                    "phishingStatus"
                ).textContent =
                    phishingRisk.risk;

            } else {

                document.getElementById(
                    "phishingStatus"
                ).textContent =
                    "Not analyzed";

            }


            // ==================================
            // PROMPT INJECTION
            // ==================================

            const promptFindings =
                scan.promptInjectionFindings || [];


            const promptInjectionDetected =
                promptFindings.some(
                    finding =>
                        finding.type !==
                        "NO_PROMPT_INJECTION"
                );


            document.getElementById(
                "promptStatus"
            ).textContent =
                promptInjectionDetected
                    ? "Possible Injection"
                    : "No injection detected";


            // ==================================
            // EXTENSION SECURITY
            // ==================================

            document.getElementById(
                "extensionCount"
            ).textContent =
                extensionScan.length;


            // ----------------------------------
            // Permission Count
            // ----------------------------------

            let totalPermissions = 0;


            extensionScan.forEach(
                extension => {

                    totalPermissions +=
                        (
                            extension.permissions || []
                        ).length;

                }
            );


            document.getElementById(
                "permissionCount"
            ).textContent =
                totalPermissions;


            // ----------------------------------
            // Extension Risk
            // ----------------------------------

            const hasHighRiskExtension =
                extensionScan.some(
                    extension =>
                        extension.risk === "HIGH"
                );


            const hasMediumRiskExtension =
                extensionScan.some(
                    extension =>
                        extension.risk === "MEDIUM"
                );


            let extensionOverallRisk =
                "LOW";


            if (hasHighRiskExtension) {

                extensionOverallRisk =
                    "HIGH";

            } else if (
                hasMediumRiskExtension
            ) {

                extensionOverallRisk =
                    "MEDIUM";

            }


            document.getElementById(
                "extensionRisk"
            ).textContent =
                extensionOverallRisk;


            document.getElementById(
                "extensionRiskDetail"
            ).textContent =
                extensionOverallRisk;


            // ----------------------------------
            // Extension Findings
            // ----------------------------------

            let extensionFindingCount = 0;


            extensionScan.forEach(
                extension => {

                    extensionFindingCount +=
                        (
                            extension.findings || []
                        ).length;

                }
            );


            document.getElementById(
                "extensionFindings"
            ).textContent =
                extensionFindingCount;
            
            // EXTENSION FINDINGS DETAILS
            const extensionFindingsContainer =
                document.getElementById("extensionFindingsContainer");

            if (extensionFindingsContainer) {

                extensionFindingsContainer.replaceChildren();

                if (extensionScan.length === 0) {

                    extensionFindingsContainer.textContent =
                        "No installed extensions found.";

                } else {

                    extensionScan.forEach(extension => {

                        const extensionCard =
                            document.createElement("div");

                        extensionCard.className =
                            "extension-finding-card";


                        // Extension Name
                        const extensionName =
                            document.createElement("h4");

                        extensionName.textContent =
                            extension.name || "Unknown Extension";

                        extensionCard.appendChild(
                            extensionName
                        );


                        // Risk
                        const risk =
                            document.createElement("p");

                        risk.textContent =
                            `Risk: ${extension.risk || "LOW"}`;

                        extensionCard.appendChild(
                            risk
                        );


                        // Findings
                        const findingsTitle =
                            document.createElement("strong");

                        findingsTitle.textContent =
                            "Findings:";

                        extensionCard.appendChild(
                            findingsTitle
                        );


                        const findings =
                            extension.findings || [];


                        if (findings.length === 0) {

                            const noFindings =
                                document.createElement("p");

                            noFindings.textContent =
                                "No specific findings detected.";

                            extensionCard.appendChild(
                                noFindings
                            );

                        } else {

                            findings.forEach(finding => {

                                const findingItem =
                                    document.createElement("div");

                                findingItem.className =
                                    "extension-finding-item";

                                const severity =
                                    document.createElement("strong");

                                severity.textContent =
                                    finding.severity || "LOW";

                                const reason =
                                    document.createElement("span");

                                reason.textContent =
                                    finding.reason ||
                                    "No reason provided";

                                findingItem.appendChild(
                                    severity
                                );

                                findingItem.appendChild(
                                    document.createTextNode(" ")
                                );

                                findingItem.appendChild(
                                    reason
                                );

                                extensionCard.appendChild(
                                    findingItem
                                );
                            });
                        }


                        extensionFindingsContainer.appendChild(
                            extensionCard
                        );
                    });
                }
            }

            // ==================================
            // OVERALL WEBSITE RISK
            // ==================================

            const calculatedRisk =
                scan.risk?.level ||
                "SAFE";


            const finalOverallRisk =
                scan.overallRisk ||
                calculatedRisk;


            document.getElementById(
                "overallRisk"
            ).textContent =
                finalOverallRisk;


            document.getElementById(
                "websiteRisk"
            ).textContent =
                calculatedRisk;

            const riskReasonElement =
                document.getElementById(
                    "aiReason"
                );


            if (riskReasonElement) {

                const websiteReasons =
                    scan.risk?.reasons || [];


                const extensionReasons =
                    scan.extensionRiskReasons || [];


                const allReasons = [
                    ...websiteReasons,
                    ...extensionReasons
                ];


                if (allReasons.length === 0) {

                    riskReasonElement.textContent =
                        "No significant security indicators detected.";

                } else {

                    riskReasonElement.replaceChildren();


                    allReasons.forEach(
                        reason => {

                            const item =
                                document.createElement(
                                    "div"
                                );


                            item.textContent =
                                "• " + reason;


                            riskReasonElement.appendChild(
                                item
                            );

                        }
                    );

                }

            }

            // ==================================
            // AI ANALYSIS
            // ==================================

            const aiSummaryElement =
                document.getElementById(
                    "aiSummary"
                );

            const aiWhyElement =
                document.getElementById(
                    "aiWhy"
                );

            const aiRecommendationsElement =
                document.getElementById(
                    "aiRecommendations"
                );

            const aiUserMessageElement =
                document.getElementById(
                    "aiUserMessage"
                );


            if (
                aiAnalysis &&
                aiAnalysis.success &&
                aiAnalysis.analysis
            ) {

                const analysis =
                    aiAnalysis.analysis;


                // -------------------------------
                // Summary
                // -------------------------------

                if (aiSummaryElement) {

                    aiSummaryElement.textContent =
                        analysis.summary ||
                        "No AI summary available.";

                }


                // -------------------------------
                // Why suspicious?
                // -------------------------------

                if (aiWhyElement) {

                    aiWhyElement.replaceChildren();


                    const why =
                        Array.isArray(
                            analysis.why
                        )
                            ? analysis.why
                            : [];


                    if (why.length === 0) {

                        aiWhyElement.textContent =
                            "No additional explanation available.";

                    } else {

                        why.forEach(
                            reason => {

                                const item =
                                    document.createElement(
                                        "div"
                                    );

                                item.textContent =
                                    "• " + reason;

                                aiWhyElement.appendChild(
                                    item
                                );

                            }
                        );

                    }

                }


                // -------------------------------
                // Recommendations
                // -------------------------------

                if (aiRecommendationsElement) {

                    aiRecommendationsElement.replaceChildren();


                    const recommendations =
                        Array.isArray(
                            analysis.recommendations
                        )
                            ? analysis.recommendations
                            : [];


                    if (
                        recommendations.length === 0
                    ) {

                        aiRecommendationsElement.textContent =
                            "No specific recommendations available.";

                    } else {

                        recommendations.forEach(
                            recommendation => {

                                const item =
                                    document.createElement(
                                        "div"
                                    );


                                const priority =
                                    recommendation.priority ||
                                    "INFO";


                                const action =
                                    recommendation.action ||
                                    "No action provided";


                                item.textContent =
                                    `• ${priority}: ${action}`;


                                aiRecommendationsElement.appendChild(
                                    item
                                );

                            }
                        );

                    }

                }


                // -------------------------------
                // User Message
                // -------------------------------

                if (aiUserMessageElement) {

                    aiUserMessageElement.textContent =
                        analysis.user_message ||
                        "No additional message available.";

                }

            }
            else if (
                aiAnalysis &&
                aiAnalysis.success === false
            ) {

                if (aiSummaryElement) {

                    aiSummaryElement.textContent =
                        "AI analysis is temporarily unavailable. Local security analysis is still active.";

                }

                if (aiWhyElement) {

                    aiWhyElement.textContent =
                        "";

                }

                if (aiRecommendationsElement) {

                    aiRecommendationsElement.textContent =
                        "";

                }

                if (aiUserMessageElement) {

                    aiUserMessageElement.textContent =
                        "You can continue using SentinelAI. Core security detection does not depend on AI.";

                }

            }
            else {

                if (aiSummaryElement) {

                    aiSummaryElement.textContent =
                        "AI analysis is not available for this scan.";

                }

            }

            // ==================================
            // ALL WEBSITE FINDINGS
            // ==================================

            const urlFindings =
                scan.urlFindings || [];


            const domFindings =
                scan.domFindings || [];


            const formFindings =
                scan.formFindings || [];


            const scriptIframeFindings =
                scan.scriptIframeFindings || [];


            const sensitiveDataFindings =
                scan.sensitiveDataFindings || [];


            const findings = [

                ...urlFindings,

                ...domFindings,

                ...formFindings,

                ...scriptIframeFindings,

                ...sensitiveDataFindings,

                ...promptFindings

            ];


            // ==================================
            // URL FINDINGS COUNT
            // ==================================

            const urlFindingsElement =
                document.getElementById(
                    "urlFindings"
                );


            if (urlFindingsElement) {

                urlFindingsElement.textContent =
                    urlFindings.length;

            }


            // ==================================
            // FINDINGS CONTAINER
            // ==================================

            const findingsContainer =
                document.getElementById(
                    "findingsContainer"
                );


            if (!findingsContainer) {

                return;

            }


            if (findings.length === 0) {

                findingsContainer.textContent =
                    "No security findings";

                return;

            }


            findingsContainer.replaceChildren();


            // ==================================
            // DISPLAY FINDINGS
            // ==================================

            findings.forEach(
                (finding) => {

                    const item =
                        document.createElement(
                            "div"
                        );


                    item.className =
                        "finding-item";


                    const severity =
                        document.createElement(
                            "strong"
                        );


                    severity.textContent =
                        finding.severity;


                    const reason =
                        document.createElement(
                            "span"
                        );


                    reason.textContent =
                        finding.reason;


                    item.appendChild(
                        severity
                    );


                    item.appendChild(
                        reason
                    );


                    findingsContainer.appendChild(
                        item
                    );

                }
            );

        }
    );

}


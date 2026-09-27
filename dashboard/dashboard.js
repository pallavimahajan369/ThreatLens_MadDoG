
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
            "extensionScan"
        ],
        (result) => {

            const scan =
                result[`scan_${tabId}`];

            const extensionScan =
                result.extensionScan || [];


            if (!scan) {

                console.log(
                    "No scan data for tab:",
                    tabId
                );

                return;

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

                    riskReasonElement.innerHTML = "";


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


            findingsContainer.innerHTML = "";


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


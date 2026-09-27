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
        `scan_${tabId}`,
        (result) => {

            const scan =
                result[`scan_${tabId}`];


            if (!scan) {

                console.log(
                    "No scan data for tab:",
                    tabId
                );

                return;
            }


            // ===============================
            // WEBSITE
            // ===============================

            document.getElementById(
                "websiteUrl"
            ).textContent =
                currentWebsite ||
                scan.url ||
                "Unknown";


            // ===============================
            // BASIC DOM INFORMATION
            // ===============================

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


            // ===============================
            // PHISHING RISK
            // ===============================

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


            // ===============================
            // OVERALL RISK
            // ===============================

            let overallRisk = "LOW";


            if (
                phishingRisk &&
                phishingRisk.risk
            ) {

                overallRisk =
                    phishingRisk.risk;

            }


            document.getElementById(
                "overallRisk"
            ).textContent =
                overallRisk;


            document.getElementById(
                "websiteRisk"
            ).textContent =
                overallRisk;


            document.getElementById(
                "extensionRisk"
            ).textContent =
                "LOW";


            // ===============================
            // OTHER STATUS
            // ===============================

            document.getElementById(
                "promptStatus"
            ).textContent =
                "Not analyzed";


            document.getElementById(
                "extensionCount"
            ).textContent =
                "Not analyzed";


            document.getElementById(
                "permissionCount"
            ).textContent =
                "Not analyzed";


            document.getElementById(
                "extensionRiskDetail"
            ).textContent =
                "LOW";


            document.getElementById(
                "extensionFindings"
            ).textContent =
                "0";


            // ===============================
            // FINDINGS
            // ===============================

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

                ...sensitiveDataFindings

            ];


            // ===============================
            // URL FINDINGS COUNT
            // ===============================

            const urlFindingsElement =
                document.getElementById(
                    "urlFindings"
                );


            if (urlFindingsElement) {

                urlFindingsElement.textContent =
                    urlFindings.length;

            }


            // ===============================
            // FINDINGS CONTAINER
            // ===============================

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


            // ===============================
            // DISPLAY FINDINGS
            // ===============================

            findings.forEach((finding) => {

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

            });

        }
    );

}
console.log("SentinelAI Dashboard loaded");

// Get current website URL passed from popup
const params = new URLSearchParams(window.location.search);

const currentWebsite = params.get("url");

chrome.storage.local.get("lastScan", (result) => {

    const scan = result.lastScan;

    if (!scan) {
        console.log("No scan data available");
        return;
    }

    // Show current website URL
    document.getElementById("websiteUrl")
        .textContent = currentWebsite || scan.url || "Unknown";

    document.getElementById("formsCount")
        .textContent = scan.forms || 0;

    document.getElementById("scriptsCount")
        .textContent = scan.scripts || 0;

    document.getElementById("iframesCount")
        .textContent = scan.iframes || 0;

    document.getElementById("domStatus")
        .textContent = "Available";

    document.getElementById("overallRisk")
        .textContent = "LOW";

    document.getElementById("websiteRisk")
        .textContent = "LOW";

    document.getElementById("extensionRisk")
        .textContent = "LOW";

    document.getElementById("phishingStatus")
        .textContent = "Not analyzed";

    document.getElementById("promptStatus")
        .textContent = "Not analyzed";

    document.getElementById("extensionCount")
        .textContent = "Not analyzed";

    document.getElementById("permissionCount")
        .textContent = "Not analyzed";

    document.getElementById("extensionRiskDetail")
        .textContent = "LOW";

    document.getElementById("extensionFindings")
        .textContent = "0";


    // URL findings
    const findingsContainer =
        document.getElementById("findingsContainer");

    const findings =
        scan.urlFindings || [];

    const urlFindingsElement =
        document.getElementById("urlFindings");

    if (urlFindingsElement) {
        urlFindingsElement.textContent =
            findings.length;
    }


    if (!findingsContainer) {
        return;
    }

    if (findings.length === 0) {

        findingsContainer.textContent =
            "No security findings";

        return;
    }


    findingsContainer.innerHTML = "";

    findings.forEach((finding) => {

        const item =
            document.createElement("div");

        item.className = "finding-item";


        const severity =
            document.createElement("strong");

        severity.textContent =
            finding.severity;


        const reason =
            document.createElement("span");

        reason.textContent =
            finding.reason;


        item.appendChild(severity);
        item.appendChild(reason);

        findingsContainer.appendChild(item);

    });

});
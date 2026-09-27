console.log("SentinelAI Dashboard loaded");


chrome.storage.local.get("lastScan", (result) => {

    const scan = result.lastScan;


    if (!scan) {

        console.log("No scan data available");

        return;
    }


    // -------------------------
    // WEBSITE INFORMATION
    // -------------------------

    document.getElementById("websiteUrl")
        .textContent = scan.url || "Unknown";


    document.getElementById("formsCount")
        .textContent = scan.forms || 0;


    document.getElementById("scriptsCount")
        .textContent = scan.scripts || 0;


    document.getElementById("iframesCount")
        .textContent = scan.iframes || 0;


    // DOM information

    document.getElementById("domStatus")
        .textContent = "Available";


    // -------------------------
    // DEFAULT SECURITY STATUS
    // -------------------------

    document.getElementById("overallRisk")
        .textContent = "LOW";


    document.getElementById("websiteRisk")
        .textContent = "LOW";


    document.getElementById("extensionRisk")
        .textContent = "LOW";


    // -------------------------
    // CURRENT PLACEHOLDER
    // -------------------------

    document.getElementById("phishingStatus")
        .textContent = "Not analyzed";


    document.getElementById("promptStatus")
        .textContent = "Not analyzed";


    // -------------------------
    // EXTENSION
    // -------------------------

    document.getElementById("extensionCount")
        .textContent = "Not analyzed";


    document.getElementById("permissionCount")
        .textContent = "Not analyzed";


    document.getElementById("extensionRiskDetail")
        .textContent = "LOW";


    document.getElementById("extensionFindings")
        .textContent = "0";


});
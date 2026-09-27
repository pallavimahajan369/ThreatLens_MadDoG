console.log("SentinelAI service worker started");
console.log("SentinelAI service worker started");


function analyzeExtensionSecurity(extension) {

    const findings = [];

    const permissions =
        extension.permissions || [];

    const hostPermissions =
        extension.hostPermissions || [];


    if (permissions.includes("tabs")) {

        findings.push({
            type: "TABS_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can access information about browser tabs"
        });

    }


    if (permissions.includes("cookies")) {

        findings.push({
            type: "COOKIES_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can access browser cookies"
        });

    }


    if (permissions.includes("webRequest")) {

        findings.push({
            type: "WEBREQUEST_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can observe web requests"
        });

    }


    if (permissions.includes("scripting")) {

        findings.push({
            type: "SCRIPTING_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can inject or execute scripts on webpages"
        });

    }


    const hasAllURLs =
        hostPermissions.some(
            permission =>
                permission === "<all_urls>" ||
                permission === "*://*/*" ||
                permission === "http://*/*" ||
                permission === "https://*/*"
        );


    if (hasAllURLs) {

        findings.push({
            type: "ALL_URLS",
            severity: "HIGH",
            reason:
                "Extension can access a broad range of websites"
        });

    }


    if (
        permissions.includes("scripting") ||
        hasAllURLs
    ) {

        findings.push({
            type: "WEBPAGE_MODIFICATION",
            severity: "MEDIUM",
            reason:
                "Extension may have capability to modify webpage content"
        });

    }


    const highRiskPermissions = [
        "cookies",
        "webRequest",
        "webRequestBlocking",
        "debugger"
    ];


    const riskyPermissionCount =
        permissions.filter(permission =>
            highRiskPermissions.includes(permission)
        ).length;


    if (riskyPermissionCount >= 2) {

        findings.push({
            type: "EXCESSIVE_PERMISSIONS",
            severity: "HIGH",
            reason:
                "Extension requests multiple high-impact permissions"
        });

    }


    if (hostPermissions.length >= 5) {

        findings.push({
            type: "BROAD_HOST_ACCESS",
            severity: "MEDIUM",
            reason:
                "Extension requests access to multiple website origins"
        });

    }


    let risk = "LOW";


    if (
        findings.some(
            finding =>
                finding.severity === "HIGH"
        )
    ) {

        risk = "HIGH";

    } else if (
        findings.some(
            finding =>
                finding.severity === "MEDIUM"
        )
    ) {

        risk = "MEDIUM";

    }


    if (findings.length === 0) {

        findings.push({
            type: "NO_SUSPICIOUS_PERMISSION",
            severity: "LOW",
            reason:
                "No suspicious permission indicators detected"
        });

    }


    return {
        risk: risk,
        findings: findings
    };
}

async function scanInstalledExtensions() {

    const extensions =
        await chrome.management.getAll();


    const results =
        extensions
            .filter(
                extension =>
                    extension.type === "extension"
            )
            .map(
                extension => {

                    const analysis =
                        analyzeExtensionSecurity(
                            extension
                        );


                    return {

                        id:
                            extension.id,

                        name:
                            extension.name,

                        enabled:
                            extension.enabled,

                        permissions:
                            extension.permissions || [],

                        hostPermissions:
                            extension.hostPermissions || [],

                        risk:
                            analysis.risk,

                        findings:
                            analysis.findings

                    };

                }
            );


    await chrome.storage.local.set({

        extensionScan:
            results,

        extensionScanTimestamp:
            new Date().toISOString()

    });


    console.log(
        "SentinelAI Extension Scan:",
        results
    );


    return results;
}
chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        console.log(
            "Service Worker received:",
            message
        );

        if (message.type === "SCAN_RESULT") {

            const tabId = sender.tab?.id;

            if (tabId === undefined) {
                return;
            }

            chrome.storage.local.set({

                lastScan: message.data,

                [`scan_${tabId}`]: message.data

            });

            console.log(
                "Scan result stored for tab:",
                tabId
            );
        }

    }
);
scanInstalledExtensions();
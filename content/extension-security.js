console.log("SentinelAI Extension Security Engine loaded");


function analyzeExtensionSecurity(extension) {

    const findings = [];

    const permissions =
        extension.permissions || [];

    const hostPermissions =
        extension.hostPermissions || [];


    // ==========================================
    // 1. TABS PERMISSION
    // ==========================================

    if (permissions.includes("tabs")) {

        findings.push({
            type: "TABS_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can access information about browser tabs"
        });

    }


    // ==========================================
    // 2. COOKIES PERMISSION
    // ==========================================

    if (permissions.includes("cookies")) {

        findings.push({
            type: "COOKIES_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can access browser cookies"
        });

    }


    // ==========================================
    // 3. WEBREQUEST PERMISSION
    // ==========================================

    if (permissions.includes("webRequest")) {

        findings.push({
            type: "WEBREQUEST_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can observe web requests"
        });

    }


    // ==========================================
    // 4. SCRIPTING PERMISSION
    // ==========================================

    if (permissions.includes("scripting")) {

        findings.push({
            type: "SCRIPTING_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can inject or execute scripts on webpages"
        });

    }


    // ==========================================
    // 5. ALL URLS
    // ==========================================

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


    // ==========================================
    // 6. WEBPAGE MODIFICATION
    // ==========================================

    const canModifyWebpages =
        permissions.includes("scripting") ||
        hasAllURLs;

    if (canModifyWebpages) {

        findings.push({
            type: "WEBPAGE_MODIFICATION",
            severity: "MEDIUM",
            reason:
                "Extension may have capability to modify webpage content"
        });

    }


    // ==========================================
    // 7. EXCESSIVE PERMISSIONS
    // ==========================================

    const highRiskPermissions = [
        "cookies",
        "webRequest",
        "webRequestBlocking",
        "debugger",
        "management"
    ];

    const riskyPermissionCount =
        permissions.filter(permission =>
            highRiskPermissions.includes(permission)
        ).length;

    if (
        riskyPermissionCount >= 2
    ) {

        findings.push({
            type: "EXCESSIVE_PERMISSIONS",
            severity: "HIGH",
            reason:
                "Extension requests multiple high-impact permissions"
        });

    }


    // ==========================================
    // 8. MANY HOST PERMISSIONS
    // ==========================================

    if (hostPermissions.length >= 5) {

        findings.push({
            type: "BROAD_HOST_ACCESS",
            severity: "MEDIUM",
            reason:
                "Extension requests access to multiple website origins"
        });

    }


    // ==========================================
    // 9. RISK CALCULATION
    // ==========================================

    let risk = "LOW";

    const hasHighRisk =
        findings.some(
            finding =>
                finding.severity === "HIGH"
        );

    const hasMediumRisk =
        findings.some(
            finding =>
                finding.severity === "MEDIUM"
        );

    if (hasHighRisk) {

        risk = "HIGH";

    } else if (hasMediumRisk) {

        risk = "MEDIUM";

    }


    // ==========================================
    // 10. NO RISK SIGNAL
    // ==========================================

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
console.log("SentinelAI Phishing Security Engine loaded");


function analyzePhishingRisk(
    urlFindings,
    domFindings,
    formFindings,
    scriptIframeFindings
) {

    let score = 0;

    const signals = [];


    // =========================================
    // 1. SUSPICIOUS URL SIGNAL
    // =========================================

    const suspiciousURL =
        urlFindings.some(
            finding =>
                finding.severity === "HIGH" ||
                finding.reason.toLowerCase().includes("suspicious") ||
                finding.reason.toLowerCase().includes("punycode")
        );


    if (suspiciousURL) {

        score += 30;

        signals.push(
            "Suspicious URL pattern detected"
        );

    }


    // =========================================
    // 2. LOGIN / PASSWORD FORM
    // =========================================

    const passwordField =
        formFindings.some(
            finding =>
                finding.type === "PASSWORD_FIELD"
        );


    if (passwordField) {

        score += 20;

        signals.push(
            "Password field detected"
        );

    }


    // =========================================
    // 3. CROSS-ORIGIN FORM
    // =========================================

    const crossOriginForm =
        formFindings.some(
            finding =>
                finding.type === "CROSS_ORIGIN_ACTION"
        );


    if (crossOriginForm) {

        score += 40;

        signals.push(
            "Cross-origin form submission detected"
        );

    }


    // =========================================
    // 4. SUSPICIOUS FORM STRUCTURE
    // =========================================

    const suspiciousForm =
        formFindings.some(
            finding =>
                finding.type ===
                "SUSPICIOUS_FORM_STRUCTURE"
        );


    if (suspiciousForm) {

        score += 20;

        signals.push(
            "Suspicious form structure detected"
        );

    }


    // =========================================
    // 5. CROSS-ORIGIN IFRAME
    // =========================================

    const crossOriginIframe =
        scriptIframeFindings.some(
            finding =>
                finding.type ===
                "CROSS_ORIGIN_IFRAME"
        );


    if (crossOriginIframe) {

        score += 15;

        signals.push(
            "Cross-origin iframe detected"
        );

    }


    // =========================================
    // 6. SUSPICIOUS IFRAME
    // =========================================

    const suspiciousIframe =
        scriptIframeFindings.some(
            finding =>
                finding.type ===
                "SUSPICIOUS_IFRAME_SOURCE"
        );


    if (suspiciousIframe) {

        score += 30;

        signals.push(
            "Suspicious iframe source detected"
        );

    }


    // =========================================
    // 7. SUSPICIOUS SCRIPT
    // =========================================

    const suspiciousScript =
        scriptIframeFindings.some(
            finding =>
                finding.type ===
                "SUSPICIOUS_SCRIPT_SOURCE"
        );


    if (suspiciousScript) {

        score += 30;

        signals.push(
            "Suspicious external script source detected"
        );

    }


    // =========================================
    // 8. RISK LEVEL
    // =========================================

    let risk = "LOW";


    if (score >= 60) {

        risk = "HIGH";

    } else if (score >= 30) {

        risk = "MEDIUM";

    }


    // =========================================
    // 9. RESULT
    // =========================================

    return {

        score: score,

        risk: risk,

        signals: signals

    };

}
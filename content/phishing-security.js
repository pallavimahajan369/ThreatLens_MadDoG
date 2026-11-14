

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
        (urlFindings || []).some(
            finding =>
                finding &&
                finding.type !== "NO_SUSPICIOUS_URL_PATTERN" &&
                finding.severity !== "LOW" &&
                (
                    finding.severity === "HIGH" ||
                    (
                        typeof finding.reason === "string" &&
                        !finding.reason.toLowerCase().startsWith("no suspicious") &&
                        (
                            finding.reason.toLowerCase().includes("suspicious") ||
                            finding.reason.toLowerCase().includes("punycode")
                        )
                    )
                )
        );


    if (suspiciousURL) {

        score += 30;

        signals.push(
            "Suspicious URL pattern detected"
        );

    }


    // =========================================
    // 2. CONTEXT-AWARE PASSWORD FIELD ANALYSIS
    // =========================================
    // A password field on a normal HTTPS website (Gmail, LinkedIn, Bank, GitHub)
    // is standard web authentication and NOT a phishing signal on its own.
    // It ONLY becomes a phishing threat when combined with an insecure transport (HTTP),
    // an untrusted/suspicious URL (IP address, excessive subdomains, punycode),
    // or when submitted to an external third-party domain (credential harvesting).
    const hasPasswordField = (formFindings || []).some(
        f => f && f.type === "PASSWORD_FIELD"
    );

    const isInsecureHttp = (urlFindings || []).some(
        f => f && f.type === "HTTP_PROTOCOL"
    ) || (formFindings || []).some(
        f => f && (f.type === "INSECURE_PASSWORD_TRANSMISSION" || f.type === "HTTP_ACTION")
    );

    const isCrossOriginPassword = (formFindings || []).some(
        f => f && f.type === "CROSS_ORIGIN_ACTION" && f.severity === "HIGH"
    );

    const hasSuspiciousUrlForAuth = suspiciousURL || (urlFindings || []).some(
        f => f && (f.type === "IP_ADDRESS" || f.type === "PUNYCODE_DOMAIN" || f.type === "EXCESSIVE_SUBDOMAINS")
    );

    const isHiddenPasswordForm = (formFindings || []).some(
        f => f && f.type === "HIDDEN_FORM_CONTROLS"
    );

    if (hasPasswordField) {
        if (isInsecureHttp || isCrossOriginPassword || hasSuspiciousUrlForAuth || isHiddenPasswordForm) {
            score += 35;
            signals.push("Password field operating in suspicious or unencrypted context");
        }
    }

    // =========================================
    // 3. CROSS-ORIGIN FORM (CREDENTIAL HARVESTING)
    // =========================================
    const crossOriginPasswordForm = (formFindings || []).some(
        f => f && f.type === "CROSS_ORIGIN_ACTION" && f.severity === "HIGH"
    );

    const crossOriginGeneralForm = (formFindings || []).some(
        f => f && f.type === "CROSS_ORIGIN_ACTION" && f.severity !== "HIGH"
    );

    if (crossOriginPasswordForm) {
        score += 45;
        signals.push("Form submits sensitive passwords to an external origin (credential harvesting risk)");
    } else if (crossOriginGeneralForm && hasSuspiciousUrlForAuth) {
        score += 20;
        signals.push("Cross-origin form submission on a suspicious host");
    }

    // =========================================
    // 4. SUSPICIOUS FORM STRUCTURE
    // =========================================
    const suspiciousForm = (formFindings || []).some(
        f => f && f.type === "SUSPICIOUS_FORM_STRUCTURE"
    );

    if (suspiciousForm) {
        score += 20;
        signals.push("Suspicious form structure detected");
    }

    // =========================================
    // 5. IFRAME CONTEXT & BEHAVIOR ANALYSIS
    // =========================================
    // Verified third-party iframes (reCAPTCHA, Turnstile, Stripe, PayPal, YouTube)
    // are standard web components and do NOT contribute to phishing risk.
    // Only hidden iframes, untrusted iframe sources, or unverified iframes on suspicious hosts add score.
    const suspiciousIframe = (scriptIframeFindings || []).some(
        f => f && (f.type === "SUSPICIOUS_IFRAME_SOURCE" || f.type === "DANGEROUS_IFRAME_SANDBOX")
    );

    const hiddenIframe = (scriptIframeFindings || []).some(
        f => f && f.type === "HIDDEN_IFRAME"
    );

    const unverifiedCrossOriginIframe = (scriptIframeFindings || []).some(
        f => f && f.type === "CROSS_ORIGIN_IFRAME" && !f.isVerifiedProvider
    );

    if (suspiciousIframe) {
        score += 30;
        signals.push("Suspicious iframe source or dangerous sandbox configuration detected");
    }

    if (hiddenIframe) {
        score += 20;
        signals.push("Hidden or zero-pixel iframe detected");
    }

    if (unverifiedCrossOriginIframe && hasSuspiciousUrlForAuth) {
        score += 15;
        signals.push("Unverified cross-origin iframe on a suspicious host");
    }

    // =========================================
    // 6. SUSPICIOUS EXTERNAL SCRIPT
    // =========================================
    const suspiciousScript = (scriptIframeFindings || []).some(
        f => f && f.type === "SUSPICIOUS_SCRIPT_SOURCE"
    );

    if (suspiciousScript) {
        score += 30;
        signals.push("Suspicious external script source detected");
    }

    // =========================================
    // 7. RISK LEVEL
    // =========================================

    let risk = "SAFE";

    if (score >= 60) {
        risk = "HIGH";
    } else if (score >= 30) {
        risk = "MEDIUM";
    } else if (score > 0) {
        risk = "LOW";
    }

    // =========================================
    // 9. RESULT
    // =========================================

    return {
        score: score,
        risk: risk,
        level: risk,
        signals: signals
    };

}

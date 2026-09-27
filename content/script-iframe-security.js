console.log("SentinelAI Script & Iframe Security Engine loaded");


function analyzeScriptIframeSecurity() {

    const findings = [];


    // =========================================
    // 1. EXTERNAL SCRIPTS
    // =========================================

    const scripts =
        document.querySelectorAll("script[src]");

    let externalScriptCount = 0;

    scripts.forEach((script) => {

        const src = script.src;

        if (!src) {
            return;
        }

        try {

            const scriptURL =
                new URL(
                    src,
                    window.location.href
                );

            if (
                scriptURL.origin !==
                window.location.origin
            ) {

                externalScriptCount++;

            }

        } catch (error) {
            // Ignore invalid URLs
        }

    });


    if (externalScriptCount > 0) {

        findings.push({
            category: "SCRIPT",
            type: "EXTERNAL_SCRIPT",
            severity: "LOW",
            reason:
                `${externalScriptCount} external script(s) detected`
        });

    }


    // =========================================
    // 2. SUSPICIOUS SCRIPT SOURCES
    // =========================================

    const suspiciousDomains = [
        "unknown-domain.example",
        "malicious.example",
        "evil.example"
    ];

    scripts.forEach((script) => {

        const src = script.src;

        if (!src) {
            return;
        }

        try {

            const scriptURL =
                new URL(
                    src,
                    window.location.href
                );

            const hostname =
                scriptURL.hostname.toLowerCase();


            if (
                suspiciousDomains.includes(hostname)
            ) {

                findings.push({
                    category: "SCRIPT",
                    type: "SUSPICIOUS_SCRIPT_SOURCE",
                    severity: "HIGH",
                    reason:
                        `Suspicious external script source detected: ${hostname}`
                });

            }

        } catch (error) {
            // Ignore invalid URLs
        }

    });


    // =========================================
    // 3. INLINE SCRIPT INDICATORS
    // =========================================

    const inlineScripts =
        document.querySelectorAll(
            "script:not([src])"
        );


    if (inlineScripts.length > 0) {

        findings.push({
            category: "SCRIPT",
            type: "INLINE_SCRIPT",
            severity: "LOW",
            reason:
                `${inlineScripts.length} inline script(s) detected`
        });

    }


    // =========================================
    // 4. DANGEROUS JAVASCRIPT APIs
    // =========================================

    const dangerousAPIs = [
        "eval(",
        "document.write(",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "setTimeout(",
        "setInterval("
    ];


    let dangerousAPICount = 0;


    inlineScripts.forEach((script) => {

        const code =
            script.textContent || "";


        dangerousAPIs.forEach((api) => {

            if (code.includes(api)) {

                dangerousAPICount++;

            }

        });

    });


    if (dangerousAPICount > 0) {

        findings.push({
            category: "SCRIPT",
            type: "DANGEROUS_API",
            severity: "MEDIUM",
            reason:
                `${dangerousAPICount} potentially dangerous JavaScript API reference(s) detected`
        });

    }


    // =========================================
    // 5. IFRAMES
    // =========================================

    const iframes =
        document.querySelectorAll("iframe");


    if (iframes.length > 0) {

        findings.push({
            category: "IFRAME",
            type: "IFRAME_DETECTED",
            severity: "LOW",
            reason:
                `${iframes.length} iframe(s) detected`
        });

    }


    // =========================================
    // 6. CROSS-ORIGIN IFRAMES
    // =========================================

    let crossOriginIframeCount = 0;


    iframes.forEach((iframe) => {

        const src =
            iframe.getAttribute("src");


        if (!src) {
            return;
        }


        try {

            const iframeURL =
                new URL(
                    src,
                    window.location.href
                );


            if (
                iframeURL.origin !==
                window.location.origin
            ) {

                crossOriginIframeCount++;

            }

        } catch (error) {
            // Ignore invalid URLs
        }

    });


    if (crossOriginIframeCount > 0) {

        findings.push({
            category: "IFRAME",
            type: "CROSS_ORIGIN_IFRAME",
            severity: "MEDIUM",
            reason:
                `${crossOriginIframeCount} cross-origin iframe(s) detected`
        });

    }


    // =========================================
    // 7. HIDDEN IFRAMES
    // =========================================

    let hiddenIframeCount = 0;


    iframes.forEach((iframe) => {

        const style =
            window.getComputedStyle(iframe);


        const hiddenByStyle =
            style.display === "none" ||
            style.visibility === "hidden";


        const hiddenByAttribute =
            iframe.hidden ||
            iframe.hasAttribute("hidden");


        if (
            hiddenByStyle ||
            hiddenByAttribute
        ) {

            hiddenIframeCount++;

        }

    });


    if (hiddenIframeCount > 0) {

        findings.push({
            category: "IFRAME",
            type: "HIDDEN_IFRAME",
            severity: "MEDIUM",
            reason:
                `${hiddenIframeCount} hidden iframe(s) detected`
        });

    }


    // =========================================
    // 8. SUSPICIOUS IFRAME SOURCE
    // =========================================

    iframes.forEach((iframe) => {

        const src =
            iframe.getAttribute("src");


        if (!src) {
            return;
        }


        try {

            const iframeURL =
                new URL(
                    src,
                    window.location.href
                );


            const hostname =
                iframeURL.hostname.toLowerCase();


            if (
                suspiciousDomains.includes(hostname)
            ) {

                findings.push({
                    category: "IFRAME",
                    type: "SUSPICIOUS_IFRAME_SOURCE",
                    severity: "HIGH",
                    reason:
                        `Suspicious iframe source detected: ${hostname}`
                });

            }

        } catch (error) {
            // Ignore invalid URLs
        }

    });


    // =========================================
    // 9. NO FINDINGS
    // =========================================

    if (findings.length === 0) {

        findings.push({
            category: "SCRIPT_IFRAME",
            type: "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
            severity: "LOW",
            reason:
                "No suspicious script or iframe patterns detected"
        });

    }


    return findings;
}
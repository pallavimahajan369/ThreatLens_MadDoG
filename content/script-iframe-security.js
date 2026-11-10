
function getScriptDomPath(el) {
    if (!el || !el.tagName) return "";
    const path = [];
    let current = el;
    while (current && current.nodeType === 1 && current.tagName !== "HTML" && current.tagName !== "BODY") {
        let selector = current.tagName.toLowerCase();
        if (current.id) {
            selector += `#${current.id}`;
            path.unshift(selector);
            break;
        } else if (current.getAttribute("name")) {
            selector += `[name="${current.getAttribute("name")}"]`;
        } else if (current.className && typeof current.className === "string") {
            const firstClass = current.className.trim().split(/\s+/)[0];
            if (firstClass && !firstClass.includes(":")) selector += `.${firstClass}`;
        }
        path.unshift(selector);
        current = current.parentElement;
    }
    return path.join(" > ") || el.tagName.toLowerCase();
}

function getScriptDocumentFileName() {
    try {
        const u = new URL(window.location.href);
        const segments = u.pathname.split("/").filter(Boolean);
        const last = segments[segments.length - 1];
        if (last) {
            return last + (u.hash ? u.hash : "");
        }
        return u.hostname || "index.html";
    } catch (e) {
        return "index.html";
    }
}

function getScriptFileName(urlStr) {
    if (!urlStr) return "script.js";
    try {
        const u = new URL(urlStr, window.location.href);
        const segments = u.pathname.split("/").filter(Boolean);
        const last = segments[segments.length - 1];
        if (last) {
            return last;
        }
        return u.hostname || "script.js";
    } catch (e) {
        return "script.js";
    }
}

function analyzeScriptIframeSecurity(providedCsp = null) {
    const findings = [];
    const currentPageUrl = window.location.href;
    const docFile = getScriptDocumentFileName();

    // =========================================
    // 1. EXTERNAL SCRIPTS
    // =========================================

    const scripts = document.querySelectorAll("script[src]");
    let externalScriptCount = 0;
    const externalScriptItems = [];

    scripts.forEach((script) => {
        const src = script.src;
        if (!src) return;

        try {
            const scriptURL = new URL(src, window.location.href);

            if (scriptURL.origin !== window.location.origin) {
                externalScriptCount++;
                if (externalScriptItems.length < 20) {
                    const fileName = getScriptFileName(scriptURL.href);
                    const domPath = getScriptDomPath(script);
                    externalScriptItems.push({
                        title: `Script: ${fileName}`,
                        location: scriptURL.hostname,
                        preview: src,
                        type: "External Origin Script",
                        detail: `Loaded from: ${scriptURL.origin}`,
                        pageUrl: currentPageUrl,
                        fileName: fileName,
                        sourceUrl: scriptURL.href,
                        sourceType: "External JavaScript File",
                        domPath: domPath
                    });
                }
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
            reason: `${externalScriptCount} external script(s) detected`,
            details: {
                title: "External Third-Party Scripts",
                items: externalScriptItems,
                riskExplanation: "Scripts loaded from external origins execute with full privileges inside the user's browser context. If a third-party domain or CDN is compromised, attackers can inject malicious code directly into the site (Supply Chain Attack).",
                solution: "1. Use Subresource Integrity (SRI) on external scripts: <script src='...' integrity='sha384-...' crossorigin='anonymous'>.\n2. Self-host critical libraries on your own domain whenever possible.\n3. Implement a strict Content-Security-Policy (CSP) script-src directive limiting trusted origins."
            }
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

    const suspiciousScriptItems = [];

    scripts.forEach((script) => {
        const src = script.src;
        if (!src) return;

        try {
            const scriptURL = new URL(src, window.location.href);
            const hostname = scriptURL.hostname.toLowerCase();

            if (suspiciousDomains.includes(hostname)) {
                const fileName = getScriptFileName(scriptURL.href);
                const domPath = getScriptDomPath(script);
                suspiciousScriptItems.push({
                    title: `Suspicious Host: ${hostname}`,
                    location: hostname,
                    preview: src,
                    type: "Untrusted Script Origin",
                    detail: "Host matches known threat pattern list",
                    pageUrl: currentPageUrl,
                    fileName: fileName,
                    sourceUrl: scriptURL.href,
                    sourceType: "Suspicious Script Source",
                    domPath: domPath
                });
            }
        } catch (error) {
            // Ignore invalid URLs
        }
    });

    if (suspiciousScriptItems.length > 0) {
        findings.push({
            category: "SCRIPT",
            type: "SUSPICIOUS_SCRIPT_SOURCE",
            severity: "HIGH",
            reason: `${suspiciousScriptItems.length} suspicious external script source(s) detected`,
            details: {
                title: "Suspicious External Script Sources",
                items: suspiciousScriptItems,
                riskExplanation: "The web page is attempting to load executable JavaScript from a domain flagged as untrusted, suspicious, or known for malicious activities.",
                solution: "1. Immediately remove script references pointing to untrusted domains.\n2. Review your build pipeline and dependencies for unauthorized third-party scripts.\n3. Configure CSP to block unverified domains."
            }
        });
    }

    // =========================================
    // 3. INLINE SCRIPTS
    // =========================================

    const inlineScripts = document.querySelectorAll(
        "script:not([src])"
    );

    if (inlineScripts.length > 0) {
        const inlineScriptItems = [];

        inlineScripts.forEach((script, idx) => {
            const raw = script.textContent || "";
            const trimmed = raw.trim();
            const parent = script.parentElement ? script.parentElement.tagName.toLowerCase() : "dom";
            const lines = raw.split("\n").length;
            const snippet = trimmed.slice(0, 300) + (trimmed.length > 300 ? "..." : "");
            const domPath = getScriptDomPath(script);

            if (inlineScriptItems.length < 20) {
                inlineScriptItems.push({
                    title: `Inline Script #${idx + 1}`,
                location: `<script> inside <${parent}> tag`,
                preview: snippet || "(Empty script block)",
                type: "Inline Execution",
                detail: `Length: ${raw.length} chars | Lines: ${lines}`,
                pageUrl: currentPageUrl,
                fileName: `Inline in HTML (${docFile})`,
                sourceUrl: currentPageUrl,
                sourceType: "Page Document",
                domPath: domPath
                });
            }
        });

        findings.push({
            category: "SCRIPT",
            type: "INLINE_SCRIPT",
            severity: "LOW",
            reason: `${inlineScripts.length} inline script(s) detected`,
            details: {
                title: "Inline JavaScript Blocks",
                items: inlineScriptItems,
                riskExplanation: "Inline JavaScript executes directly inside the HTML markup. Inline scripts make it impossible to enforce a strict Content Security Policy (CSP) without allowing 'unsafe-inline', significantly increasing exposure to Cross-Site Scripting (XSS) vulnerabilities.",
                solution: "1. Extract inline scripts into external .js files served from trusted origins.\n2. Eliminate 'unsafe-inline' from your Content-Security-Policy (CSP) headers.\n3. If inline execution is required, use cryptographic nonces (nonce-...) or SHA-256 script hashes."
            }
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
    const dangerousAPIItems = [];

    inlineScripts.forEach((script, scriptIdx) => {
        const code = script.textContent || "";
        const lines = code.split("\n");

        dangerousAPIs.forEach((api) => {
            if (code.includes(api)) {
                dangerousAPICount++;

                const matchedLine = lines.find((l) => l.includes(api)) || api;
                const parent = script.parentElement ? script.parentElement.tagName.toLowerCase() : "dom";
                const domPath = getScriptDomPath(script);

                if (dangerousAPIItems.length < 20) {
                    dangerousAPIItems.push({
                        title: `API Reference: ${api.replace("(", "")}`,
                        location: `<script> inside <${parent}> tag`,
                        preview: matchedLine.trim().slice(0, 260),
                        type: "Dangerous JavaScript API",
                        detail: `Found in inline script #${scriptIdx + 1} (${api})`,
                        pageUrl: currentPageUrl,
                        fileName: `Inline in HTML (${docFile})`,
                        sourceUrl: currentPageUrl,
                        sourceType: "Page Document",
                        domPath: domPath
                    });
                }
            }
        });
    });

    if (dangerousAPICount > 0) {
        const isCspBlocking = providedCsp && providedCsp.isActive && providedCsp.blocksEval;
        findings.push({
            category: "SCRIPT",
            type: "DANGEROUS_API",
            severity: "LOW",
            isMitigated: isCspBlocking,
            reason: `${dangerousAPICount} potentially dangerous JavaScript API reference(s) detected`,
            details: {
                title: "Dangerous JavaScript APIs Detected",
                items: dangerousAPIItems,
                riskExplanation: "Dangerous APIs like eval(), innerHTML, or string-based setTimeout() allow dynamic code execution and markup injection, making applications vulnerable to arbitrary script execution.",
                solution: "1. Replace eval() and dynamic code generation with native functions or JSON.parse().\n2. Pass function references directly to setTimeout and setInterval instead of string statements.\n3. Enforce CSP without 'unsafe-eval'."
            }
        });
    }

    // =========================================
    // 5. IFRAMES
    // =========================================

    const iframes = document.querySelectorAll("iframe");

    if (iframes.length > 0) {
        const iframeItems = [];

        iframes.forEach((iframe, idx) => {
            const src = iframe.getAttribute("src") || "(about:blank / inline)";
            if (iframeItems.length < 15) {
                const domPath = getScriptDomPath(iframe);
                const fileName = src.startsWith("http") ? getScriptFileName(src) : "iframe.html";
                iframeItems.push({
                    title: `Iframe #${idx + 1}`,
                    location: `<iframe> tag`,
                    preview: src,
                    type: "Embedded Frame",
                    detail: `Sandbox attribute: ${iframe.hasAttribute("sandbox") ? iframe.getAttribute("sandbox") : "None (Unrestricted)"}`,
                    pageUrl: currentPageUrl,
                    fileName: fileName,
                    sourceUrl: src,
                    sourceType: "Embedded Iframe",
                    domPath: domPath
                });
            }
        });

        findings.push({
            category: "IFRAME",
            type: "IFRAME_DETECTED",
            severity: "LOW",
            reason: `${iframes.length} iframe(s) detected`,
            details: {
                title: "Embedded Iframes",
                items: iframeItems,
                riskExplanation: "Iframes embed external web pages inside the current document. Embedded pages can load third-party trackers, run separate JavaScript runtimes, or attempt clickjacking if not properly sandboxed.",
                solution: "1. Add the 'sandbox' attribute to restrict iframe capabilities: <iframe sandbox='allow-scripts allow-same-origin' ...>.\n2. Only embed trusted origins over HTTPS.\n3. Use CSP frame-src and child-src to whitelist allowed frame destinations."
            }
        });
    }

    // =========================================
    // 6. CROSS-ORIGIN IFRAMES
    // =========================================

    let crossOriginIframeCount = 0;
    const crossOriginItems = [];

    iframes.forEach((iframe) => {
        const src = iframe.getAttribute("src");
        if (!src) return;

        try {
            const iframeURL = new URL(src, window.location.href);

            if (iframeURL.origin !== window.location.origin) {
                crossOriginIframeCount++;
                if (crossOriginItems.length < 15) {
                    const fileName = getScriptFileName(iframeURL.href);
                    const domPath = getScriptDomPath(iframe);
                    crossOriginItems.push({
                        title: `Cross-Origin Frame #${crossOriginItems.length + 1}`,
                        location: iframeURL.hostname,
                        preview: src,
                        type: "Third-Party Frame Origin",
                        detail: `Destination Origin: ${iframeURL.origin}`,
                        pageUrl: currentPageUrl,
                        fileName: fileName,
                        sourceUrl: iframeURL.href,
                        sourceType: "Cross-Origin Frame File",
                        domPath: domPath
                    });
                }
            }
        } catch (error) {
            // Ignore invalid URLs
        }
    });

    if (crossOriginIframeCount > 0) {
        findings.push({
            category: "IFRAME",
            type: "CROSS_ORIGIN_IFRAME",
            severity: "LOW",
            reason: `${crossOriginIframeCount} cross-origin iframe(s) detected`,
            details: {
                title: "Cross-Origin Iframes Detected",
                items: crossOriginItems,
                riskExplanation: "A cross-origin iframe is loading content from a completely different domain origin. If the embedded party is compromised, it can attempt to trick users with phishing or clickjacking overlays.",
                solution: "1. Enforce sandbox restrictions on all cross-origin iframes.\n2. Verify that the third-party provider is authenticated and trusted.\n3. Use X-Frame-Options: SAMEORIGIN or CSP frame-ancestors to prevent framing of your own sensitive pages."
            }
        });
    }

    // =========================================
    // 7. HIDDEN IFRAMES
    // =========================================

    let hiddenIframeCount = 0;
    const hiddenIframeItems = [];

    iframes.forEach((iframe, idx) => {
        try {
            const style = window.getComputedStyle(iframe);

            const hiddenByStyle =
                style &&
                (style.display === "none" ||
                style.visibility === "hidden");

            const hiddenByAttribute =
                iframe.hidden ||
                iframe.hasAttribute("hidden");

            if (hiddenByStyle || hiddenByAttribute) {
                hiddenIframeCount++;
                const src = iframe.getAttribute("src") || "(no src)";
                if (hiddenIframeItems.length < 10) {
                    const fileName = src.startsWith("http") ? getScriptFileName(src) : "hidden-frame";
                    const domPath = getScriptDomPath(iframe);
                    hiddenIframeItems.push({
                        title: `Hidden Iframe #${idx + 1}`,
                        location: `<iframe> tag (Hidden)`,
                        preview: src,
                        type: "Invisible Frame",
                        detail: hiddenByAttribute ? "Attribute: hidden" : `Style: ${style.display === "none" ? "display:none" : "visibility:hidden"}`,
                        pageUrl: currentPageUrl,
                        fileName: fileName,
                        sourceUrl: src,
                        sourceType: "Hidden Frame Element",
                        domPath: domPath
                    });
                }
            }
        } catch (error) {
            // Ignore iframe style access errors
        }
    });

    if (hiddenIframeCount > 0) {
        findings.push({
            category: "IFRAME",
            type: "HIDDEN_IFRAME",
            severity: "MEDIUM",
            reason: `${hiddenIframeCount} hidden iframe(s) detected`,
            details: {
                title: "Hidden Iframes Detected",
                items: hiddenIframeItems,
                riskExplanation: "Hidden or invisible iframes are frequently utilized by malvertising, unauthorized tracking networks, or session-hijacking scripts to perform background requests without user visibility.",
                solution: "1. Review necessity of hidden iframes; replace with Fetch / AJAX APIs where possible.\n2. Apply sandbox attributes to prevent top-level navigation by hidden frames.\n3. Audit all third-party analytics and ad tags."
            }
        });
    }

    // =========================================
    // 8. SUSPICIOUS IFRAME SOURCE
    // =========================================

    const suspiciousIframeItems = [];

    iframes.forEach((iframe) => {
        const src = iframe.getAttribute("src");
        if (!src) return;

        try {
            const iframeURL = new URL(src, window.location.href);
            const hostname = iframeURL.hostname.toLowerCase();

            if (suspiciousDomains.includes(hostname)) {
                const fileName = getScriptFileName(iframeURL.href);
                const domPath = getScriptDomPath(iframe);
                suspiciousIframeItems.push({
                    title: `Suspicious Frame Source: ${hostname}`,
                    location: hostname,
                    preview: src,
                    type: "Untrusted Frame Host",
                    detail: "Host matches threat feed list",
                    pageUrl: currentPageUrl,
                    fileName: fileName,
                    sourceUrl: iframeURL.href,
                    sourceType: "Suspicious Frame Host",
                    domPath: domPath
                });
            }
        } catch (error) {
            // Ignore invalid URLs
        }
    });

    if (suspiciousIframeItems.length > 0) {
        findings.push({
            category: "IFRAME",
            type: "SUSPICIOUS_IFRAME_SOURCE",
            severity: "HIGH",
            reason: `${suspiciousIframeItems.length} suspicious iframe source(s) detected: ${suspiciousDomains[0]}`,
            details: {
                title: "Suspicious Iframe Sources",
                items: suspiciousIframeItems,
                riskExplanation: "An iframe is pointing to a domain identified as untrusted or malicious. This presents severe risk of drive-by downloads or credential theft.",
                solution: "1. Remove the suspicious iframe tag immediately.\n2. Inspect site source and CMS for unauthorized tampering or malicious script injection."
            }
        });
    }

    // =========================================
    // 9. NO FINDINGS (Passed Check)
    // =========================================

    if (findings.length === 0) {
        findings.push({
            category: "SCRIPT_IFRAME",
            type: "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
            severity: "LOW",
            reason: "No suspicious script or iframe patterns detected"
        });
    }

    return findings;
}

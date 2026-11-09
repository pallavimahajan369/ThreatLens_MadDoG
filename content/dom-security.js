
function getDomSecurityDomPath(el) {
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

function getDomDocumentFileName() {
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

function getResourceFileName(urlStr) {
    if (!urlStr) return "resource";
    try {
        const u = new URL(urlStr, window.location.href);
        const segments = u.pathname.split("/").filter(Boolean);
        const last = segments[segments.length - 1];
        if (last) {
            return last;
        }
        return u.hostname || "resource";
    } catch (e) {
        return "resource";
    }
}

function analyzeDOM() {
    const findings = [];
    const currentPageUrl = window.location.href;
    const docFile = getDomDocumentFileName();

    // --------------------------------------------------
    // 1. Forms
    // --------------------------------------------------
    const forms = document.querySelectorAll("form");

    if (forms.length > 0) {
        const formItems = [];
        forms.forEach((form, idx) => {
            if (formItems.length < 15) {
                const action = form.getAttribute("action") || "(current page)";
                const method = (form.getAttribute("method") || "GET").toUpperCase();
                const inputsCount = form.querySelectorAll("input, textarea, select").length;
                const domPath = getDomSecurityDomPath(form);
                formItems.push({
                    title: `Form #${idx + 1} (${method})`,
                    location: `<form> in DOM`,
                    preview: `Action: ${action}`,
                    type: "Form Submission",
                    detail: `Method: ${method} | Input elements: ${inputsCount}`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        });

        findings.push({
            category: "DOM",
            type: "FORMS",
            severity: "LOW",
            reason: `${forms.length} form(s) detected on the page`,
            details: {
                title: "HTML Forms Detected",
                items: formItems,
                riskExplanation: "Forms are the primary interactive entry point for user input. If forms submit via HTTP instead of HTTPS, or submit across untrusted origins, user input can be intercepted or manipulated.",
                solution: "1. Always specify an explicit action and set method='POST' for state-changing forms.\n2. Ensure all form actions point to HTTPS endpoints.\n3. Implement anti-CSRF tokens in all transactional forms."
            }
        });
    }

    // --------------------------------------------------
    // 2. Password + Sensitive Inputs
    // --------------------------------------------------
    const inputs = document.querySelectorAll("input, textarea");

    let passwordCount = 0;
    let sensitiveCount = 0;
    const passwordItems = [];
    const sensitiveItems = [];

    const sensitivePatterns = [
        "email",
        "phone",
        "mobile",
        "username",
        "user",
        "address",
        "ssn",
        "aadhaar",
        "pan",
        "card",
        "credit",
        "cvv",
        "otp"
    ];

    inputs.forEach((input) => {
        const type = (input.type || "").toLowerCase();
        const parentForm = input.closest("form");
        const formInfo = parentForm
            ? `Inside form action: ${parentForm.getAttribute("action") || "(same page)"}`
            : "Standalone input (not inside form)";
        const domPath = getDomSecurityDomPath(input);

        if (type === "password") {
            passwordCount++;
            if (passwordItems.length < 10) {
                passwordItems.push({
                    title: `Password Field: ${input.name || input.id || "unnamed"}`,
                    location: `<input type="password">`,
                    preview: `Name: "${input.name || ""}" | ID: "${input.id || ""}"`,
                    type: "Credential Input",
                    detail: formInfo,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        }

        const value = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "")
        ).toLowerCase();

        const matchedPattern = sensitivePatterns.find(pattern => value.includes(pattern));

        if (matchedPattern && type !== "password") {
            sensitiveCount++;
            if (sensitiveItems.length < 15) {
                sensitiveItems.push({
                    title: `Sensitive Field (${matchedPattern}): ${input.name || input.id || input.placeholder || "unnamed"}`,
                    location: `<input type="${type || "text"}">`,
                    preview: `Name: "${input.name || ""}" | Placeholder: "${input.placeholder || ""}"`,
                    type: "User Data Field",
                    detail: `${formInfo} (Matched pattern: "${matchedPattern}")`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        }
    });

    if (passwordCount > 0) {
        findings.push({
            category: "DOM",
            type: "PASSWORD_FIELD",
            severity: "MEDIUM",
            reason: `${passwordCount} password field(s) detected`,
            details: {
                title: "Password Input Fields Detected",
                items: passwordItems,
                riskExplanation: "Password input fields capture user authentication credentials. If the page is delivered over an insecure connection or submits credentials to an unauthorized domain, credentials can be stolen.",
                solution: "1. Enforce HTTPS across the entire domain with HSTS.\n2. Ensure the parent form submits strictly via HTTPS POST.\n3. Add autocomplete='current-password' or 'new-password' for secure password manager autofill."
            }
        });
    }

    if (sensitiveCount > 0) {
        findings.push({
            category: "DOM",
            type: "SENSITIVE_INPUT",
            severity: "MEDIUM",
            reason: `${sensitiveCount} potentially sensitive input(s) detected`,
            details: {
                title: "Sensitive User Input Fields Detected",
                items: sensitiveItems,
                riskExplanation: "Fields collecting personally identifiable information (PII) such as emails, phone numbers, addresses, or identification numbers require strict transmission security and input validation.",
                solution: "1. Ensure all inputs are submitted exclusively over HTTPS using POST requests.\n2. Never transmit sensitive inputs in URL query parameters (GET forms).\n3. Sanitize and validate inputs on the server side to prevent injection attacks."
            }
        });
    }

    // --------------------------------------------------
    // 3. Iframes
    // --------------------------------------------------
    const iframes = document.querySelectorAll("iframe");

    if (iframes.length > 0) {
        findings.push({
            category: "DOM",
            type: "IFRAME",
            severity: "LOW",
            reason: `${iframes.length} iframe(s) detected`
        });
    }

    // --------------------------------------------------
    // 4. Hidden Elements
    // --------------------------------------------------
    const hiddenElements = document.querySelectorAll(
        '[style*="display: none"], [style*="display:none"], [hidden], [style*="visibility: hidden"], [style*="visibility:hidden"]'
    );

    let hiddenCount = 0;
    const hiddenItems = [];

    hiddenElements.forEach((el) => {
        const tag = el.tagName.toLowerCase();
        if (tag === "script" || tag === "style" || tag === "noscript" || tag === "template") {
            return;
        }

        hiddenCount++;
        if (hiddenItems.length < 15) {
            const id = el.id ? `#${el.id}` : "";
            const className = el.className && typeof el.className === "string" ? `.${el.className.trim().split(" ")[0]}` : "";
            const domPath = getDomSecurityDomPath(el);
            hiddenItems.push({
                title: `Hidden <${tag}> Element`,
                location: `<${tag}${id}${className}>`,
                preview: (el.outerHTML || "").slice(0, 200),
                type: "Hidden DOM Node",
                detail: `Hidden style or attribute on <${tag}>`,
                pageUrl: currentPageUrl,
                fileName: `Inline in HTML (${docFile})`,
                sourceUrl: currentPageUrl,
                sourceType: "Page Document",
                domPath: domPath
            });
        }
    });

    if (hiddenCount > 0) {
        findings.push({
            category: "DOM",
            type: "HIDDEN_ELEMENTS",
            severity: "LOW",
            reason: `${hiddenCount} hidden element(s) detected`,
            details: {
                title: "Hidden DOM Elements",
                items: hiddenItems,
                riskExplanation: "Hidden elements are commonly used for UI components (dropdowns, modals, tabs). However, attackers and malicious scripts can hide phishing text, clickjacking overlays, or hidden tracking pixels.",
                solution: "1. Verify that hidden elements are part of valid UI workflows.\n2. Ensure hidden elements do not contain sensitive unmasked credentials or tracking beacons.\n3. Audit third-party widgets for injected invisible containers."
            }
        });
    }

    // --------------------------------------------------
    // 5. External Resources
    // --------------------------------------------------
    const resources = document.querySelectorAll(
        'script[src], img[src], link[href], iframe[src]'
    );

    let externalCount = 0;
    const externalResourceItems = [];

    resources.forEach((resource) => {
        const url = resource.src || resource.href;
        if (!url) return;

        try {
            const resourceURL = new URL(url, window.location.href);

            if (resourceURL.origin !== window.location.origin) {
                externalCount++;
                if (externalResourceItems.length < 20) {
                    const tag = resource.tagName.toLowerCase();
                    const fileName = getResourceFileName(resourceURL.href);
                    const domPath = getDomSecurityDomPath(resource);
                    externalResourceItems.push({
                        title: `<${tag}>: ${fileName}`,
                        location: resourceURL.hostname,
                        preview: url,
                        type: `External ${tag.toUpperCase()}`,
                        detail: `Loaded from: ${resourceURL.origin}`,
                        pageUrl: currentPageUrl,
                        fileName: fileName,
                        sourceUrl: resourceURL.href,
                        sourceType: `External ${tag.toUpperCase()} File`,
                        domPath: domPath
                    });
                }
            }
        } catch (error) {
            // Ignore invalid URLs
        }
    });

    if (externalCount > 0) {
        findings.push({
            category: "DOM",
            type: "EXTERNAL_RESOURCE",
            severity: "LOW",
            reason: `${externalCount} external resource(s) detected`,
            details: {
                title: "External Third-Party Resources Loaded",
                items: externalResourceItems,
                riskExplanation: "Loading resources (images, stylesheets, fonts, scripts) from third-party origins creates external dependencies and can leak user referrers or IP addresses to third-party CDNs.",
                solution: "1. Use Referrer-Policy: strict-origin-when-cross-origin to avoid leaking sensitive query URLs.\n2. Host essential assets locally where practical.\n3. Configure CSP (img-src, style-src, font-src) to restrict resource loading to approved domains."
            }
        });
    }

    // --------------------------------------------------
    // 6. Suspicious Form Structure
    // --------------------------------------------------
    const suspiciousForms = [];
    const suspiciousFormItems = [];

    forms.forEach((form, idx) => {
        const password = form.querySelector('input[type="password"]');
        const hiddenFields = form.querySelectorAll('input[type="hidden"]');

        if (password && hiddenFields.length >= 2) {
            suspiciousForms.push(form);
            const hiddenNames = Array.from(hiddenFields).map(h => h.name || "unnamed").join(", ");
            const domPath = getDomSecurityDomPath(form);
            suspiciousFormItems.push({
                title: `Suspicious Form #${idx + 1}`,
                location: `<form action="${form.getAttribute("action") || "(same page)"}">`,
                preview: `Password field present with ${hiddenFields.length} hidden fields: [${hiddenNames}]`,
                type: "Complex Hidden Form",
                detail: `Method: ${(form.getAttribute("method") || "GET").toUpperCase()}`,
                pageUrl: currentPageUrl,
                fileName: `Inline in HTML (${docFile})`,
                sourceUrl: currentPageUrl,
                sourceType: "Page Document",
                domPath: domPath
            });
        }
    });

    if (suspiciousForms.length > 0) {
        findings.push({
            category: "DOM",
            type: "SUSPICIOUS_FORM_STRUCTURE",
            severity: "MEDIUM",
            reason: `${suspiciousForms.length} form(s) have suspicious hidden structure`,
            details: {
                title: "Suspicious Form Structure Detected",
                items: suspiciousFormItems,
                riskExplanation: "Forms that combine password fields with multiple hidden input fields can indicate hidden tracking, credential redirection, or anti-CSRF misconfigurations.",
                solution: "1. Review all hidden input fields to ensure they serve legitimate framework purposes.\n2. Verify the destination action URL points to a secure HTTPS endpoint.\n3. Remove unneeded hidden tracking tokens from login forms."
            }
        });
    }

    // --------------------------------------------------
    // 7. Dangerous DOM Sinks
    // --------------------------------------------------
    const pageScripts = document.scripts;
    let dangerousSinkCount = 0;
    const sinkItems = [];

    const dangerousSinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval("
    ];

    for (let i = 0; i < pageScripts.length; i++) {
        const scriptTag = pageScripts[i];
        const code = scriptTag.textContent || "";
        const lines = code.split("\n");
        const scriptSrc = scriptTag.src;

        for (let j = 0; j < dangerousSinks.length; j++) {
            const sink = dangerousSinks[j];
            if (code.includes(sink)) {
                dangerousSinkCount++;
                const lineContext = lines.find(l => l.includes(sink)) || sink;

                if (sinkItems.length < 20) {
                    const domPath = getDomSecurityDomPath(scriptTag);
                    const fileName = scriptSrc ? getResourceFileName(scriptSrc) : `Inline Script #${i + 1} (${docFile})`;
                    sinkItems.push({
                        title: `DOM Sink: ${sink.replace("(", "")}`,
                        location: scriptSrc ? `External script` : `Inline script #${i + 1}`,
                        preview: lineContext.trim().slice(0, 260),
                        type: "DOM Sinks / Dynamic Injection",
                        detail: `Sink pattern: ${sink}`,
                        pageUrl: currentPageUrl,
                        fileName: fileName,
                        sourceUrl: scriptSrc || currentPageUrl,
                        sourceType: scriptSrc ? "External JavaScript File" : "Inline Script",
                        domPath: domPath
                    });
                }
            }
        }
    }

    if (dangerousSinkCount > 0) {
        findings.push({
            category: "DOM",
            type: "DANGEROUS_DOM_SINK",
            severity: "MEDIUM",
            reason: `${dangerousSinkCount} potentially dangerous DOM sink reference(s) detected`,
            details: {
                title: "Dangerous DOM Sinks Detected",
                items: sinkItems,
                riskExplanation: "DOM sinks like innerHTML, outerHTML, or document.write directly parse raw strings into live HTML. Passing unvalidated user input or URL query parameters into these sinks enables DOM-based Cross-Site Scripting (XSS).",
                solution: "1. Use textContent or innerText instead of innerHTML when displaying dynamic user text.\n2. If HTML markup is required, sanitize input with DOMPurify.\n3. Avoid document.write completely in modern web applications."
            }
        });
    }

    // --------------------------------------------------
    // 8. No findings
    // --------------------------------------------------
    if (findings.length === 0) {
        findings.push({
            category: "DOM",
            type: "NO_SUSPICIOUS_DOM_PATTERN",
            severity: "LOW",
            reason: "No suspicious DOM patterns detected"
        });
    }

    return findings;
}

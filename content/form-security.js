
function getFormDomPath(el) {
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

function getDocumentFileName() {
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

function analyzeFormSecurity() {
    const findings = [];
    const forms = document.querySelectorAll("form");
    const allInputs = document.querySelectorAll("input, textarea");
    const currentPageUrl = window.location.href;
    const docFile = getDocumentFileName();

    // =========================================
    // 1. PASSWORD FIELDS
    // =========================================
    const passwordFields = document.querySelectorAll('input[type="password"]');

    if (passwordFields.length > 0) {
        const items = [];
        passwordFields.forEach((field, idx) => {
            if (items.length < 15) {
                const id = field.id ? `#${field.id}` : "";
                const name = field.name ? `[name="${field.name}"]` : "";
                const placeholder = field.placeholder ? `placeholder="${field.placeholder}"` : "";
                const domPath = getFormDomPath(field);
                items.push({
                    title: `Password Input #${idx + 1}`,
                    location: `<input type="password"${id}${name}>`,
                    preview: `<input type="password" ${id} ${name} ${placeholder}>`.trim(),
                    type: "Credential Input",
                    detail: `In form: ${field.form ? (field.form.id || field.form.getAttribute("action") || "form") : "none"}`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        });

        const isHttp = currentPageUrl.startsWith("http://");
        findings.push({
            category: "FORM",
            type: "PASSWORD_FIELD",
            severity: isHttp ? "HIGH" : "LOW",
            reason: `${passwordFields.length} password field(s) detected`,
            details: {
                title: "Password Input Fields Detected",
                items: items,
                riskExplanation: "Password inputs collect sensitive authentication credentials. If the page is not served over HTTPS or if untrusted third-party scripts run on this page, keystrokes and credentials may be captured by malicious actors (formjacking / credential harvesting).",
                solution: "1. Verify the site is strictly served over HTTPS with HSTS enabled.\n2. Ensure no untrusted third-party scripts run on login/password pages.\n3. Add autocomplete='current-password' or autocomplete='new-password' with anti-CSRF protection."
            }
        });
    }

    // =========================================
    // 2. EMAIL FIELDS
    // =========================================
    const emailFields = document.querySelectorAll('input[type="email"]');

    if (emailFields.length > 0) {
        const items = [];
        emailFields.forEach((field, idx) => {
            if (items.length < 15) {
                const id = field.id ? `#${field.id}` : "";
                const name = field.name ? `[name="${field.name}"]` : "";
                const domPath = getFormDomPath(field);
                items.push({
                    title: `Email Input #${idx + 1}`,
                    location: `<input type="email"${id}${name}>`,
                    preview: `<input type="email" ${id} ${name}>`.trim(),
                    type: "PII Input",
                    detail: `In form: ${field.form ? (field.form.id || field.form.getAttribute("action") || "form") : "none"}`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        });

        findings.push({
            category: "FORM",
            type: "EMAIL_FIELD",
            severity: "LOW",
            reason: `${emailFields.length} email field(s) detected`,
            details: {
                title: "Email Input Fields Detected",
                items: items,
                riskExplanation: "Email fields collect personally identifiable information (PII). Exposed or unencrypted email inputs can lead to identity theft, tracking, or spam if intercepted or exfiltrated.",
                solution: "1. Transmit form data only via secure HTTPS POST requests.\n2. Validate and sanitize email inputs both client-side and server-side.\n3. Use Content Security Policy (CSP) to restrict where submitted data can be sent."
            }
        });
    }

    // =========================================
    // 3. PAYMENT-RELATED FIELDS
    // =========================================
    const paymentPatterns = [
        "card",
        "creditcard",
        "credit-card",
        "debit",
        "cvv",
        "cvc",
        "expiry",
        "expiration",
        "cardnumber",
        "card-number",
        "accountnumber",
        "account-number"
    ];

    let paymentFieldCount = 0;
    const paymentItems = [];

    allInputs.forEach((input) => {
        const metadata = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "") +
            " " +
            (input.autocomplete || "")
        ).toLowerCase();

        const matched = paymentPatterns.some(pattern => metadata.includes(pattern));

        if (matched) {
            paymentFieldCount++;
            if (paymentItems.length < 15) {
                const domPath = getFormDomPath(input);
                paymentItems.push({
                    title: `Payment Field #${paymentFieldCount}`,
                    location: `<${input.tagName.toLowerCase()} id="${input.id || ''}" name="${input.name || ''}">`,
                    preview: `<input type="${input.type || 'text'}" name="${input.name || ''}" placeholder="${input.placeholder || ''}">`,
                    type: "Financial Input",
                    detail: `Matched payment keyword in attributes. Form: ${input.form ? (input.form.id || input.form.getAttribute("action") || 'form') : 'none'}`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        }
    });

    if (paymentFieldCount > 0) {
        findings.push({
            category: "FORM",
            type: "PAYMENT_FIELD",
            severity: "MEDIUM",
            reason: `${paymentFieldCount} payment-related field(s) detected`,
            details: {
                title: "Payment-Related Fields Detected",
                items: paymentItems,
                riskExplanation: "Payment fields collect sensitive financial data such as credit card numbers, CVVs, or expiration dates. Malicious browser extensions or XSS attacks could harvest this information (Magecart/formjacking attacks).",
                solution: "1. Use PCI-DSS compliant hosted iframe fields (e.g., Stripe Elements, PayPal SDK) rather than raw inputs.\n2. Restrict script origins with strict CSP (script-src, connect-src).\n3. Never log or retain unmasked CVV or full credit card numbers."
            }
        });
    }

    // =========================================
    // 4. API-KEY-LIKE INPUTS
    // =========================================
    const apiKeyPatterns = [
        "api-key",
        "apikey",
        "api_key",
        "access-token",
        "access_token",
        "secret",
        "client-secret",
        "client_secret",
        "private-key",
        "bearer-token"
    ];

    const csrfKeywords = [
        "csrf",
        "xsrf",
        "authenticity_token",
        "authenticity-token",
        "antiforgery",
        "anti-forgery"
    ];

    let apiKeyFieldCount = 0;
    const apiKeyItems = [];

    allInputs.forEach((input) => {
        const metadata = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "")
        ).toLowerCase();

        // Standard anti-CSRF protection tokens are NOT leaked secret API keys
        const isCsrf = csrfKeywords.some(kw => metadata.includes(kw));
        if (isCsrf) return;

        const matched = apiKeyPatterns.some(pattern => metadata.includes(pattern));

        if (matched) {
            apiKeyFieldCount++;
            if (apiKeyItems.length < 15) {
                const domPath = getFormDomPath(input);
                apiKeyItems.push({
                    title: `Secret / Key Field #${apiKeyFieldCount}`,
                    location: `<${input.tagName.toLowerCase()} id="${input.id || ''}" name="${input.name || ''}">`,
                    preview: `<input type="${input.type || 'text'}" name="${input.name || ''}" placeholder="${input.placeholder || ''}">`,
                    type: "Credential Input",
                    detail: `Matched secret keyword in attributes. Form: ${input.form ? (input.form.id || 'form') : 'none'}`,
                    pageUrl: currentPageUrl,
                    fileName: `Inline in HTML (${docFile})`,
                    sourceUrl: currentPageUrl,
                    sourceType: "Page Document",
                    domPath: domPath
                });
            }
        }
    });

    if (apiKeyFieldCount > 0) {
        findings.push({
            category: "FORM",
            type: "API_KEY_INPUT",
            severity: "HIGH",
            reason: `${apiKeyFieldCount} API-key-like input(s) detected`,
            details: {
                title: "API Key / Token Inputs Detected",
                items: apiKeyItems,
                riskExplanation: "Fields accepting API keys, secret tokens, or access credentials can expose administrative privileges or cloud resources if submitted insecurely or logged in browser history.",
                solution: "1. Never transmit API secret keys via client-side web forms.\n2. Use OAuth2/OIDC authorization flows or backend session authentication instead.\n3. Rotate any API keys or tokens that may have been entered into untrusted pages."
            }
        });
    }

    // =========================================
    // 5. FORM ACTION
    // =========================================
    const crossOriginItems = [];
    forms.forEach((form, idx) => {
        const action = form.getAttribute("action");

        try {
            const formAction = action
                ? new URL(action, window.location.href)
                : new URL(window.location.href);

            if (
                formAction.origin &&
                formAction.origin !== "null" &&
                formAction.origin !== window.location.origin
            ) {
                if (crossOriginItems.length < 15) {
                    const domPath = getFormDomPath(form);
                    crossOriginItems.push({
                        title: `Cross-Origin Form #${crossOriginItems.length + 1}`,
                        location: `<form action="${formAction.origin}...">`,
                        preview: `Target Origin: ${formAction.origin} | Action: ${formAction.href}`,
                        type: "Cross-Origin Action",
                        detail: `Method: ${(form.getAttribute("method") || "GET").toUpperCase()} | Current origin: ${window.location.origin}`,
                        pageUrl: currentPageUrl,
                        fileName: `Inline in HTML (${docFile})`,
                        sourceUrl: formAction.href,
                        sourceType: "Cross-Origin Endpoint",
                        domPath: domPath
                    });
                }
            }
        } catch (error) {
            // Ignore malformed actions without crashing
        }
    });

    if (crossOriginItems.length > 0) {
        findings.push({
            category: "FORM",
            type: "CROSS_ORIGIN_ACTION",
            severity: "HIGH",
            reason: `${crossOriginItems.length} form(s) submit to a different origin`,
            details: {
                title: "Cross-Origin Form Submissions Detected",
                items: crossOriginItems,
                riskExplanation: "The form submits sensitive user input directly to an external or cross-origin domain. This is a common pattern in phishing sites, clickjacking, or data exfiltration schemes.",
                solution: "1. Verify that the destination domain is an authorized, trusted payment or authentication gateway.\n2. If not intended, change form action to submit to your own verified origin endpoint.\n3. Implement Subresource Integrity and strict Content Security Policy (CSP) form-action directives."
            }
        });
    }

    // =========================================
    // 6. FORM METHOD
    // =========================================
    const sensitiveGetItems = [];
    forms.forEach((form, idx) => {
        const method = (form.getAttribute("method") || "GET").toUpperCase();

        if (method === "GET") {
            const hasSensitiveField = form.querySelector('input[type="password"], input[type="email"]');
            if (hasSensitiveField) {
                if (sensitiveGetItems.length < 15) {
                    const action = form.getAttribute("action") || "(current page)";
                    const domPath = getFormDomPath(form);
                    sensitiveGetItems.push({
                        title: `GET Form with Sensitive Input #${sensitiveGetItems.length + 1}`,
                        location: `<form method="GET" action="${action}">`,
                        preview: `Method: GET | Action: ${action}`,
                        type: "Sensitive GET Method",
                        detail: `Contains sensitive field: <input type="${hasSensitiveField.type}">`,
                        pageUrl: currentPageUrl,
                        fileName: `Inline in HTML (${docFile})`,
                        sourceUrl: currentPageUrl,
                        sourceType: "Page Document",
                        domPath: domPath
                    });
                }
            }
        }
    });

    if (sensitiveGetItems.length > 0) {
        findings.push({
            category: "FORM",
            type: "SENSITIVE_GET_FORM",
            severity: "HIGH",
            reason: "Sensitive input detected in a GET form; submitted data may appear in the URL",
            details: {
                title: "Sensitive Input in GET Form Detected",
                items: sensitiveGetItems,
                riskExplanation: "Forms using the GET method append submitted values (passwords, tokens, or emails) directly into the URL query string. This causes credentials to be stored in plain text in browser history, server logs, web proxies, and referrer headers.",
                solution: "1. Change the form method from 'GET' to 'POST' (method='POST').\n2. Ensure the endpoint processes authentication and sensitive data strictly over HTTPS.\n3. Clear any sensitive parameters from server access logs and browser history."
            }
        });
    }

    // =========================================
    // 7. NO FINDINGS
    // =========================================
    if (findings.length === 0) {
        findings.push({
            category: "FORM",
            type: "NO_FORM_SECURITY_ISSUE",
            severity: "LOW",
            reason: "No suspicious form or input patterns detected"
        });
    }

    return findings;
}

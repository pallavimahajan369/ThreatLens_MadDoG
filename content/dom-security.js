console.log("SentinelAI DOM Security Engine loaded");

function analyzeDOM() {

    const findings = [];

    // 1. Forms
    const forms = document.querySelectorAll("form");

    if (forms.length > 0) {

        findings.push({
            category: "DOM",
            type: "FORMS",
            severity: "LOW",
            reason:
                `${forms.length} form(s) detected on the page`
        });

    }


    // 2. Password fields
    const passwordFields =
        document.querySelectorAll(
            'input[type="password"]'
        );

    if (passwordFields.length > 0) {

        findings.push({
            category: "DOM",
            type: "PASSWORD_FIELD",
            severity: "MEDIUM",
            reason:
                `${passwordFields.length} password field(s) detected`
        });

    }


    // 3. Sensitive inputs
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

    const inputs =
        document.querySelectorAll(
            "input, textarea"
        );

    let sensitiveCount = 0;

    inputs.forEach((input) => {

        const value = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "")
        ).toLowerCase();

        const matched =
            sensitivePatterns.some(pattern =>
                value.includes(pattern)
            );

        if (matched) {
            sensitiveCount++;
        }

    });

    if (sensitiveCount > 0) {

        findings.push({
            category: "DOM",
            type: "SENSITIVE_INPUT",
            severity: "MEDIUM",
            reason:
                `${sensitiveCount} potentially sensitive input(s) detected`
        });

    }


    // 4. Iframes
    const iframes =
        document.querySelectorAll("iframe");

    if (iframes.length > 0) {

        findings.push({
            category: "DOM",
            type: "IFRAME",
            severity: "LOW",
            reason:
                `${iframes.length} iframe(s) detected on the page`
        });

    }


    // 5. Hidden elements
    const allElements =
        document.querySelectorAll("*");

    let hiddenCount = 0;

    allElements.forEach((element) => {

        const style =
            window.getComputedStyle(element);

        if (
            style.display === "none" ||
            style.visibility === "hidden"
        ) {
            hiddenCount++;
        }

    });

    if (hiddenCount > 0) {

        findings.push({
            category: "DOM",
            type: "HIDDEN_ELEMENTS",
            severity: "LOW",
            reason:
                `${hiddenCount} hidden element(s) detected`
        });

    }


    // 6. External resources
    const resources = document.querySelectorAll(
        'script[src], img[src], link[href], iframe[src]'
    );

    let externalCount = 0;

    resources.forEach((resource) => {

        const url =
            resource.src ||
            resource.href;

        if (!url) {
            return;
        }

        try {

            const resourceURL =
                new URL(url, window.location.href);

            if (
                resourceURL.origin !==
                window.location.origin
            ) {
                externalCount++;
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
            reason:
                `${externalCount} external resource(s) detected`
        });

    }


    // 7. Suspicious form structure
    const suspiciousForms = [];

    forms.forEach((form) => {

        const password =
            form.querySelector(
                'input[type="password"]'
            );

        const hiddenFields =
            form.querySelectorAll(
                'input[type="hidden"]'
            );

        if (
            password &&
            hiddenFields.length >= 2
        ) {

            suspiciousForms.push(form);

        }

    });

    if (suspiciousForms.length > 0) {

        findings.push({
            category: "DOM",
            type: "SUSPICIOUS_FORM_STRUCTURE",
            severity: "MEDIUM",
            reason:
                `${suspiciousForms.length} form(s) contain password fields with multiple hidden fields`
        });

    }


    // 8. Dangerous DOM sinks
    const pageScripts =
        Array.from(document.scripts);

    let dangerousSinkCount = 0;

    const dangerousSinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval("
    ];

    pageScripts.forEach((script) => {

        const code =
            script.textContent || "";

        dangerousSinks.forEach((sink) => {

            if (code.includes(sink)) {
                dangerousSinkCount++;
            }

        });

    });

    if (dangerousSinkCount > 0) {

        findings.push({
            category: "DOM",
            type: "DANGEROUS_DOM_SINK",
            severity: "MEDIUM",
            reason:
                `${dangerousSinkCount} potentially dangerous DOM sink reference(s) detected`
        });

    }


    // No findings
    if (findings.length === 0) {

        findings.push({
            category: "DOM",
            type: "NO_SUSPICIOUS_DOM_PATTERN",
            severity: "LOW",
            reason:
                "No suspicious DOM patterns detected"
        });

    }

    return findings;
}
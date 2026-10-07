console.log("SentinelAI DOM Security Engine loaded");

function analyzeDOM() {

    const findings = [];

    // --------------------------------------------------
    // 1. Forms
    // --------------------------------------------------

    const forms =
        document.querySelectorAll("form");

    if (forms.length > 0) {

        findings.push({
            category: "DOM",
            type: "FORMS",
            severity: "LOW",
            reason:
                `${forms.length} form(s) detected on the page`
        });

    }


    // --------------------------------------------------
    // 2. Password + Sensitive Inputs
    // --------------------------------------------------

    const inputs =
        document.querySelectorAll(
            "input, textarea"
        );

    let passwordCount = 0;
    let sensitiveCount = 0;

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

        const type =
            (input.type || "").toLowerCase();

        if (type === "password") {
            passwordCount++;
        }

        const value = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "")
        ).toLowerCase();

        const matched =
            sensitivePatterns.some(
                pattern =>
                    value.includes(pattern)
            );

        if (matched) {
            sensitiveCount++;
        }

    });


    if (passwordCount > 0) {

        findings.push({
            category: "DOM",
            type: "PASSWORD_FIELD",
            severity: "MEDIUM",
            reason:
                `${passwordCount} password field(s) detected`
        });

    }


    if (sensitiveCount > 0) {

        findings.push({
            category: "DOM",
            type: "SENSITIVE_INPUT",
            severity: "MEDIUM",
            reason:
                `${sensitiveCount} potentially sensitive input(s) detected`
        });

    }


    // --------------------------------------------------
    // 3. Iframes
    // --------------------------------------------------

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


    // --------------------------------------------------
    // 4. Hidden Elements
    // --------------------------------------------------

    let hiddenCount = 0;

    /*
     * Only inspect elements that can reasonably
     * participate in visual/content hiding.
     *
     * This avoids querySelectorAll("*") over the
     * complete DOM tree.
     */
    const potentiallyHiddenElements =
        document.querySelectorAll(
            "div, section, article, form, input, textarea, button, a, p, span, img, iframe"
        );

    potentiallyHiddenElements.forEach((element) => {

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


    // --------------------------------------------------
    // 5. External Resources
    // --------------------------------------------------

    const resources =
        document.querySelectorAll(
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
                new URL(
                    url,
                    window.location.href
                );

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


    // --------------------------------------------------
    // 6. Suspicious Form Structure
    // --------------------------------------------------

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


    // --------------------------------------------------
    // 7. Dangerous DOM Sinks
    // --------------------------------------------------

    const pageScripts =
        document.scripts;

    let dangerousSinkCount = 0;

    const dangerousSinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval("
    ];

    for (
        let i = 0;
        i < pageScripts.length;
        i++
    ) {

        const code =
            pageScripts[i].textContent || "";

        for (
            let j = 0;
            j < dangerousSinks.length;
            j++
        ) {

            if (
                code.includes(
                    dangerousSinks[j]
                )
            ) {

                dangerousSinkCount++;

            }

        }

    }


    if (dangerousSinkCount > 0) {

        findings.push({
            category: "DOM",
            type: "DANGEROUS_DOM_SINK",
            severity: "MEDIUM",
            reason:
                `${dangerousSinkCount} potentially dangerous DOM sink reference(s) detected`
        });

    }


    // --------------------------------------------------
    // 8. No Findings
    // --------------------------------------------------

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
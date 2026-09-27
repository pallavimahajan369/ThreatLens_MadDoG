console.log("SentinelAI Form Security Engine loaded");


function analyzeFormSecurity() {

    const findings = [];

    const forms = document.querySelectorAll("form");


    // =========================================
    // 1. PASSWORD FIELDS
    // =========================================

    const passwordFields =
        document.querySelectorAll(
            'input[type="password"]'
        );

    if (passwordFields.length > 0) {

        findings.push({
            category: "FORM",
            type: "PASSWORD_FIELD",
            severity: "MEDIUM",
            reason:
                `${passwordFields.length} password field(s) detected`
        });

    }


    // =========================================
    // 2. EMAIL FIELDS
    // =========================================

    const emailFields =
        document.querySelectorAll(
            'input[type="email"]'
        );

    if (emailFields.length > 0) {

        findings.push({
            category: "FORM",
            type: "EMAIL_FIELD",
            severity: "LOW",
            reason:
                `${emailFields.length} email field(s) detected`
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

    const allInputs =
        document.querySelectorAll(
            "input, textarea"
        );

    let paymentFieldCount = 0;


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


        const matched =
            paymentPatterns.some(pattern =>
                metadata.includes(pattern)
            );


        if (matched) {
            paymentFieldCount++;
        }

    });


    if (paymentFieldCount > 0) {

        findings.push({
            category: "FORM",
            type: "PAYMENT_FIELD",
            severity: "MEDIUM",
            reason:
                `${paymentFieldCount} payment-related field(s) detected`
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
        "token",
        "secret",
        "client-secret",
        "client_secret"
    ];

    let apiKeyFieldCount = 0;


    allInputs.forEach((input) => {

        const metadata = (
            (input.name || "") +
            " " +
            (input.id || "") +
            " " +
            (input.placeholder || "")
        ).toLowerCase();


        const matched =
            apiKeyPatterns.some(pattern =>
                metadata.includes(pattern)
            );


        if (matched) {
            apiKeyFieldCount++;
        }

    });


    if (apiKeyFieldCount > 0) {

        findings.push({
            category: "FORM",
            type: "API_KEY_INPUT",
            severity: "HIGH",
            reason:
                `${apiKeyFieldCount} API-key-like input(s) detected`
        });

    }


    // =========================================
    // 5. FORM ACTION
    // =========================================

    forms.forEach((form) => {

        const action =
            form.getAttribute("action");


        const formAction =
            action
                ? new URL(
                    action,
                    window.location.href
                )
                : new URL(
                    window.location.href
                );


        if (
            formAction.origin !==
            window.location.origin
        ) {

            findings.push({
                category: "FORM",
                type: "CROSS_ORIGIN_ACTION",
                severity: "HIGH",
                reason:
                    `Form submits to a different origin: ${formAction.origin}`
            });

        }

    });


    // =========================================
    // 6. FORM METHOD
    // =========================================

    forms.forEach((form) => {

        const method =
            (
                form.getAttribute("method") ||
                "GET"
            ).toUpperCase();


        if (method === "GET") {

            const hasSensitiveField =
                form.querySelector(
                    'input[type="password"], input[type="email"]'
                );


            if (hasSensitiveField) {

                findings.push({
                    category: "FORM",
                    type: "SENSITIVE_GET_FORM",
                    severity: "HIGH",
                    reason:
                        "Sensitive input detected in a GET form; submitted data may appear in the URL"
                });

            }

        }

    });


    // =========================================
    // 7. NO FINDINGS
    // =========================================

    if (findings.length === 0) {

        findings.push({
            category: "FORM",
            type: "NO_FORM_SECURITY_ISSUE",
            severity: "LOW",
            reason:
                "No suspicious form or input patterns detected"
        });

    }


    return findings;
}
    console.log(
        "SentinelAI Sensitive Data Security Engine loaded"
    );


    // =========================================
    // HELPER: Luhn Validation
    // =========================================

    function isValidLuhn(number) {

        let sum = 0;
        let shouldDouble = false;

        for (
            let i = number.length - 1;
            i >= 0;
            i--
        ) {

            let digit =
                parseInt(number[i], 10);

            if (shouldDouble) {

                digit *= 2;

                if (digit > 9) {
                    digit -= 9;
                }
            }

            sum += digit;

            shouldDouble = !shouldDouble;
        }

        return sum % 10 === 0;
    }


    // =========================================
    // HELPER: AWS Secret Context Detection
    // =========================================

    function hasAWSSecretContext(text, index) {

        const contextStart =
            Math.max(0, index - 100);

        const contextEnd =
            Math.min(
                text.length,
                index + 140
            );

        const context =
            text
                .slice(
                    contextStart,
                    contextEnd
                )
                .toLowerCase();

        const contextPattern =
            /\b(aws[_ -]?secret|secret[_ -]?access[_ -]?key|aws[_ -]?secret[_ -]?access[_ -]?key|secret[_ -]?key)\b/;

        return contextPattern.test(
            context
        );
    }


    // =========================================
    // MAIN ANALYSIS
    // =========================================

    function analyzeSensitiveData() {

        const findings = [];


        // =========================================
        // PAGE TEXT
        // =========================================

        const pageText =
            document.body
                ? document.body.innerText
                : "";


        // =========================================
        // 1. EMAIL ADDRESS
        // =========================================

        const emailPattern =
            /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

        const emails =
            pageText.match(
                emailPattern
            ) || [];


        if (emails.length > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "EMAIL",

                severity:
                    "LOW",

                count:
                    emails.length,

                reason:
                    `${emails.length} email address(es) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 2. JWT
        // =========================================

        const jwtPattern =
            /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

        const jwtTokens =
            pageText.match(
                jwtPattern
            ) || [];


        if (jwtTokens.length > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "JWT",

                severity:
                    "HIGH",

                count:
                    jwtTokens.length,

                reason:
                    `${jwtTokens.length} JWT-like token(s) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 3. AWS ACCESS KEY
        // =========================================

        const awsAccessKeyPattern =
            /\bAKIA[0-9A-Z]{16}\b/g;

        const awsKeys =
            pageText.match(
                awsAccessKeyPattern
            ) || [];


        if (awsKeys.length > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "AWS_ACCESS_KEY",

                severity:
                    "HIGH",

                count:
                    awsKeys.length,

                reason:
                    `${awsKeys.length} AWS access key-like value(s) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 4. AWS SECRET-LIKE VALUE
        // =========================================

        /*
        * IMPORTANT:
        *
        * We intentionally do NOT use:
        *
        * /\b[A-Za-z0-9/+=]{40}\b/g
        *
        * because any random 40-character string
        * could be detected as an AWS secret.
        *
        * Instead, we require nearby AWS-secret context.
        */

        const awsSecretPattern =
            /\b[A-Za-z0-9/+=]{40}\b/g;

        let awsSecretCount = 0;

        let awsSecretMatch;


        while (
            (
                awsSecretMatch =
                    awsSecretPattern.exec(
                        pageText
                    )
            ) !== null
        ) {

            const value =
                awsSecretMatch[0];

            const index =
                awsSecretMatch.index;


            if (
                hasAWSSecretContext(
                    pageText,
                    index
                )
            ) {

                awsSecretCount++;
            }
        }


        if (awsSecretCount > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "AWS_SECRET_LIKE",

                severity:
                    "HIGH",

                count:
                    awsSecretCount,

                reason:
                    `${awsSecretCount} AWS secret-like value(s) detected with AWS secret context`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 5. CREDIT CARD-LIKE VALUE
        // =========================================

        const cardPattern =
            /\b(?:\d[ -]?){13,19}\b/g;

        const cardCandidates =
            pageText.match(
                cardPattern
            ) || [];


        const validCardCandidates =
            cardCandidates.filter(
                (value) => {

                    const digits =
                        value.replace(
                            /\D/g,
                            ""
                        );


                    if (
                        digits.length < 13 ||
                        digits.length > 19
                    ) {
                        return false;
                    }


                    return isValidLuhn(
                        digits
                    );
                }
            );


        if (
            validCardCandidates.length > 0
        ) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "CREDIT_CARD",

                severity:
                    "HIGH",

                count:
                    validCardCandidates.length,

                reason:
                    `${validCardCandidates.length} valid credit-card-like value(s) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 6. TOKEN / SECRET ASSIGNMENT
        // =========================================

        const secretPattern =
            /\b(?:token|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{12,}["']?/gi;

        const secrets =
            pageText.match(
                secretPattern
            ) || [];


        if (secrets.length > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "TOKEN_OR_SECRET",

                severity:
                    "HIGH",

                count:
                    secrets.length,

                reason:
                    `${secrets.length} token/secret-like value(s) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 7. PASSWORD-LIKE VALUE
        // =========================================

        const passwordPattern =
            /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi;

        const passwords =
            pageText.match(
                passwordPattern
            ) || [];


        if (passwords.length > 0) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "PASSWORD_LIKE",

                severity:
                    "HIGH",

                count:
                    passwords.length,

                reason:
                    `${passwords.length} password-like value(s) detected`,

                redactedValue:
                    "[REDACTED]"
            });
        }


        // =========================================
        // 8. NO FINDINGS
        // =========================================

        if (
            findings.length === 0
        ) {

            findings.push({

                category:
                    "SENSITIVE_DATA",

                type:
                    "NO_SENSITIVE_DATA",

                severity:
                    "LOW",

                count:
                    0,

                reason:
                    "No sensitive data patterns detected"
            });
        }


        return findings;
    }
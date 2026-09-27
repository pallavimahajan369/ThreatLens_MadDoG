console.log("SentinelAI URL Security Engine loaded");


// ======================================
// SUSPICIOUS TLDs
// ======================================

const suspiciousTLDs = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq"
];


// ======================================
// SUSPICIOUS KEYWORDS
// ======================================

const suspiciousKeywords = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "wallet",
    "banking",
    "signin",
    "security-alert"
];


// ======================================
// MAIN URL ANALYZER
// ======================================

function analyzeURL(url) {

    const findings = [];

    let parsedURL;

    try {

        parsedURL = new URL(url);

    } catch (error) {

        return [{
            category: "URL",
            severity: "HIGH",
            reason: "Invalid URL detected"
        }];

    }


    // ==================================
    // 1. HTTP vs HTTPS
    // ==================================

    if (parsedURL.protocol === "http:") {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason: "Website is using HTTP instead of HTTPS"

        });

    }


    // ==================================
    // 2. IP-BASED URL
    // ==================================

    const hostname = parsedURL.hostname;

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason: "Website is accessed using an IP address"

        });

    }


    // ==================================
    // 3. SUSPICIOUS TLD
    // ==================================

    const parts = hostname.split(".");

    const tld = parts[parts.length - 1].toLowerCase();

    if (suspiciousTLDs.includes(tld)) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason: `Suspicious top-level domain detected: .${tld}`

        });

    }


    // ==================================
    // 4. EXCESSIVE SUBDOMAINS
    // ==================================

    const subdomainCount =
        Math.max(0, parts.length - 2);

    if (subdomainCount >= 4) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason: "Excessive number of subdomains detected"

        });

    }


    // ==================================
    // 5. URL OBFUSCATION
    // ==================================

    if (
        parsedURL.username ||
        parsedURL.password ||
        hostname.includes("..")
    ) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason: "Potential URL obfuscation pattern detected"

        });

    }


    // ==================================
    // 6. ENCODED CHARACTERS
    // ==================================

    const encodedPattern = /%[0-9A-Fa-f]{2}/;

    if (encodedPattern.test(url)) {

        findings.push({

            category: "URL",

            severity: "LOW",

            reason: "Encoded characters detected in URL"

        });

    }


    // ==================================
    // 7. SUSPICIOUS KEYWORDS
    // ==================================

    const lowerURL = url.toLowerCase();

    const matchedKeywords =
        suspiciousKeywords.filter(keyword =>
            lowerURL.includes(keyword)
        );


    if (matchedKeywords.length >= 2) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason:
                "Multiple suspicious keywords detected: " +
                matchedKeywords.join(", ")

        });

    }


    // ==================================
    // 8. PUNYCODE / LOOKALIKE DOMAIN
    // ==================================

    if (hostname.startsWith("xn--")) {

        findings.push({

            category: "URL",

            severity: "HIGH",

            reason:
                "Punycode domain detected; possible lookalike domain"

        });

    }


    // ==================================
    // 9. UNUSUAL PORT
    // ==================================

    const commonPorts = [
        "",
        "80",
        "443"
    ];

    if (!commonPorts.includes(parsedURL.port)) {

        findings.push({

            category: "URL",

            severity: "LOW",

            reason:
                `Unusual port detected: ${parsedURL.port}`

        });

    }


    // ==================================
    // 10. LONG URL
    // ==================================

    if (url.length > 200) {

        findings.push({

            category: "URL",

            severity: "MEDIUM",

            reason:
                "Unusually long URL detected"

        });

    }


    // ==================================
    // FINAL RESULT
    // ==================================

    if (findings.length === 0) {

        findings.push({

            category: "URL",

            severity: "LOW",

            reason: "No suspicious URL patterns detected"

        });

    }


    return findings;
}
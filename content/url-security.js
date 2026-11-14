

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
            type: "INVALID_URL",
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

            type: "HTTP_PROTOCOL",

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

            type: "IP_ADDRESS",

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

            type: "SUSPICIOUS_TLD",
            severity: "LOW",

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

            type: "EXCESSIVE_SUBDOMAINS",

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

            type: "URL_OBFUSCATION",

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

            type: "ENCODED_CHARACTERS",

            severity: "LOW",

            reason: "Encoded characters detected in URL"

        });

    }


    // ==================================
    // 7. CONTEXT-AWARE SUSPICIOUS KEYWORDS
    // ==================================
    // Keywords like 'login', 'account', 'verify' are completely normal in paths
    // on legitimate websites (e.g. linkedin.com/login, accounts.google.com, github.com/account/settings).
    // They ONLY indicate suspicious phishing behavior when used deceptively:
    // a) Embedded in subdomains (e.g. login.paypal.attacker.com), OR
    // b) Combined with an IP-based host, suspicious TLD, or excessive subdomains.
    const hostLower = hostname.toLowerCase();
    const isHostStructurallySuspicious = ipPattern.test(hostname) ||
                                         suspiciousTLDs.includes(tld) ||
                                         subdomainCount >= 3;

    // Check if keyword is deceivingly embedded in the host/subdomain
    const keywordsInHost = suspiciousKeywords.filter(k => hostLower.includes(k));
    const keywordsInPath = suspiciousKeywords.filter(k => parsedURL.pathname.toLowerCase().includes(k));

    if (
        (keywordsInHost.length >= 2 && isHostStructurallySuspicious) ||
        (keywordsInHost.length >= 1 && isHostStructurallySuspicious) ||
        (keywordsInPath.length >= 2 && isHostStructurallySuspicious)
    ) {
        const detectedKeywords = [...new Set([...keywordsInHost, ...keywordsInPath])];
        findings.push({
            category: "URL",
            type: "SUSPICIOUS_KEYWORDS",
            severity: "LOW", // supporting signal per roadmap
            reason: "Deceptive keywords detected on untrusted URL host or structure: " + detectedKeywords.join(", ")
        });
    }


    // ==================================
    // 8. PUNYCODE / LOOKALIKE DOMAIN
    // ==================================

    if (hostname.startsWith("xn--")) {

        findings.push({

            category: "URL",

            type: "PUNYCODE_DOMAIN",

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

            type: "UNUSUAL_PORT",

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

            type: "LONG_URL",

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

            type: "NO_SUSPICIOUS_URL_PATTERN",

            severity: "LOW",

            reason: "No suspicious URL patterns detected"

        });

    }


    return findings;
}

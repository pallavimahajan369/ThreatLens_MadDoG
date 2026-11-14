
const params = new URLSearchParams(window.location.search);
const tabId = params.get("tabId");
const currentWebsite = params.get("url");

const informationalTypes = [
    "NO_SUSPICIOUS_DOM_PATTERN",
    "NO_FORM_SECURITY_ISSUE",
    "NO_SUSPICIOUS_SCRIPT_IFRAME_PATTERN",
    "NO_SENSITIVE_DATA",
    "NO_PROMPT_INJECTION",
    "NO_SUSPICIOUS_URL_PATTERN",
    "NO_WEB_VULNERABILITY",
    "VERIFIED_THIRD_PARTY_IFRAME"
];

function isRestrictedUrl(url) {
    if (!url) return false;
    const lower = url.toLowerCase();
    return (
        lower.startsWith("chrome://") ||
        lower.startsWith("chrome-extension://") ||
        lower.startsWith("edge://") ||
        lower.startsWith("about:") ||
        lower.startsWith("devtools://") ||
        lower.startsWith("view-source:") ||
        lower.includes("chromewebstore.google.com") ||
        lower.includes("chrome.google.com/webstore")
    );
}

function isSamePage(urlA, urlB) {
    if (!urlA || !urlB) return false;
    try {
        const a = new URL(urlA);
        const b = new URL(urlB);
        return a.origin === b.origin;
    } catch (e) {
        return urlA === urlB;
    }
}

function extractFileNameFromUrl(urlStr, fallback = "index.html") {
    if (!urlStr) return fallback;
    try {
        const u = new URL(urlStr, window.location.href);
        const segs = u.pathname.split("/").filter(Boolean);
        const last = segs[segs.length - 1];
        if (last) {
            return last + (u.hash ? u.hash : "");
        }
        return u.hostname || fallback;
    } catch (e) {
        return fallback;
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==================================
// COMPREHENSIVE FINDINGS KNOWLEDGE BASE
// ==================================

function getKnowledgeBaseEntry(type) {
    if (typeof getRegisteredVulnerability === "function") {
        const reg = getRegisteredVulnerability(type);
        if (reg) {
            return {
                title: reg.title,
                riskExplanation: reg.riskExplanation,
                solution: reg.solution
            };
        }
    }
    return findingKnowledgeBase[type] || {};
}

const findingKnowledgeBase = {
    BRUTE_FORCE_SUSCEPTIBLE_LOGIN: {
        title: "Brute Force Susceptible Authentication",
        riskExplanation: "The authentication mechanism does not enforce rate limiting, account lockout thresholds, or CAPTCHA validation. Attackers can execute automated dictionary or credential-stuffing attacks to compromise user and administrator accounts.",
        solution: "1. Implement progressive account lockouts after consecutive failed login attempts.\n2. Enforce IP-based rate limiting (e.g. max 5 attempts per minute).\n3. Deploy Multi-Factor Authentication (MFA) and CAPTCHA."
    },
    CROSS_SITE_REQUEST_FORGERY: {
        title: "Cross-Site Request Forgery (CSRF) Endpoint",
        riskExplanation: "Sensitive operations (such as password modification or account updates) can be triggered without anti-CSRF tokens. An attacker can craft a malicious external page that submits unauthorized requests using the victim's active session.",
        solution: "1. Include cryptographically unpredictable anti-CSRF tokens in all state-changing forms.\n2. Set SameSite=Lax or SameSite=Strict attributes on session cookies.\n3. Require verification of current credentials before applying critical updates."
    },
    UNRESTRICTED_FILE_UPLOAD: {
        title: "Unrestricted File Upload Endpoint",
        riskExplanation: "The file upload handler accepts arbitrary files without validating file extensions or MIME types server-side. Attackers can upload executable web shells (.php, .jsp, .phtml) to obtain interactive Remote Code Execution (RCE) on the host.",
        solution: "1. Validate file extensions strictly against an allowlist of image extensions (jpg, png, gif).\n2. Store uploaded files in an isolated directory outside the web root with script execution disabled.\n3. Generate randomized filenames and re-encode images."
    },
    INSECURE_CAPTCHA_BYPASS: {
        title: "Insecure CAPTCHA / Multi-Step Logic Bypass",
        riskExplanation: "The application relies on client-side state flags (such as 'step=2' or 'passed_captcha=true') to verify CAPTCHA completion. Attackers can manipulate request parameters to bypass verification entirely.",
        solution: "1. Verify CAPTCHA responses strictly server-side before executing privileged operations.\n2. Never trust client-supplied status flags.\n3. Invalidate CAPTCHA tokens immediately after first use."
    },
    BLIND_SQL_INJECTION_ENDPOINT: {
        title: "Blind / Time-Based SQL Injection Target Endpoint",
        riskExplanation: "The application passes user input into backend SQL queries without displaying database errors or records directly. Attackers can extract the entire database character-by-character using boolean condition testing or SLEEP() time delays.",
        solution: "1. Use Parameterized Prepared Statements (PDO in PHP, PreparedStatement in Java/Node).\n2. Enforce strict numerical type casting on input parameters: (int)$_GET['id'].\n3. Deploy Web Application Firewall (WAF) inspection."
    },
    WEAK_SESSION_ID_GENERATION: {
        title: "Predictable / Weak Session ID Generation",
        riskExplanation: "The application generates sequential, predictable, or timestamp-based session cookies (such as integer counters). Attackers can predict future or concurrent session IDs to hijack authenticated sessions without entering credentials.",
        solution: "1. Use Cryptographically Secure Pseudo-Random Number Generators (CSPRNG) with at least 128 bits of entropy (e.g. random_bytes(32)).\n2. Rely on proven web framework session handlers.\n3. Mark session cookies with HttpOnly, Secure, and SameSite attributes."
    },
    DOM_XSS_ENDPOINT: {
        title: "DOM-Based Cross-Site Scripting (DOM XSS) Endpoint",
        riskExplanation: "Client-side JavaScript reads input directly from the document location (such as default=English) and executes it into unescaped DOM sinks (document.write or innerHTML), allowing attackers to execute arbitrary JavaScript in the victim's session.",
        solution: "1. Avoid dangerous sinks such as document.write() and innerHTML.\n2. Use safe text assignment APIs like textContent or innerText.\n3. Sanitize untrusted input with DOMPurify."
    },
    REFLECTED_XSS_ENDPOINT: {
        title: "Reflected Cross-Site Scripting (Reflected XSS) Endpoint",
        riskExplanation: "The web application reflects user query parameters directly into the HTML response without context-aware HTML entity encoding. Attackers can craft deceptive links that execute malicious JavaScript when opened by victims.",
        solution: "1. Apply context-aware HTML entity encoding: htmlspecialchars(string, ENT_QUOTES, 'UTF-8').\n2. Implement a Content Security Policy (CSP) header: script-src 'self'.\n3. Set HttpOnly flags on session cookies."
    },
    STORED_XSS_ENDPOINT: {
        title: "Stored / Persistent Cross-Site Scripting Endpoint",
        riskExplanation: "The application stores user input (such as comments or guestbook messages) in backend databases and displays it to subsequent visitors without sanitization. The malicious script executes automatically in the browser of every visitor.",
        solution: "1. Context-encode all dynamic values before rendering them in the DOM.\n2. Validate and sanitize input strings server-side using HTML sanitization libraries.\n3. Enforce a strict Content Security Policy (CSP) that disables inline script execution."
    },
    CSP_BYPASS_VULNERABILITY: {
        title: "Content Security Policy (CSP) Bypass Endpoint",
        riskExplanation: "The page configures a Content Security Policy with weaknesses (such as allowing 'unsafe-inline', wildcards '*', or hosting JSONP endpoints) that permit attackers to bypass script restrictions.",
        solution: "1. Eliminate 'unsafe-inline' and 'unsafe-eval' from the CSP header.\n2. Implement cryptographic script nonces: script-src 'nonce-RANDOM'.\n3. Restrict object-src to 'none' and base-uri to 'self'."
    },
    CLIENT_SIDE_SECURITY_BYPASS: {
        title: "Client-Side Security Control Bypass",
        riskExplanation: "The application attempts to enforce access control or token validation entirely inside client-side JavaScript. Because client-side code is fully controllable by users, attackers can manipulate JavaScript variables and bypass the control.",
        solution: "1. Never rely on client-side JavaScript for access control, authorization, or business logic.\n2. Enforce all validation and permission checks on the server.\n3. Treat all client submissions as untrusted."
    },
    DATABASE_SETUP_EXPOSURE: {
        title: "Exposed Database Setup & Reset Interface",
        riskExplanation: "The setup script allows unauthenticated visitors to initialize, reset, or drop database tables and revert credentials to factory defaults. Attackers can wipe application data or reset administrative access.",
        solution: "1. Delete setup.php immediately after installation.\n2. Restrict access to administrative scripts using web server authorization and IP allowlists."
    },
    LAB_SECURITY_CONFIGURATION: {
        title: "DVWA Lab Security Level Configuration",
        riskExplanation: "This page configures the security difficulty level (Low, Medium, High, Impossible) for the DVWA testing environment.",
        solution: "1. In production applications, never expose security configuration switches to public users.\n2. Restrict administrative configurations to authorized administrators."
    },
    LAB_INSTRUCTIONS_PAGE: {
        title: "Penetration Testing Lab Instructions",
        riskExplanation: "Educational instructions for practicing ethical security testing techniques on this lab instance.",
        solution: "1. Lab documentation should remain isolated from production environments."
    },
    PHP_CGI_ARGUMENT_INJECTION: {
        title: "PHP CGI Argument Injection (CVE-2024-4577 / CVE-2012-1823)",
        riskExplanation: "The request or URL parameters match PHP CGI argument injection patterns (e.g. %ad soft hyphen or -d flags). On Windows Apache setups running PHP in CGI mode, Best-Fit character encoding allows attackers to bypass security checks and execute arbitrary operating system commands (Remote Code Execution).",
        solution: "1. Upgrade PHP immediately to patched versions (PHP 8.3.8+, 8.2.20+, or 8.1.29+).\n2. Migrate from Action php-cgi directives to FastCGI (php-fpm).\n3. Deploy Web Application Firewall (WAF) or rewrite rules to reject query strings with %ad or starting with a hyphen (-)."
    },
    PHP_CONFIG_OR_VERSION_DISCLOSURE: {
        title: "Exposed PHP Configuration / Version Disclosure",
        riskExplanation: "The webpage exposes detailed PHP runtime internals (such as a public phpinfo() diagnostic page or outdated PHP runtime banner). Attackers leverage these disclosures to identify vulnerable extensions, internal filesystem paths, and unpatched CVE targets.",
        solution: "1. Immediately delete or password-protect all phpinfo() diagnostic files.\n2. Turn off server signature headers by setting 'expose_php = Off' in php.ini.\n3. Keep the PHP environment updated with current security patches."
    },
    INSECURE_PASSWORD_TRANSMISSION: {
        title: "Insecure Password Transmission (Plaintext / GET Method)",
        riskExplanation: "User credentials or passwords are submitted over unencrypted HTTP or via the HTTP GET method. This causes passwords to be exposed in cleartext across the network, recorded in browser history, and stored in plain text inside server access logs and proxy logs.",
        solution: "1. Enforce HTTPS across all pages with HTTP Strict Transport Security (HSTS).\n2. Form submissions containing passwords MUST use the POST method with encrypted transport.\n3. Set autocomplete='current-password' or 'new-password' on password inputs."
    },
    MISSING_CSRF_PROTECTION: {
        title: "Missing Anti-CSRF Token on State-Changing Form",
        riskExplanation: "This form carries out sensitive state-changing operations (such as password changes, email updates, or financial transactions) via POST without an unpredictable anti-CSRF token. An attacker can trick authenticated users into executing unwanted actions through malicious third-party links or embedded images.",
        solution: "1. Implement cryptographically secure anti-CSRF tokens for all state-changing forms.\n2. Enforce SameSite=Lax or SameSite=Strict attributes on session cookies.\n3. Check Origin and Referer headers on incoming state-changing requests."
    },
    XSS_PAYLOAD_URL: {
        title: "Cross-Site Scripting (XSS) Payload in URL",
        riskExplanation: "The URL query parameters contain active HTML/JavaScript injection payloads (e.g. <script>, javascript:, or event handlers). If reflected into the webpage without context-aware sanitization, attacker code executes within the victim's session.",
        solution: "1. Sanitize and HTML-entity encode all URL parameters before rendering in the DOM.\n2. Enforce a robust Content Security Policy (CSP): script-src 'self'.\n3. Use textContent or DOMPurify rather than innerHTML."
    },
    DOM_XSS_SOURCE_SINK: {
        title: "DOM-Based Cross-Site Scripting Flow Detected",
        riskExplanation: "An inline script reads client-controlled input from the URL (location.search / hash) and directly injects it into an unescaped execution sink (document.write, innerHTML, or eval), executing arbitrary script code entirely within the browser without server round-trips.",
        solution: "1. Replace dangerous sinks (document.write, innerHTML) with safe alternatives (textContent, setAttribute).\n2. Sanitize dynamic HTML using DOMPurify before DOM insertion.\n3. Implement Trusted Types API in supporting browsers."
    },
    COMMAND_INJECTION_PAYLOAD: {
        title: "OS Command Injection Payload in URL",
        riskExplanation: "The URL parameters contain shell metacharacters (;, |, &&, backticks) chained with operating system commands. If concatenated into backend shell execution functions, attackers gain full interactive command shell access to the host.",
        solution: "1. Never execute system commands with user-supplied input.\n2. Use language-specific safe APIs (e.g. child_process.execFile without shell).\n3. Strictly validate inputs against rigid alphanumeric or IP address regular expressions."
    },
    PATH_TRAVERSAL_PAYLOAD: {
        title: "Path Traversal / Local File Inclusion Payload",
        riskExplanation: "The URL or request parameters contain directory traversal sequences (../, %2e%2e/) aimed at breaking out of the web document root to read system configuration files (/etc/passwd, win.ini) or source code.",
        solution: "1. Use basename() to strip directory traversal sequences.\n2. Validate requested files against a strict whitelist of permissible resources.\n3. Ensure the web application user has minimum filesystem read privileges."
    },
    EXPOSED_ADMIN_INTERFACE: {
        title: "Exposed Sensitive Administrative Portal",
        riskExplanation: "An administrative management interface (such as phpMyAdmin, .git repository, .env file, or actuator endpoints) is publicly exposed without IP restriction or multi-factor authentication, inviting brute force attacks and configuration leaks.",
        solution: "1. Restrict administrative portals behind corporate VPN or IP allowlists.\n2. Configure web servers (Nginx/Apache) to deny access to dotfiles (e.g. location ~ /\. { deny all; }).\n3. Disable development and actuator endpoints in production environments."
    },
    POTENTIAL_SSRF_PARAMETER: {
        title: "Potential Server-Side Request Forgery (SSRF) Target",
        riskExplanation: "A URL parameter instructs the server to retrieve remote data from internal loopback addresses (127.0.0.1, localhost), private corporate subnets (10.x, 192.168.x), or cloud metadata services (169.254.169.254), risking internal infrastructure compromise.",
        solution: "1. Enforce a strict domain allowlist for server-side HTTP fetch operations.\n2. Resolve hostnames and block all private, loopback, and link-local IP ranges before connecting.\n3. Disable dangerous protocols (file://, gopher://, dict://)."
    },
    OPEN_REDIRECT_PARAMETER: {
        title: "Potential Open Redirection Parameter",
        riskExplanation: "The application accepts untrusted URL parameters that dictate redirection destinations. Attackers exploit this behavior to construct convincing phishing links that bounce victims through a trusted domain onto fraudulent credential-harvesting pages.",
        solution: "1. Avoid accepting absolute external URLs in redirection parameters; restrict redirects to relative paths.\n2. Validate external destinations against a strict allowlist of trusted domains."
    },
    DIRECTORY_LISTING_ENABLED: {
        title: "Web Server Directory Indexing Enabled",
        riskExplanation: "The web server automatically generates directory listings when index files are missing, exposing the entire folder hierarchy and allowing unauthorized visitors to download backup archives, scripts, and internal documents.",
        solution: "1. Disable directory indexing in Apache ('Options -Indexes') or Nginx ('autoindex off;').\n2. Place empty index.html files in public folders to suppress automated directory indexes."
    },
    VERBOSE_ERROR_DISCLOSURE: {
        title: "Verbose Stack Trace / Error Disclosure",
        riskExplanation: "The application outputs detailed programming call stacks, unhandled exceptions, and database connection strings directly in the HTML response, providing attackers with detailed implementation details and attack vectors.",
        solution: "1. Configure custom generic error pages for HTTP 404, 500, and 502 status codes.\n2. Set display_errors = Off in PHP and debug = False in Django/Flask/Express.\n3. Record detailed exception traces in centralized, access-controlled log stores."
    },
    SESSION_TOKEN_IN_URL: {
        title: "Session Identifier / Secret Token Leaked in URL",
        riskExplanation: "Session identifiers (such as PHPSESSID, JSESSIONID) or bearer tokens are passed in URL query strings. These tokens are leaked into proxy caches, browser history logs, and transmitted in Referer headers when clicking external hyperlinks.",
        solution: "1. Transmit session identifiers exclusively through HTTP-only, Secure, SameSite cookies.\n2. Pass API tokens in HTTP request headers ('Authorization: Bearer <token>') rather than query parameters."
    },
    OUTDATED_VULNERABLE_LIBRARY: {
        title: "Outdated Vulnerable JavaScript Library",
        riskExplanation: "The application includes an outdated client-side JavaScript library (e.g. legacy jQuery < 3.5.0) that has published Common Vulnerabilities and Exposures (CVEs) such as Cross-Site Scripting in htmlPrefilter.",
        solution: "1. Upgrade frontend dependencies to the latest stable release (e.g. jQuery 3.7.1+).\n2. Integrate automated Software Composition Analysis (SCA) into the CI/CD pipeline."
    },
    SQL_INJECTION_ENDPOINT: {
        title: "SQL Injection Target Endpoint Detected",
        riskExplanation: "The current URL matches a known SQL Injection target endpoint (/vulnerabilities/sqli/ or similar). These endpoints typically execute backend SQL queries with parameters from input forms without sanitization, allowing attackers to access unauthorized database records, bypass authentication, or dump user tables.",
        solution: "1. Never concatenate dynamic user parameters into SQL query strings.\n2. Use Parameterized Prepared Statements (PDO in PHP, PreparedStatement in Java/Node).\n3. Enforce strict input validation, type casting (e.g. (int)$_GET['id']), and least-privilege database user permissions."
    },
    POTENTIAL_SQL_INJECTION_FORM: {
        title: "Form Susceptible to SQL Injection",
        riskExplanation: "The page contains an interactive form that transmits database query identifiers (such as 'id' or 'query') via the GET method without input validation or type constraints. An attacker can submit SQL metacharacters (such as ' OR 1=1 --) to extract database contents or hijack administrative accounts.",
        solution: "1. Enforce Parameterized Queries on all server-side query endpoints.\n2. Convert data retrieval forms to use POST with CSRF tokens where appropriate.\n3. Add HTML5 input validation patterns and numerical type constraints."
    },
    SQL_INJECTION_ERROR: {
        title: "Database Error Signature Detected in DOM",
        riskExplanation: "The webpage rendered a visible SQL database error message (e.g. MySQL, PostgreSQL, MSSQL, SQLite syntax error). This indicates that backend SQL queries are failing due to malformed input, confirming an active Error-Based SQL Injection vulnerability.",
        solution: "1. Disable database error display and verbose debugging in production environments (display_errors = Off).\n2. Log errors to secure server-side log files instead of returning them to the user.\n3. Implement parameterized prepared statements to eliminate SQL syntax anomalies."
    },
    SQL_INJECTION_PAYLOAD_URL: {
        title: "SQL Injection Payload Detected in URL",
        riskExplanation: "The URL query parameters contain active SQL Injection attack patterns (e.g. UNION SELECT, boolean condition manipulation, or SQL comment characters).",
        solution: "1. Use parameterized database queries to ensure user input cannot alter SQL syntax structure.\n2. Apply Web Application Firewall (WAF) inspection rules."
    },
    XSS_TARGET_ENDPOINT: {
        title: "Cross-Site Scripting (XSS) Target Endpoint",
        riskExplanation: "The current URL endpoint is identified as a Cross-Site Scripting target. Unsanitized input rendered on this page can execute arbitrary JavaScript in the user's browser session.",
        solution: "1. Context-encode all dynamic values using htmlspecialchars(string, ENT_QUOTES, 'UTF-8').\n2. Enforce a strict Content Security Policy (CSP) header: script-src 'self'.\n3. Sanitize HTML using DOMPurify."
    },
    COMMAND_INJECTION_ENDPOINT: {
        title: "OS Command Injection Endpoint Detected",
        riskExplanation: "The page allows user input to be passed into operating system shell commands (e.g. ping/exec). Attackers can chain shell operators (;, &&, |) to execute arbitrary commands on the server.",
        solution: "1. Avoid passing user input to system shell execution functions.\n2. Whitelist allowed inputs strictly (e.g. validate IP format with regex).\n3. Use parameterized process invocation without shell spawning."
    },
    FILE_INCLUSION_ENDPOINT: {
        title: "File Inclusion / Path Traversal Endpoint",
        riskExplanation: "The application passes file path parameters directly to file inclusion APIs (e.g. include, require). Attackers can traverse directories (../../) to read sensitive system files (e.g. /etc/passwd).",
        solution: "1. Whitelist permitted file names explicitly.\n2. Disable allow_url_include in server configuration.\n3. Sanitize input to reject directory traversal characters (../)."
    },
    INLINE_SCRIPT: {
        title: "Inline Script Execution Detected",
        riskExplanation: "Inline JavaScript runs directly inside HTML markup without origin or file isolation. If attacker-controlled input reaches the page, inline scripts can execute arbitrary JavaScript (Cross-Site Scripting / XSS), allowing attackers to steal session cookies, hijack user accounts, or redirect users to malicious websites.",
        solution: "1. Migrate inline JavaScript code into external .js files.\n2. Configure a strict Content Security Policy (CSP) header: `Content-Security-Policy: script-src 'self' https:;` and remove `'unsafe-inline'`.\n3. If inline scripts are unavoidable, use CSP cryptographic nonces (`nonce-rAnd0m`) or SHA-256 hashes."
    },
    EXTERNAL_SCRIPT: {
        title: "External JavaScript Resources Detected",
        riskExplanation: "External scripts are loaded from outside domains or Content Delivery Networks (CDNs). If a third-party CDN or script repository is compromised or injected with malware, attackers can execute rogue code directly inside your application (Magecart / Supply Chain attacks).",
        solution: "1. Apply Subresource Integrity (SRI) attributes with cryptographic hashes to external scripts: `integrity='sha384-...' crossorigin='anonymous'`.\n2. Whitelist only trusted, reputable CDNs in your Content Security Policy (CSP).\n3. Host mission-critical scripts on your own origin rather than third-party hosts."
    },
    DANGEROUS_API: {
        title: "Potentially Dangerous JavaScript API References",
        riskExplanation: "APIs such as eval(), Function(), setTimeout(string), or setInterval(string) dynamically parse and compile text into executable JavaScript code. If user-controlled data or URL parameters reach these APIs, attackers can achieve remote code execution (DOM-based XSS).",
        solution: "1. Replace `eval()` and `new Function()` with native JavaScript methods or `JSON.parse()` for data decoding.\n2. Pass function references directly to `setTimeout(myFunc, 1000)` instead of code strings `setTimeout('myFunc()', 1000)`.\n3. Disallow `'unsafe-eval'` in Content Security Policy (CSP)."
    },
    DANGEROUS_DOM_SINK: {
        title: "Dangerous DOM Sink References Detected",
        riskExplanation: "DOM sinks like `innerHTML`, `outerHTML`, or `document.write()` parse strings directly as HTML markup. When unsanitized parameters, hash fragments, or user input are assigned to these sinks, malicious HTML/script tags are injected and executed immediately in the user's browser (DOM XSS).",
        solution: "1. Replace `innerHTML` and `outerHTML` with safe text assignment APIs like `textContent` or `innerText` when displaying text.\n2. Build DOM structures safely using `document.createElement()` and `element.setAttribute()`.\n3. If HTML rendering is required, sanitize input using a verified library such as DOMPurify before inserting into the DOM."
    },
    SENSITIVE_INPUT: {
        title: "Sensitive / Personal Data Input Fields Detected",
        riskExplanation: "Input fields that collect credentials, phone numbers, addresses, identity numbers, or personal identifying data (PII) are high-value targets for formjacking, keylogging extensions, and phishing scams.",
        solution: "1. Ensure all sensitive input fields are contained in forms that transmit data strictly over HTTPS POST.\n2. Configure explicit autocomplete attributes (e.g. `autocomplete='username'`) and anti-CSRF protection.\n3. Prevent unauthorized third-party scripts from reading DOM elements on sensitive pages."
    },
    EXTERNAL_RESOURCE: {
        title: "External Third-Party Resources Detected",
        riskExplanation: "The page references multiple external assets (styles, media, fonts, tracking scripts). Insecure external resources can lead to mixed-content warnings, unauthorized third-party tracking, or traffic tampering if served over unencrypted connections.",
        solution: "1. Ensure all external resources are loaded over secure HTTPS connections.\n2. Define strict Content Security Policy directives (`default-src 'self'`, `img-src`, `style-src`) to restrict allowed resource domains.\n3. Audit third-party tracking pixels and remove unneeded marketing tags."
    },
    PASSWORD_FIELD: {
        title: "Password Input Field Detected",
        riskExplanation: "Password fields collect sensitive authentication secrets. If unencrypted or exposed to untrusted third-party scripts or extensions, credentials can be harvested and accounts compromised.",
        solution: "1. Ensure the page enforces HTTPS and HTTP Strict Transport Security (HSTS).\n2. Do not include untrusted third-party scripts or analytics on login and password change pages.\n3. Use strong, unique passwords with a password manager and enable multi-factor authentication (MFA)."
    },
    EMAIL_FIELD: {
        title: "Email Input Field Detected",
        riskExplanation: "Email input fields collect personally identifiable information (PII). Insecure transmission or exposure can lead to credential harvesting, spam, and identity tracking.",
        solution: "1. Submit email forms exclusively via HTTPS POST requests.\n2. Validate and sanitize email format both client-side and server-side.\n3. Apply rate-limiting to prevent automated form submission attacks."
    },
    PAYMENT_FIELD: {
        title: "Financial / Payment Input Detected",
        riskExplanation: "Payment inputs collect credit card numbers, CVVs, expiration dates, or bank account credentials. Malicious browser extensions or XSS attacks could harvest this information (Magecart attacks).",
        solution: "1. Use PCI-DSS compliant hosted iframe fields (such as Stripe Elements or PayPal SDK) rather than raw inputs.\n2. Restrict script origins with strict CSP (`script-src`, `connect-src`).\n3. Never log or retain unmasked CVV or full credit card numbers in browser storage or logs."
    },
    API_KEY_INPUT: {
        title: "API Key / Access Token Input Detected",
        riskExplanation: "Fields accepting API keys, secret tokens, or access credentials can expose administrative privileges or cloud resources if submitted insecurely or logged in browser history.",
        solution: "1. Never transmit API secret keys via client-side web forms.\n2. Use OAuth2/OIDC authorization flows or backend session authentication instead.\n3. Rotate any API keys or tokens that may have been entered into untrusted pages."
    },
    CROSS_ORIGIN_ACTION: {
        title: "Cross-Origin Form Submission",
        riskExplanation: "The form submits sensitive user input directly to a different domain/origin. This is a common pattern in phishing sites, clickjacking, or data exfiltration schemes.",
        solution: "1. Verify that the destination domain is an authorized, trusted payment or authentication gateway.\n2. If not intended, change form action to submit to your own verified origin endpoint.\n3. Implement Subresource Integrity and strict Content Security Policy (CSP) `form-action` directives."
    },
    SENSITIVE_GET_FORM: {
        title: "Sensitive Input in GET Form Detected",
        riskExplanation: "Forms using the GET method append submitted values (passwords, tokens, or emails) directly into the URL query string. This causes credentials to be stored in plain text in browser history, server logs, web proxies, and referrer headers.",
        solution: "1. Change the form method from 'GET' to 'POST' (`method='POST'`).\n2. Ensure the endpoint processes authentication and sensitive data strictly over HTTPS.\n3. Clear any sensitive parameters from server access logs and browser history."
    },
    FORMS: {
        title: "HTML Forms Detected",
        riskExplanation: "Forms are the primary interactive entry point for user input. If forms submit via HTTP instead of HTTPS, or submit across untrusted origins, user input can be intercepted or manipulated.",
        solution: "1. Always specify an explicit action and set `method='POST'` for state-changing forms.\n2. Ensure all form actions point to HTTPS endpoints.\n3. Implement anti-CSRF tokens in all transactional forms."
    },
    HIDDEN_ELEMENTS: {
        title: "Hidden DOM Elements Detected",
        riskExplanation: "Hidden elements can be used by malicious actors for clickjacking, invisible overlay attacks, or stealth data harvesting without user awareness.",
        solution: "1. Inspect hidden inputs and elements to ensure they serve legitimate application purposes.\n2. Remove any obsolete or unauthorized hidden iframes or fields.\n3. Implement X-Frame-Options or CSP frame-ancestors to prevent framing."
    },
    SUSPICIOUS_FORM_STRUCTURE: {
        title: "Suspicious Form Structure Detected",
        riskExplanation: "Forms with missing actions, empty endpoints, or javascript: pseudo-protocol actions can lead to unexpected script execution or unvalidated submissions.",
        solution: "1. Explicitly declare target endpoint actions for all forms.\n2. Avoid using 'javascript:' in form action attributes.\n3. Validate form submission handlers."
    },
    IFRAME_DETECTED: {
        title: "Embedded Iframe Detected",
        riskExplanation: "Iframes embed external web documents. Unrestricted iframes can execute unauthorized code, trigger drive-by downloads, or compromise user sessions.",
        solution: "1. Add the `sandbox` attribute to iframes with minimum required privileges (e.g. `sandbox='allow-scripts'`).\n2. Set CSP `frame-src` to restrict which domains can be framed.\n3. Use HTTPS for all iframe source URLs."
    },
    CROSS_ORIGIN_IFRAME: {
        title: "Cross-Origin Iframe Detected",
        riskExplanation: "The page embeds content from a different domain. If that domain is unverified or malicious, it can perform phishing, clickjacking, or cryptomining in the background.",
        solution: "1. Verify the domain of all embedded third-party iframes.\n2. Restrict iframe permissions using `sandbox='allow-scripts allow-same-origin'`.\n3. Use CSP frame-src directive to enforce trusted sources."
    },
    HIDDEN_IFRAME: {
        title: "Hidden or Zero-Size Iframe Detected",
        riskExplanation: "Completely hidden (0x0 pixel or display:none) iframes are frequently used by malware and adware to perform silent ad-fraud, tracking, or cookie-dropping without user knowledge.",
        solution: "1. Investigate the source URL of hidden iframes.\n2. Remove unnecessary tracking iframes.\n3. Block unauthorized hidden frames using Content Security Policy."
    },
    SUSPICIOUS_IFRAME_SOURCE: {
        title: "Suspicious Iframe Source Detected",
        riskExplanation: "The iframe source points to an unverified or flagged domain, potentially serving phishing or exploit payloads.",
        solution: "1. Do not interact with or provide credentials inside this iframe.\n2. Block the flagged iframe source domain in your network/firewall.\n3. Report phishing domains to Safe Browsing."
    },
    HTTP_PROTOCOL: {
        title: "Unencrypted HTTP Connection",
        riskExplanation: "The connection to this site is unencrypted. Anyone on the same network (e.g. public Wi-Fi) can intercept credentials, session cookies, and modify page contents.",
        solution: "1. Upgrade to HTTPS and configure automatic HTTP-to-HTTPS redirects.\n2. Enforce HTTP Strict Transport Security (HSTS) with a long max-age.\n3. Avoid entering sensitive passwords or payment details on HTTP sites."
    },
    IP_ADDRESS: {
        title: "IP Address Used as Hostname",
        riskExplanation: "Accessing websites directly via raw IP addresses rather than registered domain names is a typical tactic used in malware command-and-control and phishing infrastructure.",
        solution: "1. Use verified, registered domain names with valid SSL/TLS certificates.\n2. Avoid entering credentials or downloading files from raw IP address hosts."
    },
    SUSPICIOUS_TLD: {
        title: "Suspicious Top-Level Domain (TLD)",
        riskExplanation: "Certain free or high-abuse TLDs are statistically correlated with disposable phishing sites, malware distribution, and spam campaigns.",
        solution: "1. Exercise caution before entering credentials or downloading files.\n2. Verify the site's brand authenticity through verified search channels."
    },
    HOMOGLYPH: {
        title: "Homoglyph / Lookalike Domain Detected",
        riskExplanation: "The domain uses visually deceptive characters or lookalikes to impersonate well-known brands (IDN homograph attack).",
        solution: "1. Carefully inspect the address bar for spoofed characters.\n2. Manually type the official website address into your browser."
    },
    PUNYCODE: {
        title: "Punycode (xn--) Domain Detected",
        riskExplanation: "Punycode domain encodings can disguise internationalized spoofed characters to fool users into thinking they are on a trusted website.",
        solution: "1. Verify the decoded hostname in your browser's address bar.\n2. Do not submit sensitive data if the domain does not match the genuine service."
    },
    SUBDOMAIN_COUNT: {
        title: "Excessive Subdomains Detected",
        riskExplanation: "URLs with many nested subdomains often attempt to mimic genuine domains in URL prefixes to mislead users on mobile or truncated address bars.",
        solution: "1. Identify the genuine root domain (the part right before the TLD).\n2. Ensure the root domain belongs to the official organization."
    },
    PORT: {
        title: "Non-Standard Port Detected",
        riskExplanation: "Using non-standard ports (e.g. 8080, 8443, 8888) may indicate temporary testing servers, compromised hosts, or unmanaged infrastructure.",
        solution: "1. Ensure standard secure web ports (443) are used for production websites.\n2. Verify that non-standard ports are intentional and properly secured."
    },
    DATA_URI: {
        title: "Data URI Scheme Detected",
        riskExplanation: "Data URIs encode executable HTML or scripts directly into the URL bar, completely bypassing origin-based web security protections.",
        solution: "1. Avoid opening data: URLs from untrusted links.\n2. Configure CSP to disallow data: URI navigation."
    },
    JWT: {
        title: "JSON Web Token (JWT) Detected in DOM",
        riskExplanation: "JWT tokens in DOM source can grant administrative access or user impersonation if exposed to third-party scripts or stored insecurely.",
        solution: "1. Store authentication tokens in secure, HttpOnly, SameSite cookies instead of DOM or localStorage.\n2. Rotate exposed tokens immediately."
    },
    TOKEN_OR_SECRET: {
        title: "API Secret / Private Token Exposed",
        riskExplanation: "Hardcoded API keys, private credentials, or secrets in client-side code allow anyone inspecting the page to access backend services.",
        solution: "1. Revoke and rotate the exposed secret key immediately.\n2. Move API calls requiring secret keys to backend server functions."
    },
    AWS_ACCESS_KEY: {
        title: "AWS Access Key Detected in DOM",
        riskExplanation: "Exposed cloud credentials (AKIA...) can allow malicious actors to compromise cloud infrastructure and exfiltrate databases.",
        solution: "1. Invalidate and rotate the AWS IAM access key in the AWS console immediately.\n2. Use IAM Roles and STS temporary credentials instead of long-lived access keys."
    },
    CREDIT_CARD: {
        title: "Credit Card Pattern Detected in DOM",
        riskExplanation: "Exposing credit card numbers in DOM text violates PCI-DSS compliance and risks financial fraud.",
        solution: "1. Mask credit card numbers (display only last 4 digits).\n2. Never render full card numbers in plain text HTML."
    },
    GENERIC_PROMPT_INJECTION: {
        title: "Potential Prompt Injection Detected",
        riskExplanation: "The page contains text designed to override, hijack, or deceive AI language models into ignoring instructions or leaking data.",
        solution: "1. Treat all untrusted website content as unverified data.\n2. Separate system instructions from user-provided context using delimiter boundaries and guardrails."
    },
    SYSTEM_OVERRIDE: {
        title: "System Override Prompt Injection Detected",
        riskExplanation: "Input attempting to instruct AI models to 'ignore previous instructions' or assume an unconstrained persona.",
        solution: "1. Apply input sanitization and safety filters before feeding content into AI models.\n2. Use system-level immutable instruction prompts."
    }
};

// ==================================
// SETTINGS HANDLERS
// ==================================
// PROTECTION SETTINGS & KEY CONTROLLER
// ==================================
const geminiApiKeyInput = document.getElementById("geminiApiKeyInput");
const toggleKeyVisibilityBtn = document.getElementById("toggleKeyVisibilityBtn");
const saveAiConfigBtn = document.getElementById("saveAiConfigBtn");
const removeAiConfigBtn = document.getElementById("removeAiConfigBtn");
const testAiConnectionBtn = document.getElementById("testAiConnectionBtn");
const aiConnectionStatusMsg = document.getElementById("aiConnectionStatusMsg");
const aiKeyBadge = document.getElementById("aiKeyBadge");
const triggerAiBtn = document.getElementById("triggerAiBtn");
const aiPromptBanner = document.getElementById("aiPromptBanner");
const scrollToSettingsBtn = document.getElementById("scrollToSettingsBtn");

function updateKeyStatusBadge(hasKey) {
    if (!aiKeyBadge) return;
    if (hasKey) {
        aiKeyBadge.textContent = "CONFIGURED";
        aiKeyBadge.className = "status-pill enabled";
    } else {
        aiKeyBadge.textContent = "NOT CONFIGURED";
        aiKeyBadge.className = "status-pill disabled";
    }
}

// Load saved key state
chrome.storage.local.get(["geminiApiKey"], (cfg) => {
    const key = cfg.geminiApiKey?.trim();
    if (geminiApiKeyInput && key) {
        geminiApiKeyInput.value = key;
    }
    updateKeyStatusBadge(!!key);
    if (key && aiPromptBanner) {
        aiPromptBanner.classList.add("hidden");
    }
});

// Toggle key visibility (Show / Hide eye)
if (toggleKeyVisibilityBtn && geminiApiKeyInput) {
    toggleKeyVisibilityBtn.addEventListener("click", () => {
        const isPassword = geminiApiKeyInput.type === "password";
        geminiApiKeyInput.type = isPassword ? "text" : "password";
        toggleKeyVisibilityBtn.textContent = isPassword ? "🙈" : "👁️";
    });
}

// Save Key
if (saveAiConfigBtn) {
    saveAiConfigBtn.addEventListener("click", () => {
        const key = geminiApiKeyInput ? geminiApiKeyInput.value.trim() : "";
        if (!key) {
            if (aiConnectionStatusMsg) {
                aiConnectionStatusMsg.className = "connection-status-msg status-error";
                aiConnectionStatusMsg.textContent = "⚠️ Please paste a valid Gemini API key first.";
                aiConnectionStatusMsg.classList.remove("hidden");
            }
            return;
        }

        chrome.storage.local.set({ geminiApiKey: key }, () => {
            if (chrome.runtime.lastError) {}
            updateKeyStatusBadge(true);
            if (aiPromptBanner) aiPromptBanner.classList.add("hidden");
            if (aiConnectionStatusMsg) {
                aiConnectionStatusMsg.className = "connection-status-msg status-success";
                aiConnectionStatusMsg.textContent = "✅ Key saved securely in your browser!";
                aiConnectionStatusMsg.classList.remove("hidden");
                setTimeout(() => aiConnectionStatusMsg.classList.add("hidden"), 4000);
            }
        });
    });
}

// Remove Key
if (removeAiConfigBtn) {
    removeAiConfigBtn.addEventListener("click", () => {
        chrome.storage.local.remove(["geminiApiKey"], () => {
            if (geminiApiKeyInput) geminiApiKeyInput.value = "";
            updateKeyStatusBadge(false);
            if (aiConnectionStatusMsg) {
                aiConnectionStatusMsg.className = "connection-status-msg status-error";
                aiConnectionStatusMsg.textContent = "🗑️ Key removed from local storage.";
                aiConnectionStatusMsg.classList.remove("hidden");
                setTimeout(() => aiConnectionStatusMsg.classList.add("hidden"), 3000);
            }
        });
    });
}

// Test Key Connection
if (testAiConnectionBtn) {
    testAiConnectionBtn.addEventListener("click", () => {
        const inputKey = geminiApiKeyInput ? geminiApiKeyInput.value.trim() : "";
        chrome.storage.local.get(["geminiApiKey"], (cfg) => {
            const currentInputKey = inputKey || (cfg.geminiApiKey ? cfg.geminiApiKey.trim() : "");
            if (!currentInputKey) {
                if (aiConnectionStatusMsg) {
                    aiConnectionStatusMsg.className = "connection-status-msg status-error";
                    aiConnectionStatusMsg.textContent = "⚠️ Please paste your Gemini API key in the box first.";
                    aiConnectionStatusMsg.classList.remove("hidden");
                }
                return;
            }

            if (geminiApiKeyInput && !geminiApiKeyInput.value) {
                geminiApiKeyInput.value = currentInputKey;
            }

            // Auto-persist key
            chrome.storage.local.set({ geminiApiKey: currentInputKey }, () => {
                if (chrome.runtime.lastError) {}
                updateKeyStatusBadge(true);
                if (aiPromptBanner) aiPromptBanner.classList.add("hidden");
            });

            if (!aiConnectionStatusMsg) return;
            aiConnectionStatusMsg.className = "connection-status-msg status-testing";
            aiConnectionStatusMsg.textContent = "⏳ Validating key with Google Gemini...";
            aiConnectionStatusMsg.classList.remove("hidden");
            testAiConnectionBtn.disabled = true;

            chrome.runtime.sendMessage({
                type: "TEST_AI_CONNECTION",
                apiKey: currentInputKey
            }, (res) => {
                testAiConnectionBtn.disabled = false;
                if (chrome.runtime.lastError) {
                    aiConnectionStatusMsg.className = "connection-status-msg status-error";
                    aiConnectionStatusMsg.textContent = "❌ Error: " + chrome.runtime.lastError.message;
                    return;
                }
                if (res && res.success) {
                    aiConnectionStatusMsg.className = "connection-status-msg status-success";
                    aiConnectionStatusMsg.textContent = "🟢 " + res.message;
                } else {
                    aiConnectionStatusMsg.className = "connection-status-msg status-error";
                    aiConnectionStatusMsg.textContent = "❌ " + (res?.error || "Key validation failed");
                }
            });
        });
    });
}

// Scroll to settings button from banner
if (scrollToSettingsBtn) {
    scrollToSettingsBtn.addEventListener("click", () => {
        const sec = document.getElementById("aiKeySection");
        if (sec) {
            sec.scrollIntoView({ behavior: "smooth", block: "center" });
            if (geminiApiKeyInput) {
                geminiApiKeyInput.classList.add("highlight-pulse");
                geminiApiKeyInput.focus();
                setTimeout(() => geminiApiKeyInput.classList.remove("highlight-pulse"), 1800);
            }
        }
    });
}

// ==================================
// RENDER AI ANALYSIS
// ==================================
function renderAiAnalysis(aiData) {
    const aiSummaryElement = document.getElementById("aiSummary");
    const aiLaymanElement = document.getElementById("aiLaymanExplanation");
    const aiDataAtRiskContainer = document.getElementById("aiDataAtRiskContainer");
    const aiDataAtRiskWrapper = document.getElementById("aiDataAtRiskWrapper");
    const aiLocationsSection = document.getElementById("aiLocationsSection");
    const aiLocationsContainer = document.getElementById("aiLocationsContainer");
    const aiUserStepsList = document.getElementById("aiUserStepsList");
    const aiDevFixTitle = document.getElementById("aiDevFixTitle");
    const aiDevStepsList = document.getElementById("aiDevStepsList");
    const aiDevCodeWrapper = document.getElementById("aiDevCodeWrapper");
    const aiDevCodeSnippet = document.getElementById("aiDevCodeSnippet");
    const aiUserMessageElement = document.getElementById("aiUserMessage");

    const analysis = aiData?.analysis || (aiData?.summary ? aiData : null);
    if (!analysis) return false;

    // 1. Executive Summary
    if (aiSummaryElement) {
        aiSummaryElement.textContent = analysis.summary || "AI security assessment completed.";
    }

    // 2. Layman Explanation (Conversational, easy-to-understand analogy)
    if (aiLaymanElement) {
        aiLaymanElement.textContent = analysis.layman_explanation ||
            "This scan analyzed the code, forms, and network ports of this page to detect whether data could be intercepted or manipulated.";
    }

    // 3. Potential Exposure Pills
    if (aiDataAtRiskContainer && aiDataAtRiskWrapper) {
        aiDataAtRiskContainer.replaceChildren();
        const dataAtRisk = Array.isArray(analysis.data_at_risk) ? analysis.data_at_risk : [];
        if (dataAtRisk.length > 0) {
            aiDataAtRiskWrapper.style.display = "flex";
            dataAtRisk.forEach((item) => {
                const pill = document.createElement("span");
                pill.className = "risk-pill";
                pill.textContent = "⚠️ " + item;
                aiDataAtRiskContainer.appendChild(pill);
            });
        } else {
            aiDataAtRiskWrapper.style.display = "none";
        }
    }

    // 4. Exact Vulnerability Locations
    if (aiLocationsSection && aiLocationsContainer) {
        aiLocationsContainer.replaceChildren();
        const locs = Array.isArray(analysis.vulnerability_locations) ? analysis.vulnerability_locations : [];
        if (locs.length > 0) {
            aiLocationsSection.style.display = "block";
            locs.forEach((loc) => {
                const card = document.createElement("div");
                card.className = "location-card";

                const titleEl = document.createElement("div");
                titleEl.className = "loc-card-title";
                titleEl.textContent = loc.title || "Security Vulnerability Location";

                const badgeStrip = document.createElement("div");
                badgeStrip.className = "loc-badge-strip";

                if (loc.location) {
                    const locBadge = document.createElement("span");
                    locBadge.className = "loc-badge";
                    locBadge.textContent = "📍 " + loc.location;
                    badgeStrip.appendChild(locBadge);
                }
                if (loc.target) {
                    const targetBadge = document.createElement("span");
                    targetBadge.className = "loc-badge";
                    targetBadge.style.color = "#38bdf8";
                    targetBadge.style.borderColor = "rgba(56, 189, 248, 0.4)";
                    targetBadge.style.background = "rgba(56, 189, 248, 0.15)";
                    targetBadge.textContent = "🎯 " + loc.target;
                    badgeStrip.appendChild(targetBadge);
                }

                const detailEl = document.createElement("div");
                detailEl.className = "loc-card-detail";
                detailEl.textContent = loc.detail || "";

                card.appendChild(titleEl);
                card.appendChild(badgeStrip);
                if (loc.detail) card.appendChild(detailEl);

                aiLocationsContainer.appendChild(card);
            });
        } else {
            aiLocationsSection.style.display = "none";
        }
    }

    // 5. Actionable Steps For You (User Guide)
    if (aiUserStepsList) {
        aiUserStepsList.replaceChildren();
        const userSteps = Array.isArray(analysis.how_to_solve_user) 
            ? analysis.how_to_solve_user 
            : (Array.isArray(analysis.recommendations) 
                ? analysis.recommendations.filter(r => String(r.priority || "").includes("YOU") || String(r.priority || "").includes("IMMEDIATE")).map(r => r.action || r)
                : ["Verify the website domain before entering credentials.", "Review installed browser extensions."]);

        userSteps.forEach(step => {
            const item = document.createElement("div");
            item.className = "step-item";
            item.textContent = String(step);
            aiUserStepsList.appendChild(item);
        });
    }

    // 6. Developer Fix & Code Snippet
    if (aiDevStepsList) {
        aiDevStepsList.replaceChildren();
        const devData = analysis.how_to_secure_dev || {};
        if (aiDevFixTitle && devData.title) {
            aiDevFixTitle.textContent = devData.title;
        }

        const devSteps = Array.isArray(devData.steps) 
            ? devData.steps 
            : (Array.isArray(analysis.recommendations)
                ? analysis.recommendations.filter(r => String(r.priority || "").includes("DEV") || String(r.priority || "").includes("CRITICAL")).map(r => r.action || r)
                : ["Enforce HTTPS port 443 with HSTS.", "Sanitize all dynamic inputs before DOM and database insertion."]);

        devSteps.forEach(step => {
            const item = document.createElement("div");
            item.className = "step-item";
            item.textContent = String(step);
            aiDevStepsList.appendChild(item);
        });

        if (aiDevCodeWrapper && aiDevCodeSnippet) {
            if (devData.code_snippet) {
                aiDevCodeSnippet.textContent = devData.code_snippet;
                aiDevCodeWrapper.style.display = "block";
            } else {
                aiDevCodeWrapper.style.display = "none";
            }
        }
    }

    // 7. Security Verdict
    if (aiUserMessageElement) {
        aiUserMessageElement.textContent = analysis.user_message || "Security analysis verified by ThreatLens Ocular Engine.";
    }

    return true;
}

if (typeof window !== "undefined") {
    window.renderAiAnalysis = renderAiAnalysis;
}

// On-demand Analyze with AI button
if (triggerAiBtn) {
    triggerAiBtn.addEventListener("click", () => {
        const currentInputKey = geminiApiKeyInput ? geminiApiKeyInput.value.trim() : "";
        chrome.storage.local.get(["geminiApiKey"], (cfg) => {
            const savedKey = (cfg.geminiApiKey || currentInputKey)?.trim();
            const activeKey = currentInputKey || savedKey;

            if (!activeKey) {
                if (aiPromptBanner) {
                    aiPromptBanner.classList.remove("hidden");
                }
                const sec = document.getElementById("aiKeySection");
                if (sec) {
                    sec.scrollIntoView({ behavior: "smooth", block: "center" });
                    if (geminiApiKeyInput) {
                        geminiApiKeyInput.classList.add("highlight-pulse");
                        geminiApiKeyInput.focus();
                        setTimeout(() => geminiApiKeyInput.classList.remove("highlight-pulse"), 1800);
                    }
                }
                return;
            }

            if (currentInputKey) {
                chrome.storage.local.set({ geminiApiKey: currentInputKey }, () => {
                    if (chrome.runtime.lastError) {}
                    updateKeyStatusBadge(true);
                });
            }

            if (aiPromptBanner) aiPromptBanner.classList.add("hidden");
            const originalHtml = triggerAiBtn.innerHTML;
            triggerAiBtn.innerHTML = '<span class="btn-icon">⏳</span> Analyzing with Gemini...';
            triggerAiBtn.classList.add("loading");
            triggerAiBtn.disabled = true;

            const aiSummaryEl = document.getElementById("aiSummary");
            const aiWhyEl = document.getElementById("aiWhy");
            const aiRecEl = document.getElementById("aiRecommendations");

            const stages = [
                "⚡ Compacting DOM & security findings...",
                "🧠 Querying Gemini Neural Engine...",
                "🛡️ Formulating instant threat remediation..."
            ];
            let currentStage = 0;
            let stageInterval = null;

            if (aiSummaryEl) {
                aiSummaryEl.innerHTML = '<div class="ai-analyzing-box"><span class="chakra-pulse"></span> <em id="aiStageText">' + stages[0] + '</em></div>';
                stageInterval = setInterval(() => {
                    currentStage = (currentStage + 1) % stages.length;
                    const stageTextEl = document.getElementById("aiStageText");
                    if (stageTextEl) {
                        stageTextEl.textContent = stages[currentStage];
                    }
                }, 1000);
            }
            if (aiWhyEl) aiWhyEl.textContent = "Extracting top vulnerability indicators...";
            if (aiRecEl) aiRecEl.textContent = "Synthesizing remediation strategy...";

            let isFinished = false;
            // 15-second client-side safety watchdog so it NEVER gets stuck
            const watchdog = setTimeout(() => {
                if (!isFinished) {
                    isFinished = true;
                    if (stageInterval) clearInterval(stageInterval);
                    triggerAiBtn.disabled = false;
                    triggerAiBtn.innerHTML = originalHtml;
                    triggerAiBtn.classList.remove("loading");
                    if (aiSummaryEl) {
                        aiSummaryEl.innerHTML = '<span style="color: #f87171;">⚠️ AI analysis timed out. Check your internet connection or click \"✦ Analyze with AI\" to retry.</span>';
                    }
                }
            }, 15000);

            chrome.runtime.sendMessage({
                type: "FORCE_AI_SCAN",
                tabId: tabId ? Number(tabId) : null,
                apiKey: activeKey
            }, (res) => {
                if (isFinished) return;
                isFinished = true;
                clearTimeout(watchdog);
                if (stageInterval) clearInterval(stageInterval);
                triggerAiBtn.disabled = false;
                triggerAiBtn.innerHTML = originalHtml;
                triggerAiBtn.classList.remove("loading");

                if (chrome.runtime.lastError) {
                    console.error("AI trigger error:", chrome.runtime.lastError.message);
                    if (aiSummaryEl) {
                        aiSummaryEl.innerHTML = '<span style="color: #f87171;">❌ AI Trigger Error: ' + chrome.runtime.lastError.message + '</span>';
                    }
                    return;
                }

                if (res && res.success === false) {
                    if (aiSummaryEl) {
                        aiSummaryEl.innerHTML = '<span style="color: #f87171;">❌ AI Analysis Error: ' + (res.error || "Request failed") + '</span>';
                    }
                    return;
                }

                if (aiPromptBanner) aiPromptBanner.classList.add("hidden");
                const freshAnalysis = res?.result?.analysis || res?.analysis || res?.result;
                if (freshAnalysis) {
                    try {
                        const renderFn = (typeof renderAiAnalysis === "function") 
                            ? renderAiAnalysis 
                            : (typeof window !== "undefined" && typeof window.renderAiAnalysis === "function" ? window.renderAiAnalysis : null);
                        if (renderFn) {
                            renderFn(freshAnalysis);
                        }
                    } catch (e) {
                        console.error("ThreatLens: Error rendering AI analysis:", e);
                    }
                }
                loadDashboardData();
            });
        });
    });
}


// ==================================
// MODAL CONTROLLER & DETAILS VIEWER
// ==================================

const modalOverlay = document.getElementById("findingDetailModal");
const modalCloseBtn = document.getElementById("modalCloseBtn");
const modalCloseFooterBtn = document.getElementById("modalCloseFooterBtn");

function closeFindingModal() {
    if (modalOverlay) {
        modalOverlay.classList.add("hidden");
        document.body.style.overflow = "";
    }
}

if (modalCloseBtn) {
    modalCloseBtn.addEventListener("click", closeFindingModal);
}

if (modalCloseFooterBtn) {
    modalCloseFooterBtn.addEventListener("click", closeFindingModal);
}

if (modalOverlay) {
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) {
            closeFindingModal();
        }
    });
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modalOverlay && !modalOverlay.classList.contains("hidden")) {
        closeFindingModal();
    }
});


// =========================================================

// =========================================================
// UNIVERSAL ROBUST FILE DOWNLOAD & CLIPBOARD UTILITIES
// =========================================================

function fallbackAnchorDownload(blobUrl, filename) {
    try {
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = filename;
        link.style.display = "none";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => {
            try { URL.revokeObjectURL(blobUrl); } catch (e) {}
        }, 30000);
    } catch (e) {
        console.error("Fallback anchor download error:", e);
    }
}

function triggerFileDownload(content, filename, mimeType = "text/markdown;charset=utf-8") {
    try {
        const blob = new Blob([content], { type: mimeType });
        const blobUrl = URL.createObjectURL(blob);

        if (typeof chrome !== "undefined" && chrome.downloads && typeof chrome.downloads.download === "function") {
            chrome.downloads.download({
                url: blobUrl,
                filename: filename,
                saveAs: false
            }, (downloadId) => {
                if (chrome.runtime.lastError || !downloadId) {
                    fallbackAnchorDownload(blobUrl, filename);
                } else {
                    setTimeout(() => {
                        try { URL.revokeObjectURL(blobUrl); } catch (e) {}
                    }, 30000);
                }
            });
            return;
        }

        fallbackAnchorDownload(blobUrl, filename);
    } catch (err) {
        console.error("ThreatLens triggerFileDownload error:", err);
    }
}

function fallbackExecCommandCopy(text) {
    return new Promise((resolve, reject) => {
        try {
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.top = "-9999px";
            textarea.style.left = "-9999px";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            const successful = document.execCommand("copy");
            document.body.removeChild(textarea);
            if (successful) {
                resolve();
            } else {
                reject(new Error("execCommand copy returned false"));
            }
        } catch (err) {
            reject(err);
        }
    });
}

function copyTextToClipboard(text) {
    if (!text) return Promise.reject(new Error("No text to copy"));
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        return navigator.clipboard.writeText(text).catch(() => {
            return fallbackExecCommandCopy(text);
        });
    }
    return fallbackExecCommandCopy(text);
}

// HACKERONE / BUGCROWD BUG BOUNTY REPORT GENERATOR
// =========================================================

let currentActiveModalFinding = null;
let currentActiveModalPageUrl = "";
let lastRenderedFindingsList = [];

function generateHackerOneReport(finding, pageUrl) {
    if (!finding) return "";
    const kb = typeof getKnowledgeBaseEntry === "function" ? getKnowledgeBaseEntry(finding.type) : {};
    const cvss = typeof getVulnerabilityCvssAndGuide === "function" ? getVulnerabilityCvssAndGuide(finding.type) : null;
    const title = finding.details?.title || kb.title || finding.reason || finding.type;
    const severity = (finding.severity || "MEDIUM").toUpperCase();
    const cveId = finding.cveId || finding.details?.cveId || cvss?.cveId || (finding.type?.includes("SQL") ? "CWE-89" : "CWE-General");
    const cvssScore = finding.details?.cvssScore || (cvss ? cvss.cvssScore : "6.5");
    const cvssVector = finding.details?.cvssVector || (cvss ? cvss.cvssVector : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
    const location = finding.details?.items?.[0]?.location || finding.details?.location || pageUrl || "Target Endpoint";
    const preview = finding.details?.items?.[0]?.preview || finding.details?.preview || pageUrl;
    const riskExplanation = finding.details?.riskExplanation || kb.risk || finding.reason || "Unauthorized data access or security boundary violation.";
    const solution = finding.details?.solution || kb.solution || "Apply strict server-side input validation, output encoding, and principle of least privilege.";
    const isMitigated = finding.isMitigated || !!finding.details?.cspMitigation;
    const cspDetails = finding.details?.cspMitigation?.details || "None";

    let urlObj = null;
    let hostname = "target-application.com";
    try {
        urlObj = new URL(pageUrl);
        hostname = urlObj.hostname || "target-application.com";
    } catch (e) {}

    let report = "# [Vulnerability Report] [" + cveId + "] " + title + " on " + hostname + "\n\n";

    report += "## Summary\n";
    report += "A **" + severity + "** severity security vulnerability was identified on the target host **" + hostname + "** at endpoint `" + location + "`.\n";
    report += "The application processes dynamic user inputs or parameters without adequate server-side sanitization, matching vulnerability pattern **" + cveId + "** (" + title + ").\n\n";

    report += "## Asset & Vulnerability Details\n";
    report += "- **Target URL:** `" + pageUrl + "`\n";
    report += "- **Vulnerable Endpoint / Location:** `" + location + "`\n";
    report += "- **Weakness Classification:** " + cveId + " (" + title + ")\n";
    report += "- **Severity Rating:** **" + severity + "**\n";
    report += "- **CVSS v3.1 Base Score:** **" + cvssScore + "**\n";
    report += "- **CVSS v3.1 Vector String:** `" + cvssVector + "`\n\n";

    report += "## Proof of Concept (Step-by-Step Reproduction)\n";
    report += "1. Open a modern web browser and navigate to the target endpoint:\n";
    report += "   ```\n   " + pageUrl + "\n   ```\n";
    report += "2. Inspect the affected parameter or interactive component at location:\n";
    report += "   `" + location + "`\n";
    report += "3. Review the reflected payload or source evidence:\n";
    report += "   ```html\n   " + preview + "\n   ```\n";
    report += "4. Observe the response: The application accepts or reflects the input vector without context-aware encoding or parameterization.\n\n";

    report += "## Security & Business Impact\n";
    report += riskExplanation + "\n\n";

    report += "## Defense-in-Depth & Mitigation Posture\n";
    if (isMitigated) {
        report += "- **Mitigation Status:** [MITIGATED / DEFENSE-IN-DEPTH ENFORCED]\n";
        report += "- **Active Defense:** " + cspDetails + "\n";
        report += "*Note for Triager: While the endpoint exhibits the vulnerability pattern, active client-side exploitability is restricted in modern browsers by the enforced Content Security Policy.*\n\n";
    } else {
        report += "- **Mitigation Status:** Unmitigated (Active vulnerability)\n";
        report += "- **Content Security Policy:** Not currently blocking this attack vector.\n\n";
    }

    report += "## Suggested Remediation\n";
    report += "```\n" + solution + "\n```\n\n";

    report += "---\n*Automated Proof of Concept generated via ThreatLens Ocular Security Assistant.*\n";

    return report;
}

function generateAndDownloadBugBountyReport() {
    const scan = lastRenderedScan || {};
    const url = lastRenderedPageUrl || scan.url || window.location.href;
    let hostname = "target-website";
    try {
        hostname = new URL(url).hostname || "target-website";
    } catch (e) {}

    let findings = [];
    if (Array.isArray(lastRenderedFindingsList) && lastRenderedFindingsList.length > 0) {
        findings = [...lastRenderedFindingsList];
    } else {
        findings = [
            ...(scan.webVulnerabilityFindings || []),
            ...(scan.urlFindings || []),
            ...(scan.domFindings || []),
            ...(scan.formFindings || []),
            ...(scan.scriptIframeFindings || []),
            ...(scan.sensitiveDataFindings || []),
            ...(scan.promptInjectionFindings || [])
        ];
    }

    const exportBtn = document.getElementById("exportBugBountyBtn");

    if (findings.length === 0) {
        if (exportBtn) {
            const orig = exportBtn.innerHTML;
            exportBtn.innerHTML = "<span>⚠️ No Findings to Export</span>";
            setTimeout(() => { exportBtn.innerHTML = orig; }, 2500);
        }
        return;
    }

    let fullReport = "# 🎯 ThreatLens Bug Bounty Submission Package\n";
    fullReport += "**Target Host:** " + hostname + "\n";
    fullReport += "**Target URL:** " + url + "\n";
    fullReport += "**Export Date:** " + new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC\n";
    fullReport += "**Ready-to-Submit Vulnerabilities:** " + findings.length + "\n\n";
    fullReport += "---\n\n";

    findings.forEach((f, idx) => {
        fullReport += "---\n\n### Bug Bounty Submission #" + (idx + 1) + "\n\n";
        fullReport += generateHackerOneReport(f, url);
        fullReport += "\n\n";
    });

    const safeHost = hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
    const fileName = "ThreatLens_BugBounty_Package_" + safeHost + "_" + Date.now() + ".md";
    triggerFileDownload(fullReport, fileName, "text/markdown;charset=utf-8");

    if (exportBtn) {
        const orig = exportBtn.innerHTML;
        exportBtn.innerHTML = "<span>✅ Package Downloaded!</span>";
        setTimeout(() => { exportBtn.innerHTML = orig; }, 2500);
    }
}


function openFindingModal(finding, pageUrl) {
    if (!modalOverlay || !finding) return;
    currentActiveModalFinding = finding;
    currentActiveModalPageUrl = pageUrl || lastRenderedPageUrl || "";

    const severity = (finding.severity || "LOW").toUpperCase();
    const type = finding.type || "UNKNOWN";
    const category = finding.category || "SECURITY";
    const kb = findingKnowledgeBase[type] || {
        title: finding.reason || "Security Finding",
        riskExplanation: "This pattern was flagged by ThreatLens because it represents potential security risk, unauthorized behavior, or insecure data handling on the page.",
        solution: "1. Review the flagged elements and code snippets to verify whether this behavior is intended.\n2. Ensure all external and dynamic scripts are properly isolated and sanitized.\n3. Enforce strict Content Security Policy (CSP) and HTTPS headers."
    };

    // Header badge & title
    const modalSeverityBadge = document.getElementById("modalSeverityBadge");
    if (modalSeverityBadge) {
        modalSeverityBadge.textContent = severity;
        modalSeverityBadge.className = `modal-badge badge-${severity.toLowerCase()}`;
    }

    const modalTitle = document.getElementById("modalTitle");
    if (modalTitle) {
        modalTitle.textContent = finding.details?.title || kb.title || finding.reason;
    }

    // Active CSP Mitigation Banner
    const existingCspAlert = document.getElementById("modalCspMitigationAlert");
    if (existingCspAlert) existingCspAlert.remove();

    if (finding.isMitigated || finding.details?.cspMitigation) {
        const mitBox = document.createElement("div");
        mitBox.id = "modalCspMitigationAlert";
        mitBox.className = "csp-mitigation-box";
        const mitDetails = finding.details?.cspMitigation?.details || "This finding's active execution is blocked because the page enforces a strict Content Security Policy.";
        const mitPolicy = finding.details?.cspMitigation?.policySummary || "Strict script-src enforced without 'unsafe-inline'";
        mitBox.innerHTML = `
            <div class="csp-mit-title">🛡️ Active Defense-in-Depth: Content Security Policy Enforced</div>
            <div class="csp-mit-desc">${escapeHtml(mitDetails)}</div>
            <div class="csp-mit-chip">Policy: <strong>${escapeHtml(mitPolicy)}</strong></div>
        `;
        const modalBody = document.querySelector(".modal-body");
        if (modalBody) {
            modalBody.prepend(mitBox);
        }
    }

    // Meta strip
    const modalCategory = document.getElementById("modalCategory");
    if (modalCategory) {
        modalCategory.textContent = category;
    }

    const modalUrl = document.getElementById("modalUrl");
    if (modalUrl) {
        modalUrl.textContent = pageUrl || "Current Website";
        modalUrl.title = pageUrl || "";
    }

    const items = finding.details?.items || [];
    const modalItemsCount = document.getElementById("modalItemsCount");
    if (modalItemsCount) {
        modalItemsCount.textContent = items.length > 0
            ? `${items.length} instance(s)`
            : "1 finding";
    }

    // Itemized Instances Section
    const modalItemsContainer = document.getElementById("modalItemsContainer");
    if (modalItemsContainer) {
        modalItemsContainer.replaceChildren();

        if (items.length > 0) {
            items.forEach((item, index) => {
                const card = document.createElement("div");
                card.className = "modal-item-card";

                const header = document.createElement("div");
                header.className = "item-card-header";

                const title = document.createElement("strong");
                title.className = "item-card-title";
                title.textContent = item.title || `Occurrence #${index + 1}`;

                const loc = document.createElement("span");
                loc.className = "item-card-location";
                loc.textContent = item.location || "DOM Element";

                header.appendChild(title);
                header.appendChild(loc);
                card.appendChild(header);

                // --- SOURCE & LOCATION INFO BOX (PAGE, FILE, DOM PATH) ---
                const itemPageUrl = item.pageUrl || pageUrl || "Current Webpage";
                let itemFileName = item.fileName;
                const itemSourceUrl = item.sourceUrl || (item.preview && item.preview.startsWith("http") ? item.preview : null);

                if (!itemFileName) {
                    if (itemSourceUrl && itemSourceUrl.startsWith("http")) {
                        itemFileName = extractFileNameFromUrl(itemSourceUrl, "resource.js");
                    } else {
                        itemFileName = `Inline in HTML (${extractFileNameFromUrl(itemPageUrl, "index.html")})`;
                    }
                }

                const sourceBox = document.createElement("div");
                sourceBox.className = "item-source-box";

                // Row 1: Page URL
                const pageRow = document.createElement("div");
                pageRow.className = "source-row";
                const pageBadge = document.createElement("span");
                pageBadge.className = "source-badge badge-page";
                pageBadge.textContent = "🌐 Page URL";
                const pageVal = document.createElement("span");
                pageVal.className = "source-value";
                pageVal.textContent = itemPageUrl;
                pageVal.title = itemPageUrl;
                pageRow.appendChild(pageBadge);
                pageRow.appendChild(pageVal);
                sourceBox.appendChild(pageRow);

                // Row 2: File Name & Source URL
                const fileRow = document.createElement("div");
                fileRow.className = "source-row";
                const fileBadge = document.createElement("span");
                fileBadge.className = "source-badge badge-file";
                fileBadge.textContent = "📄 File Name";
                const fileVal = document.createElement("span");
                fileVal.className = "source-value";
                const fileNameStrong = document.createElement("strong");
                fileNameStrong.className = "file-name-highlight";
                fileNameStrong.textContent = itemFileName;
                fileVal.appendChild(fileNameStrong);

                if (itemSourceUrl && itemSourceUrl !== itemPageUrl && itemSourceUrl.startsWith("http")) {
                    const fileUrlSpan = document.createElement("span");
                    fileUrlSpan.className = "file-source-url";
                    fileUrlSpan.textContent = ` (${itemSourceUrl})`;
                    fileUrlSpan.title = itemSourceUrl;
                    fileVal.appendChild(fileUrlSpan);
                } else {
                    const inlineSpan = document.createElement("span");
                    inlineSpan.className = "file-source-url";
                    inlineSpan.textContent = " (Inside Page Document)";
                    fileVal.appendChild(inlineSpan);
                }
                fileRow.appendChild(fileBadge);
                fileRow.appendChild(fileVal);
                sourceBox.appendChild(fileRow);

                // Row 3: DOM Path / Code Selector
                if (item.domPath) {
                    const domRow = document.createElement("div");
                    domRow.className = "source-row";
                    const domBadge = document.createElement("span");
                    domBadge.className = "source-badge badge-dom";
                    domBadge.textContent = "🎯 DOM Path";
                    const domVal = document.createElement("code");
                    domVal.className = "source-dom-path";
                    domVal.textContent = item.domPath;
                    domVal.title = item.domPath;
                    domRow.appendChild(domBadge);
                    domRow.appendChild(domVal);
                    sourceBox.appendChild(domRow);
                }

                card.appendChild(sourceBox);

                // Code Snippet Preview
                if (item.preview) {
                    const preview = document.createElement("pre");
                    preview.className = "item-card-preview";
                    const code = document.createElement("code");
                    code.textContent = item.preview;
                    preview.appendChild(code);
                    card.appendChild(preview);
                }

                // Detail / Notes
                if (item.detail || item.type) {
                    const detail = document.createElement("div");
                    detail.className = "item-card-detail";
                    detail.textContent = item.detail
                        ? `${item.type ? `[${item.type}] ` : ""}${item.detail}`
                        : `Type: ${item.type}`;
                    card.appendChild(detail);
                }

                modalItemsContainer.appendChild(card);
            });
        } else {
            // General or single instance fallback
            const card = document.createElement("div");
            card.className = "modal-item-card";

            const header = document.createElement("div");
            header.className = "item-card-header";

            const title = document.createElement("strong");
            title.className = "item-card-title";
            title.textContent = finding.reason || "Security Indicator Detected";

            const loc = document.createElement("span");
            loc.className = "item-card-location";
            loc.textContent = `Type: ${type}`;

            header.appendChild(title);
            header.appendChild(loc);
            card.appendChild(header);

            // Source box for general finding
            const sourceBox = document.createElement("div");
            sourceBox.className = "item-source-box";

            const pageRow = document.createElement("div");
            pageRow.className = "source-row";
            const pageBadge = document.createElement("span");
            pageBadge.className = "source-badge badge-page";
            pageBadge.textContent = "🌐 Page URL";
            const pageVal = document.createElement("span");
            pageVal.className = "source-value";
            pageVal.textContent = pageUrl || "Current Webpage";
            pageRow.appendChild(pageBadge);
            pageRow.appendChild(pageVal);
            sourceBox.appendChild(pageRow);

            const fileRow = document.createElement("div");
            fileRow.className = "source-row";
            const fileBadge = document.createElement("span");
            fileBadge.className = "source-badge badge-file";
            fileBadge.textContent = "📄 File Name";
            const fileVal = document.createElement("span");
            fileVal.className = "source-value";
            const fileNameStrong = document.createElement("strong");
            fileNameStrong.className = "file-name-highlight";
            fileNameStrong.textContent = extractFileNameFromUrl(pageUrl, "index.html");
            fileVal.appendChild(fileNameStrong);
            fileRow.appendChild(fileBadge);
            fileRow.appendChild(fileVal);
            sourceBox.appendChild(fileRow);

            card.appendChild(sourceBox);

            const detail = document.createElement("div");
            detail.className = "item-card-detail";
            detail.textContent = `Category: ${category} | Status: Detected on current page`;
            card.appendChild(detail);

            modalItemsContainer.appendChild(card);
        }
    }

    // Risk Explanation
    const modalRiskExplanation = document.getElementById("modalRiskExplanation");
    if (modalRiskExplanation) {
        modalRiskExplanation.textContent =
            finding.details?.riskExplanation || kb.riskExplanation;
    }

    // Solution Guide
    const modalSolutionText = document.getElementById("modalSolutionText");
    if (modalSolutionText) {
        modalSolutionText.textContent =
            finding.details?.solution || kb.solution;
    }
    // CVSS & Ethical Verification Guide Section
    const modalAuditorGuideSection = document.getElementById("modalAuditorGuideSection");
    const modalCvssScore = document.getElementById("modalCvssScore");
    const modalCvssVector = document.getElementById("modalCvssVector");
    const modalAuditorGuideText = document.getElementById("modalAuditorGuideText");

    const cvssData = typeof getVulnerabilityCvssAndGuide === "function"
        ? getVulnerabilityCvssAndGuide(type)
        : null;

    if (cvssData && modalAuditorGuideSection) {
        modalAuditorGuideSection.classList.remove("hidden");
        if (modalCvssScore) {
            modalCvssScore.textContent = `${cvssData.cvssScore} ${cvssData.cvssSeverity}`;
            modalCvssScore.className = `cvss-score-pill cvss-${cvssData.cvssSeverity.toLowerCase()}`;
        }
        if (modalCvssVector) {
            modalCvssVector.textContent = cvssData.cvssVector;
        }
        if (modalAuditorGuideText) {
            modalAuditorGuideText.textContent = `${cvssData.guide.title}\n\n` + cvssData.guide.steps.join("\n");
        }
    } else if (modalAuditorGuideSection) {
        modalAuditorGuideSection.classList.add("hidden");
    }

    // Open Modal
    modalOverlay.classList.remove("hidden");
    document.body.style.overflow = "hidden";
}

// ==================================
// MAIN DASHBOARD DATA RENDERER
// ==================================


// ==================================
// ETHICAL AUDITOR & PENTEST SUITE LOGIC
// ==================================

let lastRenderedScan = null;
let lastRenderedExtensionScan = [];
let lastRenderedAiAnalysis = null;
let lastRenderedPageUrl = "";

function renderAuditorSuite(safeScan) {
    const audit = safeScan?.securityAudit || {};
    const technologies = audit.technologies || [];
    const attackSurface = audit.attackSurface || {};
    const headerCookie = audit.headerCookieAudit || {};

    // 1. Technology Profile
    const techStackContainer = document.getElementById("techStackContainer");
    if (techStackContainer) {
        techStackContainer.replaceChildren();

        if (technologies.length === 0) {
            const fallbackP = document.createElement("p");
            fallbackP.className = "empty-hint";
            fallbackP.textContent = "No specific CMS or framework signatures detected in DOM.";
            techStackContainer.appendChild(fallbackP);
        } else {
            const tagList = document.createElement("div");
            tagList.className = "tech-tag-list";

            technologies.forEach(tech => {
                const tag = document.createElement("span");
                const catClass = tech.category ? `category-${tech.category.toLowerCase().replace(/[^a-z]/g, "")}` : "";
                tag.className = `tech-tag ${catClass}`;
                tag.innerHTML = `<strong>${escapeHtml(tech.name)}</strong> <em>(${escapeHtml(tech.category)})</em>`;
                tagList.appendChild(tag);
            });
            techStackContainer.appendChild(tagList);
        }
    }

    // 2. Attack Surface (Hidden Inputs & Routes)
    const attackSurfaceContainer = document.getElementById("attackSurfaceContainer");
    if (attackSurfaceContainer) {
        attackSurfaceContainer.replaceChildren();

        const group = document.createElement("div");
        group.className = "surface-list-group";

        // Discovered API Routes
        const routes = attackSurface.discoveredEndpoints || [];
        const routeHeader = document.createElement("span");
        routeHeader.className = "surface-subheading";
        routeHeader.textContent = `Discovered API Routes (${routes.length})`;
        group.appendChild(routeHeader);

        if (routes.length === 0) {
            const emptyP = document.createElement("span");
            emptyP.className = "empty-hint";
            emptyP.textContent = "No internal API routes found in page scripts.";
            group.appendChild(emptyP);
        } else {
            routes.slice(0, 5).forEach(r => {
                const pill = document.createElement("div");
                pill.className = "route-pill";
                pill.textContent = r;
                group.appendChild(pill);
            });
            if (routes.length > 5) {
                const more = document.createElement("span");
                more.className = "empty-hint";
                more.textContent = `+ ${routes.length - 5} additional routes discovered`;
                group.appendChild(more);
            }
        }

        // Hidden Inputs
        const hiddenInps = attackSurface.hiddenInputs || [];
        const inputHeader = document.createElement("span");
        inputHeader.className = "surface-subheading";
        inputHeader.textContent = `Hidden Form Parameters (${hiddenInps.length})`;
        group.appendChild(inputHeader);

        if (hiddenInps.length === 0) {
            const emptyP = document.createElement("span");
            emptyP.className = "empty-hint";
            emptyP.textContent = "No hidden form fields detected.";
            group.appendChild(emptyP);
        } else {
            hiddenInps.slice(0, 4).forEach(inp => {
                const pill = document.createElement("div");
                pill.className = "hidden-input-pill";
                pill.innerHTML = `<span>${escapeHtml(inp.name)}</span><em>${escapeHtml(inp.formAction || "form")}</em>`;
                group.appendChild(pill);
            });
        }

        // Sensitive Comments
        const comments = attackSurface.sensitiveComments || [];
        if (comments.length > 0) {
            const commHeader = document.createElement("span");
            commHeader.className = "surface-subheading";
            commHeader.textContent = `Suspicious HTML Comments (${comments.length})`;
            group.appendChild(commHeader);

            comments.slice(0, 2).forEach(c => {
                const box = document.createElement("div");
                box.className = "comment-leak-box";
                box.textContent = `<!-- ${c} -->`;
                group.appendChild(box);
            });
        }

        attackSurfaceContainer.appendChild(group);
    }

    // 3. Header & Cookie Hygiene
    const headerCookieContainer = document.getElementById("headerCookieContainer");
    if (headerCookieContainer) {
        headerCookieContainer.replaceChildren();

        // Protocol
        const isHttps = headerCookie.isHttps !== false;
        const protoRow = document.createElement("div");
        protoRow.className = "hygiene-item";
        protoRow.innerHTML = `<span>Transport Encryption</span><span class="${isHttps ? 'hygiene-badge-good' : 'hygiene-badge-bad'}">${isHttps ? 'HTTPS SECURE' : 'HTTP PLAINTEXT'}</span>`;
        headerCookieContainer.appendChild(protoRow);

        // Content Security Policy (HTTP Header / Meta)
        const csp = headerCookie.csp;
        const missingCsp = headerCookie.missingCsp !== false && (!csp || !csp.isActive);
        const cspRow = document.createElement("div");
        cspRow.className = "hygiene-item";

        let cspLabel = "MISSING CSP";
        let cspClass = "hygiene-badge-warn";
        if (csp && csp.isActive) {
            if (csp.isStrictScript) {
                cspLabel = `ACTIVE (${csp.source || "Header"}: ${csp.summary})`;
                cspClass = "hygiene-badge-good";
            } else if (csp.hasUnsafeInline) {
                cspLabel = `PERMISSIVE (${csp.source || "Header"}: 'unsafe-inline' active)`;
                cspClass = "hygiene-badge-warn";
            } else {
                cspLabel = `ACTIVE (${csp.source || "Header"})`;
                cspClass = "hygiene-badge-good";
            }
        } else if (!missingCsp) {
            cspLabel = "CSP CONFIGURED";
            cspClass = "hygiene-badge-good";
        }
        cspRow.innerHTML = `<span>Content Security Policy</span><span class="${cspClass}">${escapeHtml(cspLabel)}</span>`;
        headerCookieContainer.appendChild(cspRow);

        // Cookies
        const cookieData = headerCookie.cookieHygiene || {};
        const totalCookies = cookieData.totalAccessible || 0;
        const insecureCookies = cookieData.insecureCookies || [];

        const cookieRow = document.createElement("div");
        cookieRow.className = "hygiene-item";
        if (insecureCookies.length > 0) {
            cookieRow.innerHTML = `<span>Accessible Session Tokens</span><span class="hygiene-badge-bad">${insecureCookies.length} MISSING HTTPONLY</span>`;
        } else if (totalCookies > 0) {
            cookieRow.innerHTML = `<span>Client Accessible Cookies</span><span class="hygiene-badge-good">${totalCookies} Cookie(s)</span>`;
        } else {
            cookieRow.innerHTML = `<span>Cookie Surface</span><span class="hygiene-badge-good">0 Client Exposed</span>`;
        }
        headerCookieContainer.appendChild(cookieRow);
    }
}

function generateAndDownloadAuditReport() {
    const scan = lastRenderedScan || {};
    const url = lastRenderedPageUrl || scan.url || window.location.href;
    let hostname = "target-website";
    try {
        hostname = new URL(url).hostname || "target-website";
    } catch (e) {}

    const audit = scan.securityAudit || {};
    const technologies = audit.technologies || [];
    const attackSurface = audit.attackSurface || {};
    const findings = [
        ...(scan.webVulnerabilityFindings || []),
        ...(scan.urlFindings || []),
        ...(scan.domFindings || []),
        ...(scan.formFindings || []),
        ...(scan.scriptIframeFindings || []),
        ...(scan.sensitiveDataFindings || []),
        ...(scan.promptInjectionFindings || [])
    ].filter(f => f && !informationalTypes.includes(f.type));

    const overallRisk = scan.overallRisk || scan.risk?.level || "LOW";
    const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

    let md = `# 🛡️ ThreatLens Penetration Testing & Security Audit Report\n\n`;
    md += `**Target Host:** ${hostname}  \n`;
    md += `**Target URL:** ${url}  \n`;
    md += `**Assessment Date:** ${timestamp}  \n`;
    md += `**Overall Environment Risk:** ${overallRisk}  \n`;
    md += `**Auditing Engine:** ThreatLens Ocular Security Assistant v1.0.4  \n\n`;
    md += `---\n\n`;

    // 1. Executive Summary
    md += `## 1. Executive Summary\n\n`;
    md += `During passive client-side security assessment of **${hostname}**, ThreatLens cataloged **${findings.length} security indicator(s)**. `;
    if (overallRisk === "HIGH" || overallRisk === "CRITICAL") {
        md += `Critical or high-severity vulnerabilities were identified that may allow unauthorized data extraction, database manipulation, or administrative session hijacking. Immediate remediation is required.\n\n`;
    } else {
        md += `The assessed web application exhibits a stable baseline posture with no immediate critical exploitation paths detected.\n\n`;
    }

    // 2. Attack Surface & Tech Stack
    md += `## 2. Attack Surface & Technology Fingerprinting\n\n`;
    if (technologies.length > 0) {
        md += `### Detected Technologies & Frameworks\n`;
        md += `| Technology | Category | Confidence |\n| :--- | :--- | :--- |\n`;
        technologies.forEach(t => {
            md += `| ${t.name} | ${t.category} | ${t.confidence || "HIGH"} |\n`;
        });
        md += `\n`;
    }

    const endpoints = attackSurface.discoveredEndpoints || [];
    if (endpoints.length > 0) {
        md += `### Discovered API Endpoints & Routes\n`;
        endpoints.forEach(ep => {
            md += `- \`${ep}\`\n`;
        });
        md += `\n`;
    }

    const hiddenInputs = attackSurface.hiddenInputs || [];
    if (hiddenInputs.length > 0) {
        md += `### Hidden Form Parameters\n`;
        hiddenInputs.forEach(inp => {
            md += `- **${inp.name}** (Form: \`${inp.formAction}\`)\n`;
        });
        md += `\n`;
    }

    // 3. Technical Findings
    md += `## 3. Technical Security Findings & CVSS v3.1 Impact\n\n`;
    if (findings.length === 0) {
        md += `*No active vulnerabilities or suspicious anomalies detected.*\n\n`;
    } else {
        findings.forEach((f, idx) => {
            const kb = getKnowledgeBaseEntry(f.type);
            const cvss = typeof getVulnerabilityCvssAndGuide === "function" ? getVulnerabilityCvssAndGuide(f.type) : null;
            const title = f.details?.title || kb.title || f.reason || f.type;
            const severity = (f.severity || "LOW").toUpperCase();

            md += `### Finding #${idx + 1}: ${title}\n`;
            md += `- **Severity:** ${severity} ${cvss ? `(CVSS ${cvss.cvssScore})` : ""}\n`;
            if (cvss) {
                md += `- **CVSS v3.1 Vector:** \`${cvss.cvssVector}\`\n`;
            }
            md += `- **Category:** ${f.category || "WEB_VULNERABILITY"}\n`;
            md += `- **Indicator Type:** \`${f.type}\`\n\n`;

            md += `**Threat Analysis:**\n`;
            md += `${f.details?.riskExplanation || kb.riskExplanation || f.reason || "Security engine flagged this element."}\n\n`;

            if (cvss && cvss.guide && cvss.guide.steps) {
                md += `**Ethical Verification Methodology (Authorized Testing):**\n`;
                cvss.guide.steps.forEach(s => {
                    md += `${s}\n`;
                });
                md += `\n`;
            }

            md += `**Remediation & Defense Plan:**\n`;
            md += `${f.details?.solution || kb.solution || "Apply strict validation and security controls."}\n\n`;
            md += `---\n\n`;
        });
    }

    // 4. Header & Cookie Hygiene
    md += `## 4. Header & Cookie Security Hygiene\n\n`;
    const isHttps = audit.headerCookieAudit?.isHttps !== false;
    const missingCsp = audit.headerCookieAudit?.missingCsp !== false;
    md += `- **Transport Encryption:** ${isHttps ? "Secure (HTTPS)" : "Insecure (HTTP / Non-TLS)"}\n`;
    md += `- **Content Security Policy (CSP Meta):** ${missingCsp ? "Missing CSP directive" : "Active"}\n`;
    md += `- **Accessible Session Cookies:** ${audit.headerCookieAudit?.cookieHygiene?.insecureCookies?.length || 0} sensitive cookie(s) missing HttpOnly\n\n`;

    md += `---\n*Report generated by ThreatLens Ocular Security Assistant.*\n`;

    // Download trigger
    const safeHost = hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
    const fileName = "ThreatLens_Audit_Report_" + safeHost + "_" + Date.now() + ".md";
    triggerFileDownload(md, fileName, "text/markdown;charset=utf-8");

    const exportReportBtnEl = document.getElementById("exportReportBtn");
    if (exportReportBtnEl) {
        const orig = exportReportBtnEl.innerHTML;
        exportReportBtnEl.innerHTML = "<span>✅ Pentest Report Downloaded!</span>";
        setTimeout(() => { exportReportBtnEl.innerHTML = orig; }, 2500);
    }
}

// =========================================================
// SOC & SIEM INTELLIGENCE CONSOLE LOGIC
// =========================================================

let currentSiemEventsList = [];
let activeSiemIncidents = [];

function renderSiemConsole(scan, storedEvents = [], storedIncidents = []) {
    let events = Array.isArray(storedEvents) && storedEvents.length > 0 ? storedEvents : [];
    if (events.length === 0 && scan && typeof generateSiemEventsFromScan === "function") {
        events = generateSiemEventsFromScan(scan);
    }
    currentSiemEventsList = events;

    let incidents = Array.isArray(storedIncidents) && storedIncidents.length > 0 ? storedIncidents : [];
    if (incidents.length === 0 && events.length > 0 && typeof correlateSiemEvents === "function") {
        incidents = correlateSiemEvents(events);
    }
    activeSiemIncidents = incidents;

    // 1. Metrics Bar
    const totalEl = document.getElementById("siemTotalEvents");
    const incEl = document.getElementById("siemCorrelatedIncidents");
    const critEl = document.getElementById("siemCriticalAlerts");
    const topMitreEl = document.getElementById("siemTopMitre");

    if (totalEl) totalEl.textContent = events.length;
    if (incEl) incEl.textContent = incidents.length;
    if (critEl) {
        const critCount = events.filter(e => e.severity === "CRITICAL" || e.severity === "HIGH").length;
        critEl.textContent = critCount;
    }

    if (topMitreEl) {
        if (events.length === 0) {
            topMitreEl.textContent = "None";
        } else {
            const freq = {};
            events.forEach(e => {
                const id = e.mitre?.techniqueId || "T1082";
                freq[id] = (freq[id] || 0) + 1;
            });
            const topId = Object.keys(freq).reduce((a, b) => freq[a] > freq[b] ? a : b, "");
            topMitreEl.textContent = topId || "None";
        }
    }

    // 2. Correlated Incidents Panel
    const incListEl = document.getElementById("siemIncidentsList");
    if (incListEl) {
        if (incidents.length === 0) {
            incListEl.innerHTML = '<div class="empty-hint">No multi-stage incidents correlated yet. Clean security posture.</div>';
        } else {
            incListEl.innerHTML = incidents.map(inc => `
                <div class="incident-card ${inc.severity === "HIGH" ? "sev-high" : ""}">
                    <div class="incident-top">
                        <span class="incident-id-badge">${inc.incidentId}</span>
                        <span class="${inc.severity === "CRITICAL" ? "badge-crit" : "badge-high"}">${inc.severity} INCIDENT</span>
                    </div>
                    <div class="incident-title">${escapeHtml(inc.title)}</div>
                    <div class="incident-tactics">
                        ${(inc.mitreTactics || []).map(t => `<span class="tactic-chip">${escapeHtml(t)}</span>`).join("")}
                    </div>
                    <div class="incident-summary">${escapeHtml(inc.summary)}</div>
                    <div class="incident-soc-action"><strong>SOC Action:</strong> ${escapeHtml(inc.socAction)}</div>
                </div>
            `).join("");
        }
    }

    // 3. MITRE ATT&CK Matrix Alignment
    const mitreTagsEl = document.getElementById("siemMitreTags");
    if (mitreTagsEl) {
        const uniqueTechniques = new Map();
        events.forEach(e => {
            if (e.mitre && e.mitre.techniqueId) {
                if (!uniqueTechniques.has(e.mitre.techniqueId)) {
                    uniqueTechniques.set(e.mitre.techniqueId, e.mitre);
                }
            }
        });

        if (uniqueTechniques.size === 0) {
            mitreTagsEl.innerHTML = '<span class="empty-hint">No malicious technique signatures observed.</span>';
        } else {
            mitreTagsEl.innerHTML = Array.from(uniqueTechniques.values()).map(m => `
                <div class="mitre-technique-pill" title="${escapeHtml(m.techniqueName)}">
                    <span class="mitre-tactic-badge">${escapeHtml(m.tactic || "Tactics")}</span>
                    <span class="mitre-id">${escapeHtml(m.techniqueId)}</span>
                    <span class="mitre-name">${escapeHtml(m.techniqueName)}</span>
                </div>
            `).join("");
        }
    }

    // 4. Update Event Feed Table
    updateSiemEventTable();
}

function updateSiemEventTable() {
    const tbody = document.getElementById("siemEventsTbody");
    const badge = document.getElementById("siemEventCountBadge");
    const sevFilter = (document.getElementById("siemSeverityFilter")?.value || "ALL").toUpperCase();
    const searchFilter = (document.getElementById("siemSearchFilter")?.value || "").toLowerCase().trim();

    if (!tbody) return;

    let filtered = currentSiemEventsList.filter(e => {
        if (sevFilter === "CRITICAL" && e.severity !== "CRITICAL") return false;
        if (sevFilter === "HIGH" && e.severity !== "CRITICAL" && e.severity !== "HIGH") return false;
        if (sevFilter === "MEDIUM" && (e.severity === "LOW" || e.severity === "INFO")) return false;
        if (sevFilter === "LOW" && e.severity !== "LOW" && e.severity !== "INFO") return false;

        if (searchFilter) {
            const haystack = `${e.eventType} ${e.message} ${e.mitre?.techniqueId} ${e.target?.hostname} ${e.target?.component}`.toLowerCase();
            if (!haystack.includes(searchFilter)) return false;
        }

        return true;
    });

    if (badge) badge.textContent = `${filtered.length} of ${currentSiemEventsList.length} events`;

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No security events match the active filter.</td></tr>';
        return;
    }

    function getBadgeClass(sev) {
        switch (String(sev || "").toUpperCase()) {
            case "CRITICAL": return "badge-crit";
            case "HIGH": return "badge-high";
            case "MEDIUM": return "badge-med";
            default: return "badge-low";
        }
    }

    tbody.innerHTML = filtered.map(e => {
        const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "--:--:--";
        const locStr = e.target ? `${e.target.hostname}:${e.target.port}${e.target.pathname}` : "local";
        return `
            <tr>
                <td class="time-cell">${timeStr}</td>
                <td><span class="${getBadgeClass(e.severity)}">${escapeHtml(e.severity)}</span></td>
                <td><span class="mitre-id">${escapeHtml(e.mitre?.techniqueId || "T1082")}</span></td>
                <td><strong>${escapeHtml(e.eventType)}</strong></td>
                <td class="target-cell" title="${escapeHtml(e.target?.component || "")}">${escapeHtml(locStr)}</td>
                <td>${escapeHtml(e.message)}</td>
            </tr>
        `;
    }).join("");
}

// Download Helper for Standard SIEM Formats
function downloadSiemFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

// SIEM Filter Event Listeners
const siemSevFilterEl = document.getElementById("siemSeverityFilter");
if (siemSevFilterEl) {
    siemSevFilterEl.addEventListener("change", updateSiemEventTable);
}

const siemSearchFilterEl = document.getElementById("siemSearchFilter");
if (siemSearchFilterEl) {
    siemSearchFilterEl.addEventListener("input", updateSiemEventTable);
}

// SIEM Exporter Buttons
const exportCefBtn = document.getElementById("exportCefBtn");
if (exportCefBtn) {
    exportCefBtn.addEventListener("click", () => {
        if (typeof exportToCef === "function") {
            const data = exportToCef(currentSiemEventsList);
            downloadSiemFile(data, `threatlens_events_${Date.now()}.cef`, "text/plain");
        }
    });
}

const exportJsonlBtn = document.getElementById("exportJsonlBtn");
if (exportJsonlBtn) {
    exportJsonlBtn.addEventListener("click", () => {
        if (typeof exportToJsonl === "function") {
            const data = exportToJsonl(currentSiemEventsList);
            downloadSiemFile(data, `threatlens_events_${Date.now()}.jsonl`, "application/json");
        }
    });
}

const exportSyslogBtn = document.getElementById("exportSyslogBtn");
if (exportSyslogBtn) {
    exportSyslogBtn.addEventListener("click", () => {
        if (typeof exportToSyslog === "function") {
            const data = exportToSyslog(currentSiemEventsList);
            downloadSiemFile(data, `threatlens_syslog_${Date.now()}.log`, "text/plain");
        }
    });
}

// Clear SIEM Logs Button
const clearSiemLogsBtn = document.getElementById("clearSiemLogsBtn");
if (clearSiemLogsBtn) {
    clearSiemLogsBtn.addEventListener("click", () => {
        if (confirm("Are you sure you want to clear all recorded SIEM security events?")) {
            chrome.runtime.sendMessage({ type: "CLEAR_SIEM_LOGS" }, () => {
                chrome.storage.local.set({ siem_events_log: [], siem_incidents: [] }, () => {
                    currentSiemEventsList = [];
                    activeSiemIncidents = [];
                    renderSiemConsole(lastRenderedScan, [], []);
                });
            });
        }
    });
}


// Ensure window attachment
if (typeof window !== 'undefined') {
    window.renderSiemConsole = renderSiemConsole;
    window.updateSiemEventTable = updateSiemEventTable;
}

function renderDashboardWithScan(scan, extensionScan, aiAnalysis, pageUrl, siemEvents = [], siemIncidents = []) {
    const isRestricted = isRestrictedUrl(pageUrl);
    const safeScan = scan || {};
    const safeExtensionScan = Array.isArray(extensionScan) ? extensionScan : [];
    // Store active scan state for report export
    lastRenderedScan = safeScan;
    lastRenderedExtensionScan = safeExtensionScan;
    lastRenderedAiAnalysis = aiAnalysis;
    lastRenderedPageUrl = pageUrl;

    // Primary UI elements render first; Auditor Suite & SIEM Console render safely at function end


    // ----------------------------------
    // WEBSITE URL
    // ----------------------------------
    const urlElement = document.getElementById("websiteUrl");
    if (urlElement) {
        urlElement.textContent = pageUrl || "Unknown";
    }

    // ----------------------------------
    // OVERVIEW
    // ----------------------------------
    const calculatedRisk =
        safeScan?.risk?.level ||
        (isRestricted ? "SAFE" : "SAFE");

    const finalOverallRisk =
        safeScan?.overallRisk ||
        calculatedRisk;

    const overallRiskElement = document.getElementById("overallRisk");
    if (overallRiskElement) {
        overallRiskElement.textContent = finalOverallRisk;
    }

    const websiteRiskElement = document.getElementById("websiteRisk");
    if (websiteRiskElement) {
        websiteRiskElement.textContent = calculatedRisk;
    }

    // ----------------------------------
    // BASIC DOM INFORMATION
    // ----------------------------------
    const formsCountElement = document.getElementById("formsCount");
    if (formsCountElement) {
        formsCountElement.textContent = scan ? (scan.forms ?? 0) : 0;
    }

    const scriptsCountElement = document.getElementById("scriptsCount");
    if (scriptsCountElement) {
        scriptsCountElement.textContent = scan ? (scan.scripts ?? 0) : 0;
    }

    const iframesCountElement = document.getElementById("iframesCount");
    if (iframesCountElement) {
        iframesCountElement.textContent = scan ? (scan.iframes ?? 0) : 0;
    }

    const domStatusElement = document.getElementById("domStatus");
    if (domStatusElement) {
        domStatusElement.textContent = scan
            ? "Available"
            : (isRestricted ? "System Protected" : "Available");
    }

    // ----------------------------------
    // PHISHING RISK
    // ----------------------------------
    const phishingStatusElement = document.getElementById("phishingStatus");
    if (phishingStatusElement) {
        if (safeScan?.phishingRisk) {
            phishingStatusElement.textContent = safeScan.phishingRisk.risk;
        } else {
            phishingStatusElement.textContent = isRestricted ? "N/A (System Page)" : "LOW";
        }
    }

    // ----------------------------------
    // PROMPT INJECTION
    // ----------------------------------
    const promptFindings = (safeScan?.promptInjectionFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const promptInjectionDetected = promptFindings.some(
        (finding) => finding.type !== "NO_PROMPT_INJECTION"
    );

    const promptStatusElement = document.getElementById("promptStatus");
    if (promptStatusElement) {
        promptStatusElement.textContent = promptInjectionDetected
            ? "Possible Injection"
            : "No injection detected";
    }

    // ----------------------------------
    // EXTENSION SECURITY
    // ----------------------------------
    const extensionCountElement = document.getElementById("extensionCount");
    if (extensionCountElement) {
        extensionCountElement.textContent = safeExtensionScan.length;
    }

    let totalPermissions = 0;
    safeExtensionScan.forEach((extension) => {
        totalPermissions += (extension.permissions || []).length;
    });

    const permissionCountElement = document.getElementById("permissionCount");
    if (permissionCountElement) {
        permissionCountElement.textContent = totalPermissions;
    }

    const hasHighRiskExtension = safeExtensionScan.some(
        (ext) => ext.risk === "HIGH"
    );
    const hasMediumRiskExtension = safeExtensionScan.some(
        (ext) => ext.risk === "MEDIUM"
    );

    let extensionOverallRisk = "LOW";
    if (hasHighRiskExtension) {
        extensionOverallRisk = "HIGH";
    } else if (hasMediumRiskExtension) {
        extensionOverallRisk = "MEDIUM";
    }

    const extensionRiskElement = document.getElementById("extensionRisk");
    if (extensionRiskElement) {
        extensionRiskElement.textContent = extensionOverallRisk;
    }

    const extensionRiskDetailElement =
        document.getElementById("extensionRiskDetail");
    if (extensionRiskDetailElement) {
        extensionRiskDetailElement.textContent = extensionOverallRisk;
    }

    let extensionFindingCount = 0;
    safeExtensionScan.forEach((extension) => {
        extensionFindingCount += (extension.findings || []).length;
    });

    const extensionFindingsCountElement =
        document.getElementById("extensionFindings");
    if (extensionFindingsCountElement) {
        extensionFindingsCountElement.textContent = extensionFindingCount;
    }

    // ----------------------------------
    // EXTENSION FINDINGS DETAILS CONTAINER
    // ----------------------------------
    const extensionFindingsContainer = document.getElementById(
        "extensionFindingsContainer"
    );

    if (extensionFindingsContainer) {
        extensionFindingsContainer.replaceChildren();

        if (safeExtensionScan.length === 0) {
            extensionFindingsContainer.textContent =
                "No installed extensions found.";
        } else {
            const fragment = document.createDocumentFragment();

            safeExtensionScan.forEach((extension) => {
                const extensionCard = document.createElement("div");
                extensionCard.className = "extension-finding-card";

                const extensionName = document.createElement("h4");
                extensionName.textContent =
                    extension.name || "Unknown Extension";
                extensionCard.appendChild(extensionName);

                const risk = document.createElement("p");
                risk.textContent = `Risk: ${extension.risk || "LOW"}`;
                extensionCard.appendChild(risk);

                const findingsTitle = document.createElement("strong");
                findingsTitle.textContent = "Findings:";
                extensionCard.appendChild(findingsTitle);

                const findings = extension.findings || [];

                if (findings.length === 0) {
                    const noFindings = document.createElement("p");
                    noFindings.textContent = "No specific findings detected.";
                    extensionCard.appendChild(noFindings);
                } else {
                    findings.forEach((finding) => {
                        const findingItem = document.createElement("div");
                        findingItem.className = "extension-finding-item";

                        const severity = document.createElement("strong");
                        severity.textContent = finding.severity || "LOW";

                        const reason = document.createElement("span");
                        reason.textContent =
                            finding.reason || "No reason provided";

                        findingItem.appendChild(severity);
                        findingItem.appendChild(document.createTextNode(" "));
                        findingItem.appendChild(reason);

                        extensionCard.appendChild(findingItem);
                    });
                }

                fragment.appendChild(extensionCard);
            });

            extensionFindingsContainer.appendChild(fragment);
        }
    }

    // ----------------------------------
    // WEBSITE SECURITY FINDINGS (Interactive Cards + Details Button)
    // ----------------------------------
    const webVulnerabilityFindings = (safeScan?.webVulnerabilityFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const urlFindings = (safeScan?.urlFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const domFindings = (safeScan?.domFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const formFindings = (safeScan?.formFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const scriptIframeFindings = (safeScan?.scriptIframeFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );
    const sensitiveDataFindings = (safeScan?.sensitiveDataFindings || []).filter(
        (f) => !informationalTypes.includes(f.type)
    );

    const findings = [
        ...webVulnerabilityFindings,
        ...urlFindings,
        ...domFindings,
        ...formFindings,
        ...scriptIframeFindings,
        ...sensitiveDataFindings,
        ...promptFindings
    ];

    const urlFindingsElement = document.getElementById("urlFindings");
    if (urlFindingsElement) {
        urlFindingsElement.textContent = urlFindings.length;
    }

    const webVulnCountElement = document.getElementById("webVulnCount");
    if (webVulnCountElement) {
        webVulnCountElement.textContent = webVulnerabilityFindings.length;
        if (webVulnerabilityFindings.length > 0) {
            webVulnCountElement.style.color = "#ef4444";
        } else {
            webVulnCountElement.style.color = "";
        }
    }


    const findingsContainer = document.getElementById("findingsContainer");
    if (findingsContainer) {
        findingsContainer.replaceChildren();

        if (findings.length === 0) {
            const emptyNotice = document.createElement("div");
            emptyNotice.className = "finding-empty-state";
            emptyNotice.textContent = "No security findings detected. Website appears safe.";
            findingsContainer.appendChild(emptyNotice);
        } else {
            findings.forEach((finding, idx) => {
                const card = document.createElement("div");
                const severity = (finding.severity || "LOW").toUpperCase();
                card.className = `finding-card severity-${severity.toLowerCase()}`;

                const leftCol = document.createElement("div");
                leftCol.className = "finding-card-left";

                const badge = document.createElement("span");
                badge.className = `finding-badge badge-${severity.toLowerCase()}`;
                badge.textContent = severity;

                const categoryTag = document.createElement("span");
                categoryTag.className = "finding-category-tag";
                categoryTag.textContent = finding.category || "SECURITY";

                const reason = document.createElement("span");
                reason.className = "finding-reason-text";
                reason.textContent = finding.reason || "No reason provided";

                leftCol.appendChild(badge);
                if (finding.isMitigated || finding.details?.cspMitigation) {
                    const cspBadge = document.createElement("span");
                    cspBadge.className = "finding-csp-mitigated-badge";
                    cspBadge.textContent = "🛡️ CSP PROTECTED";
                    cspBadge.title = "This potential vulnerability is actively neutralized by the site's Content Security Policy.";
                    leftCol.appendChild(cspBadge);
                }
                leftCol.appendChild(categoryTag);
                leftCol.appendChild(reason);

                const h1Btn = document.createElement("button");
                h1Btn.className = "finding-h1-btn";
                h1Btn.type = "button";
                h1Btn.innerHTML = "<span>📋 Copy PoC</span>";
                h1Btn.title = "Copy HackerOne / Bugcrowd Report to Clipboard";
                h1Btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const reportText = generateHackerOneReport(finding, pageUrl);
                    copyTextToClipboard(reportText).then(() => {
                        const orig = h1Btn.innerHTML;
                        h1Btn.innerHTML = "<span>✅ Copied PoC!</span>";
                        setTimeout(() => { h1Btn.innerHTML = orig; }, 2500);
                    }).catch(() => {
                        const cveId = finding.cveId || "Vulnerability";
                        const safeCve = cveId.replace(/[^a-zA-Z0-9_-]/g, "_");
                        triggerFileDownload(reportText, "ThreatLens_PoC_" + safeCve + "_" + Date.now() + ".md");
                        const orig = h1Btn.innerHTML;
                        h1Btn.innerHTML = "<span>✅ Downloaded PoC!</span>";
                        setTimeout(() => { h1Btn.innerHTML = orig; }, 2500);
                    });
                });
                card.appendChild(h1Btn);

                const detailBtn = document.createElement("button");
                detailBtn.className = "finding-detail-btn";
                detailBtn.type = "button";
                detailBtn.setAttribute("data-index", idx);
                detailBtn.innerHTML = `<span>View Details</span> <span class="arrow">&rarr;</span>`;
                detailBtn.addEventListener("click", () => {
                    openFindingModal(finding, pageUrl);
                });

                card.appendChild(leftCol);
                card.appendChild(detailBtn);

                findingsContainer.appendChild(card);
            });
        }
    }

    // ----------------------------------
    // AI ANALYSIS
    // ----------------------------------
    const aiSummaryElement = document.getElementById("aiSummary");
    const aiWhyElement = document.getElementById("aiWhy");
    const aiRecommendationsElement = document.getElementById("aiRecommendations");
    const aiUserMessageElement = document.getElementById("aiUserMessage");

    const analysis = aiAnalysis?.analysis || (aiAnalysis?.summary ? aiAnalysis : null);

    if (analysis && (analysis.summary || analysis.why || analysis.recommendations)) {
        const renderFn = (typeof renderAiAnalysis === "function") 
            ? renderAiAnalysis 
            : (typeof window !== "undefined" && typeof window.renderAiAnalysis === "function" ? window.renderAiAnalysis : null);
        if (renderFn) {
            try {
                renderFn(analysis);
            } catch (e) {
                console.error("ThreatLens: Error in renderAiAnalysis:", e);
            }
        }
    } else {
        if (aiSummaryElement) {
            aiSummaryElement.textContent = isRestricted
                ? "AI analysis is not applicable for browser internal pages."
                : "🛡️ 100% Offline Local Engine Active (Zero Cloud Exposure). All DOM, Script, and Form checks were completed inside your browser. No browsing data, HTML, or credentials were sent to the cloud.";
        }
        if (aiWhyElement) {
            aiWhyElement.replaceChildren();
            const w1 = document.createElement("div");
            w1.textContent = "• Privacy-First Security: Core threat detection never depends on third-party cloud servers.";
            const w2 = document.createElement("div");
            w2.textContent = "• Zero Data Leakage: Your browsing activity and DOM structures remain strictly private.";
            aiWhyElement.appendChild(w1);
            aiWhyElement.appendChild(w2);
        }
        if (aiRecommendationsElement) {
            aiRecommendationsElement.replaceChildren();
            const r1 = document.createElement("div");
            r1.textContent = "• Review local findings above: You can inspect individual code occurrences and file sources.";
            const r2 = document.createElement("div");
            r2.textContent = "• AI Neural Assistant: Click '✦ Analyze with AI' above for real-time threat interpretation.";
            aiRecommendationsElement.appendChild(r1);
            aiRecommendationsElement.appendChild(r2);
        }
        if (aiUserMessageElement) {
            aiUserMessageElement.textContent = "Protected by ThreatLens local ocular engine. Zero cloud exposure.";
        }
        const aiLaymanElement = document.getElementById("aiLaymanExplanation");
        if (aiLaymanElement) {
            aiLaymanElement.textContent = "A simple breakdown of how these security findings affect you in everyday life will appear here after analysis.";
        }
        const aiDataAtRiskWrapper = document.getElementById("aiDataAtRiskWrapper");
        if (aiDataAtRiskWrapper) {
            aiDataAtRiskWrapper.style.display = "none";
        }
    }

    // =========================================================
    // AUDITOR SUITE & CLIENT SIEM CONSOLE (RENDER SAFELY AT END)
    // =========================================================
    try {
        if (typeof renderAuditorSuite === "function") {
            renderAuditorSuite(safeScan);
        }
    } catch (audErr) {
        console.error("ThreatLens Auditor render error:", audErr);
    }

    try {
        if (typeof renderSiemConsole === "function") {
            renderSiemConsole(safeScan, siemEvents, siemIncidents);
        }
    } catch (siemErr) {
        console.error("ThreatLens SIEM render error:", siemErr);
    }
}

function loadDashboardData() {
    chrome.storage.local.get(
        [
            tabId ? `scan_${tabId}` : null,
            "lastScan",
            "extensionScan",
            tabId ? `ai_analysis_${tabId}` : null,
            "latest_ai_analysis",
            "privacyMode",
            "siem_events_log",
            "siem_incidents",
            tabId ? `siem_events_${tabId}` : null
        ].filter(Boolean),
        (result) => {
            let scan = null;
            const tabScan = tabId ? result[`scan_${tabId}`] : null;

            if (tabScan && (!currentWebsite || isSamePage(tabScan.url, currentWebsite))) {
                scan = tabScan;
            } else if (result.lastScan && (!currentWebsite || isSamePage(result.lastScan.url, currentWebsite))) {
                scan = result.lastScan;
            } else if (tabScan) {
                scan = tabScan;
            } else if (result.lastScan) {
                scan = result.lastScan;
            }

            if (scan && Array.isArray(scan.webVulnerabilityFindings)) {
                scan.webVulnerabilityFindings = scan.webVulnerabilityFindings.filter(f => f && f.type !== "POTENTIAL_SQL_INJECTION_FORM");
                if (scan.webVulnerabilityFindings.length === 0) {
                    scan.webVulnerabilityFindings = [{
                        category: "WEB_VULNERABILITY",
                        type: "NO_WEB_VULNERABILITY",
                        severity: "SAFE",
                        reason: "No active SQL Injection or web application vulnerabilities detected"
                    }];
                }
            }
            const extensionScan = result.extensionScan || [];
            const aiAnalysis =
                (tabId ? result[`ai_analysis_${tabId}`] : null) || result.latest_ai_analysis || null;
            const pageUrl = currentWebsite || scan?.url || result.lastScan?.url || "Unknown";

            // If no scan exists for this specific website yet, request live scan from tab content script
            if (!scan && tabId) {
                const numericTabId = parseInt(tabId, 10);
                if (!isNaN(numericTabId)) {
                    try {
                        chrome.tabs.sendMessage(
                            numericTabId,
                            { action: "REQUEST_SCAN" },
                            (resp) => {
                                if (chrome.runtime.lastError) {
                                    // Content script initializing or tab not reachable
                                } else if (resp && resp.data) {
                                    renderDashboardWithScan(
                                        resp.data,
                                        extensionScan,
                                        aiAnalysis,
                                        pageUrl
                                    );
                                }
                            }
                        );
                    } catch (e) {
                        // Ignore message delivery errors
                    }
                }
            }

            const siemEvents = (tabId ? result[`siem_events_${tabId}`] : null) || result.siem_events_log || [];
            const siemIncidents = result.siem_incidents || [];
            renderDashboardWithScan(
                scan,
                extensionScan,
                aiAnalysis,
                pageUrl,
                siemEvents,
                siemIncidents
            );
        }
    );
}

// Initial load
loadDashboardData();

// Listen for storage changes in the background and update live
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local") {
        if (
            (tabId && changes[`scan_${tabId}`]) ||
            changes.lastScan ||
            (tabId && changes[`ai_analysis_${tabId}`]) ||
            changes.latest_ai_analysis ||
            changes.extensionScan ||
            changes.siem_events_log ||
            changes.siem_incidents
        ) {
            console.log("ThreatLens: Storage updated, re-rendering dashboard");
            loadDashboardData();
        }
    }
});

// Copy AI Dev Code Button
const copyAiCodeBtn = document.getElementById("copyAiCodeBtn");
if (copyAiCodeBtn) {
    copyAiCodeBtn.addEventListener("click", () => {
        const codeEl = document.getElementById("aiDevCodeSnippet");
        if (codeEl && codeEl.textContent) {
            navigator.clipboard.writeText(codeEl.textContent).then(() => {
                const orig = copyAiCodeBtn.textContent;
                copyAiCodeBtn.textContent = "✅ Copied!";
                setTimeout(() => copyAiCodeBtn.textContent = orig, 2000);
            });
        }
    });
}

// Export Pentest Report Button
const exportReportBtn = document.getElementById("exportReportBtn");
if (exportReportBtn) {
    exportReportBtn.addEventListener("click", () => {
        generateAndDownloadAuditReport();
    });
}

const exportBugBountyBtn = document.getElementById("exportBugBountyBtn");
if (exportBugBountyBtn) {
    exportBugBountyBtn.addEventListener("click", () => {
        generateAndDownloadBugBountyReport();
    });
}

const modalDownloadH1ReportBtn = document.getElementById("modalDownloadH1ReportBtn");
if (modalDownloadH1ReportBtn) {
    modalDownloadH1ReportBtn.addEventListener("click", () => {
        if (!currentActiveModalFinding) return;
        const cveId = currentActiveModalFinding.cveId || currentActiveModalFinding.details?.cveId || "Vulnerability";
        const safeCve = cveId.replace(/[^a-zA-Z0-9_-]/g, "_");
        let hostClean = "target";
        try {
            hostClean = new URL(currentActiveModalPageUrl || window.location.href).hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
        } catch (e) {}

        const reportText = generateHackerOneReport(currentActiveModalFinding, currentActiveModalPageUrl);
        const fileName = "ThreatLens_PoC_" + safeCve + "_" + hostClean + "_" + Date.now() + ".md";
        triggerFileDownload(reportText, fileName, "text/markdown;charset=utf-8");

        const orig = modalDownloadH1ReportBtn.innerHTML;
        modalDownloadH1ReportBtn.innerHTML = "<span>✅ Downloaded PoC Report!</span>";
        setTimeout(() => { modalDownloadH1ReportBtn.innerHTML = orig; }, 2500);
    });
}

const modalCopyH1ReportBtn = document.getElementById("modalCopyH1ReportBtn");
if (modalCopyH1ReportBtn) {
    modalCopyH1ReportBtn.addEventListener("click", () => {
        if (!currentActiveModalFinding) return;
        const reportText = generateHackerOneReport(currentActiveModalFinding, currentActiveModalPageUrl);
        copyTextToClipboard(reportText).then(() => {
            const orig = modalCopyH1ReportBtn.innerHTML;
            modalCopyH1ReportBtn.innerHTML = "<span>✅ Copied PoC!</span>";
            setTimeout(() => { modalCopyH1ReportBtn.innerHTML = orig; }, 2500);
        }).catch(() => {
            const cveId = currentActiveModalFinding.cveId || "Vulnerability";
            const safeCve = cveId.replace(/[^a-zA-Z0-9_-]/g, "_");
            triggerFileDownload(reportText, "ThreatLens_PoC_" + safeCve + "_" + Date.now() + ".md");
            const orig = modalCopyH1ReportBtn.innerHTML;
            modalCopyH1ReportBtn.innerHTML = "<span>✅ Downloaded PoC!</span>";
            setTimeout(() => { modalCopyH1ReportBtn.innerHTML = orig; }, 2500);
        });
    });
}

// Re-Scan Target Button
const rescanBtn = document.getElementById("rescanBtn");
if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
        if (!tabId) {
            rescanBtn.innerHTML = "<span>⚠️ Tab ID Missing</span>";
            setTimeout(() => { rescanBtn.innerHTML = "<span>🔄 Re-Scan Target</span>"; }, 2500);
            return;
        }
        const numericTabId = parseInt(tabId, 10);
        if (isNaN(numericTabId)) return;

        rescanBtn.innerHTML = "<span>⏳ Scanning...</span>";
        chrome.tabs.sendMessage(numericTabId, { action: "REQUEST_SCAN" }, (resp) => {
            if (chrome.runtime.lastError || !resp || !resp.data) {
                // Content script was disconnected due to extension reload in dev mode
                rescanBtn.innerHTML = "<span>⚠️ Press F5 on Page & Retry</span>";
                setTimeout(() => { rescanBtn.innerHTML = "<span>🔄 Re-Scan Target</span>"; }, 3500);
            } else {
                rescanBtn.innerHTML = "<span>✅ Fresh Scan Loaded!</span>";
                renderDashboardWithScan(
                    resp.data,
                    lastRenderedExtensionScan,
                    lastRenderedAiAnalysis,
                    resp.data.url || lastRenderedPageUrl
                );
                setTimeout(() => { rescanBtn.innerHTML = "<span>🔄 Re-Scan Target</span>"; }, 2500);
            }
        });
    });
}

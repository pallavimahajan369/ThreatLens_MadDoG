from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def format_scenario(doc, num, title, problem, component, investigate, tech_process, solution, limitations):
    add_heading_2(doc, f"Scenario {num}: {title}")
    add_bullet(doc, problem, bold_prefix="1. Understand the Problem: ")
    add_bullet(doc, component, bold_prefix="2. Affected Component: ")
    add_bullet(doc, investigate, bold_prefix="3. Investigation Steps: ")
    add_bullet(doc, tech_process, bold_prefix="4. Technical Process: ")
    add_bullet(doc, solution, bold_prefix="5. Proposed Solution & Defense: ")
    add_bullet(doc, limitations, bold_prefix="6. Architectural Limitations: ")
    doc.add_paragraph()

def build_part9(doc):
    add_heading_1(doc, "PART 9: 30 SCENARIO-BASED & ADVANCED SECURITY ENGINEERING QUESTIONS")
    
    add_paragraph(doc,
        "Senior technical interviewers frequently probe candidates with real-world edge cases, attack simulations, "
        "and architectural failure modes. Below are 30 comprehensive scenarios answered with a rigorous 6-step engineering methodology: "
        "(1) Understand the Problem; (2) Identify the Affected Component; (3) Investigate; (4) Technical Process; "
        "(5) Propose Solution; (6) Explain Limitations."
    )
    
    scenarios_data = [
        (1, "Malicious Hidden Iframe Used for Clickjacking",
         "A webpage secretly embeds a zero-pixel hidden iframe pointing to a sensitive internal portal to hijack clicks.",
         "content/script-iframe-security.js and content/risk-engine.js.",
         "Inspect all <iframe> elements via document.querySelectorAll('iframe'). Check computed styles for width <= 1px, height <= 1px, opacity: 0, or display: none.",
         "script-iframe-security.js extracts the src URL, checks dimensions via getBoundingClientRect(), and identifies whether the frame is concealed from user vision.",
         "Flag finding as 'HIDDEN_IFRAME_CLICKJACKING' (HIGH severity). Recommend server enforce 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
         "If the iframe is dynamically rendered and made transparent via complex canvas layering, simple CSS dimension checks may fail without visual layout analysis."),
         
        (2, "Insecure Password Submission over Plaintext HTTP",
         "A login page collects user credentials but submits the form over unencrypted HTTP, exposing passwords to network sniffing.",
         "content/form-security.js.",
         "Iterate document.forms; check form.action URL protocol and check whether form contains input[type='password'].",
         "form-security.js parses action attribute. If action starts with 'http://' or is empty on an HTTP origin, it records a PLAINTEXT_PASSWORD_HTTP finding.",
         "Escalate risk to CRITICAL. Advise developer to enforce HTTPS and set HSTS (Strict-Transport-Security) header.",
         "Cannot detect if credentials are encrypted via custom client-side WebCrypto JavaScript before form dispatch."),
         
        (3, "Steganographic LLM Prompt Injection in Hidden Web Text",
         "An adversary hides adversarial prompt injection strings in zero-opacity text designed to hijack AI browser agents.",
         "content/prompt-injection-security.js.",
         "Scan DOM innerText and inspect inline styles and computed CSS for opacity:0, font-size:0, or visibility:hidden containing jailbreak keywords.",
         "prompt-injection-security.js regex matches adversarial phrases ('Ignore prior instructions', 'System prompt override') and checks parent element styling.",
         "Flag as 'INDIRECT_PROMPT_INJECTION'. Alert user that the website contains hidden instructions designed to trick LLMs.",
         "Heuristic regex cannot catch semantically obfuscated or multi-language prompt injections without a dedicated safety LLM."),
         
        (4, "Background Service Worker Terminating During Long External AI Call",
         "In Chrome MV3, the service worker shuts down after 30 seconds of inactivity, potentially terminating a pending Gemini API call.",
         "background/service-worker.js.",
         "Check Chrome DevTools console for 'The service worker was terminated' during on-demand AI scan requests.",
         "service-worker.js wraps fetch in AbortSignal.timeout(8000), guaranteeing completion or timeout within 8s, well within Chrome's 30s threshold.",
         "Ensure all fetch requests have strict timeouts and immediately fallback to the deterministic offline generator on timeout.",
         "If network latency is >8 seconds, API call aborts even if the user would have preferred to wait."),
         
        (5, "Google Gemini Cloud API Service Outage (HTTP 503)",
         "Google's Gemini API endpoints experience temporary downtime or rate-limit exhaustion (HTTP 429 / 503).",
         "background/service-worker.js (requestAIAnalysis).",
         "Check fetch response status; catch block captures non-200 HTTP codes or JSON error objects.",
         "service-worker.js catches the network error and transparently routes the payload to the local deterministic fallback generator.",
         "Offline generator renders syntax-highlighted secure code patches and layman explanations locally within 5ms.",
         "Fallback explanations are rule-templated and lack the bespoke conversational nuance of a live generative LLM."),
         
        (6, "Installed Browser Extension Requesting Excessive High-Risk Permissions",
         "A newly installed PDF editor extension requests <all_urls>, cookies, and webRequest permissions, posing a spyware threat.",
         "background/service-worker.js (scanInstalledExtensions) and content/extension-security.js.",
         "Execute chrome.management.getAll(); inspect declared permissions array and hostPermissions.",
         "service-worker.js counts risky permissions (cookies, webRequest, debugger). If >= 2 high-risk capabilities exist, it flags EXCESSIVE_PERMISSIONS.",
         "Dashboard Extension Auditor highlights the extension with a red CRITICAL badge and advises user to revoke permissions or uninstall.",
         "Chrome does not allow one extension to programmatically disable or uninstall another extension without user consent."),
         
        (7, "High Volume of False-Positive Alerts on External CDN Scripts Lacking SRI",
         "A developer uses 20 third-party CDN libraries without SRI attributes, generating 20 HIGH severity warnings and cluttering reports.",
         "content/script-iframe-security.js and content/risk-engine.js.",
         "Inspect script-iframe findings in the dashboard. Notice multiple 'MISSING_SRI' findings for trusted CDNs (e.g. cdnjs, cdn.jsdelivr.net).",
         "script-iframe-security.js groups repeated findings by category; risk-engine caps the cumulative contribution of missing SRI to prevent score skewing.",
         "Deduplicate findings in the UI; assign lower initial weight to known trusted CDN hosts unless accompanied by dynamic script injection.",
         "Cannot verify whether the remote CDN file has been compromised without downloading and hashing it locally."),
         
        (8, "Single-Page Application (SPA) Client-Side Route Change Without Full Reload",
         "A React application navigates from /home to /checkout via window.history.pushState without a full page refresh.",
         "content/content.js (MutationObserver).",
         "Observe whether ThreatLens re-evaluates the page when the URL changes in an SPA.",
         "content.js sets up a MutationObserver with a 300ms debounce timer (isSecurityRelevantMutation) to detect added input/form nodes.",
         "In addition to MutationObserver, listen to background chrome.tabs.onUpdated events to trigger on-demand scans on pushState navigation.",
         "SPAs that only change text nodes without altering DOM element structures may not trigger mutation scans."),
         
        (9, "Sensitive Session Token Leaking in URL Query Parameters",
         "A web application passes a raw authentication session ID in the URL (?phpsessid=abc12345), exposing it to browser history and proxy logs.",
         "content/url-security.js and content/ai-sanitizer.js.",
         "url-security.js parses new URL(window.location.href).searchParams for known session keys (phpsessid, jsessionid, token, auth).",
         "url-security.js flags 'SENSITIVE_PARAM_IN_URL' (HIGH). Prior to sending data to AI, ai-sanitizer.js redacts the parameter value.",
         "Alert developer to migrate session tokens to secure HTTP-only cookies and use POST request bodies for token transmission.",
         "If the parameter uses a non-standard custom name (e.g., ?my_special_ticket=123), generic regex might miss it without entropy analysis."),
         
        (10, "Reverse Tabnabbing Vulnerability via target='_blank' Hyperlinks",
         "A website includes external links with target='_blank' but omits rel='noopener noreferrer', allowing the linked site to hijack window.opener.",
         "content/dom-security.js.",
         "Query document.querySelectorAll(\"a[target='_blank']\"); inspect rel attribute for presence of 'noopener' or 'noreferrer'.",
         "dom-security.js flags every vulnerable link, extracts its href, and generates the exact CSS DOM path in the finding card.",
         "Inform developer to append rel='noopener noreferrer' to all target='_blank' links to sever the window.opener execution bridge.",
         "Modern versions of Chrome automatically imply rel='noopener' for target='_blank', but older browsers and other engines remain vulnerable."),
         
        (11, "Punycode Homograph Domain Mimicking a Major Financial Institution",
         "A user visits a phishing site using an internationalized domain name (e.g. xn--pypal-4ve.com) displaying 'paypal.com' visually.",
         "content/phishing-security.js and content/url-security.js.",
         "Inspect window.location.hostname for the 'xn--' Punycode prefix. Check for mixed Cyrillic/Latin character sets.",
         "phishing-security.js detects Punycode prefix; if paired with a password form or login text, it flags 'HOMOGRAPH_PHISHING_ATTACK' (CRITICAL).",
         "Display prominent warning banner on popup badge and dashboard, advising user not to enter credentials.",
         "Legitimate international websites in non-Latin languages also use Punycode; requires correlation with credential forms to prevent false alarms."),
         
        (12, "Passive Detection of Reflected SQL Injection Database Error",
         "A vulnerable web page reflects raw MySQL database syntax errors ('You have an error in your SQL syntax near...') in the HTML.",
         "content/cve-registry.js and content/web-vulnerability-security.js.",
         "web-vulnerability-security.js searches document.body.innerHTML against registered database error regexes in cve-registry.js.",
         "cve-registry.js matches CWE-89 signature (PHP/MySQL syntax error); assigns CVSS 9.8 (CRITICAL); maps to MITRE T1190.",
         "Dashboard renders parameterized SQL query remediation patch ($stmt = $pdo->prepare(...)) and highlights exact DOM location.",
         "Passive scanning cannot detect blind SQL injection where database errors are suppressed by custom error handlers."),
         
        (13, "Outdated Vulnerable JavaScript Library (jQuery < 3.5.0 XSS)",
         "A legacy web page loads jQuery 2.2.4, which is vulnerable to DOM-based XSS via jQuery.htmlPrefilter (CVE-2020-11022 / 11023).",
         "content/cve-registry.js and content/script-iframe-security.js.",
         "Inspect script src URLs and window.jQuery.fn.jquery version strings for version numbers matching vulnerable ranges (<3.5.0).",
         "Matches CVE-2020-11022 in cve-registry.js; assigns CVSS 6.1 (MEDIUM/HIGH); flags potential XSS vector in DOM manipulation.",
         "Advise developer to update jQuery to version 3.7.1 or higher, or migrate to modern native vanilla DOM APIs.",
         "If the library code is bundled, minified, and version comments are stripped, client-side regex cannot reliably determine version."),
         
        (14, "Missing Key HTTP Security Headers (HSTS, X-Frame-Options)",
         "A production e-commerce site omits Strict-Transport-Security (HSTS) and X-Frame-Options response headers.",
         "background/service-worker.js and content/security-auditor.js.",
         "service-worker.js intercepts webRequest response headers. security-auditor.js checks for presence of 'strict-transport-security' and 'x-frame-options'.",
         "Generates 'MISSING_HSTS_HEADER' and 'MISSING_FRAME_OPTIONS' findings in security-auditor.js.",
         "Recommend server configuration snippet for Nginx/Apache to append HSTS (max-age=31536000) and X-Frame-Options (DENY).",
         "Cannot determine if headers were stripped by an intermediary corporate proxy or omitted by the origin server."),
         
        (15, "Strict CSP Mitigates Inline Script Finding, Reducing Severity",
         "A page contains an inline script tag, but the server enforces a strict Content Security Policy (script-src 'self' with nonce).",
         "content/security-auditor.js (applyCspMitigations).",
         "security-auditor.js parses CSP string from response headers; evaluates whether script-src permits 'unsafe-inline'.",
         "If 'unsafe-inline' is absent, applyCspMitigations() intercepts the DOM inline script finding, downgrades severity to LOW, and appends '[CSP MITIGATED]'.",
         "Alerts developer that defense-in-depth is working properly, preventing alert fatigue and avoiding unnecessary bug tickets.",
         "If the CSP contains complex wildcard domains or unsafe-eval, the mitigation logic must accurately evaluate directive loopholes."),
         
        (16, "AWS Access Key ID Accidentally Leaked in HTML Developer Comments",
         "A developer leaves a comment in HTML: `<!-- Debug: AWS Key AKIAIOSFODNN7EXAMPLE -->`.",
         "content/sensitive-data-security.js.",
         "Use document.createTreeWalker with NodeFilter.SHOW_COMMENT to inspect all HTML comment nodes; match against `\\\\bAKIA[0-9A-Z]{16}\\\\b`.",
         "sensitive-data-security.js extracts the matched key, masks middle characters (`AKIAIOSF****EXAMPLE`), and assigns CRITICAL severity.",
         "Alert developer immediately to invalidate the exposed AWS credential in IAM, rotate secrets, and scrub comments before git commit.",
         "Cannot determine client-side whether the AWS key has active administrative privileges or is already deactivated in IAM."),
         
        (17, "Insecure Mixed Content HTTP Asset on HTTPS Banking Portal",
         "An HTTPS banking page loads a promotional banner image over plaintext HTTP (`<img src='http://insecure-cdn.com/banner.jpg'>`).",
         "content/dom-security.js.",
         "Verify window.location.protocol === 'https:'; query all script, link, img, and iframe elements with src/href starting with 'http://'.",
         "dom-security.js records a 'MIXED_CONTENT_INSECURE_ASSET' finding with the exact image tag and URL.",
         "Advise developer to update asset URLs to protocol-relative (//) or HTTPS, and configure CSP 'upgrade-insecure-requests'.",
         "Passive scanner cannot predict if modern browsers will silently auto-upgrade or block the HTTP asset."),
         
        (18, "Adversary Obfuscates Web Exploit Using JSFuck / Packed Scripts",
         "An attacker obfuscates malicious code using esoteric JavaScript encoding (e.g. `[][(![]+[])[+[]]...]`) to evade static regex.",
         "content/script-iframe-security.js and content/dom-security.js.",
         "Inspect script text nodes for high concentrations of non-alphanumeric characters (`[]!+()`) and repetitive syntax.",
         "Scanner flags 'HEURISTIC_OBFUSCATED_SCRIPT' based on symbol entropy and character distribution metrics.",
         "Alert security analyst that obfuscated code is executing; recommend manual dynamic de-obfuscation in a sandbox.",
         "Static regex cannot de-obfuscate or execute the payload without risking code execution inside the extension sandbox."),
         
        (19, "Chrome Storage Local Quota Exceeded During Long Fuzzing Session",
         "An analyst audits 500 pages in one session; chrome.storage.local approaches storage limits.",
         "background/service-worker.js (setStorage).",
         "Check chrome.runtime.lastError for 'QUOTA_BYTES' or storage write rejections.",
         "manifest.json explicitly declares 'unlimitedStorage' permission, lifting the default 10MB quota.",
         "Implement an automated FIFO (First-In, First-Out) cache rotation policy that purges scan history older than 7 days.",
         "Very large storage states can slow down JSON serialization when populating dashboard views on low-RAM workstations."),
         
        (20, "Extension Context Invalidated Error After Developer Code Reload",
         "A developer reloads the extension in Developer Mode; existing web tabs throw 'Extension context invalidated'.",
         "content/content.js and background/service-worker.js.",
         "Inspect browser console; content.js throws when calling chrome.runtime.sendMessage() because the extension runtime ID changed.",
         "content.js wraps all chrome.* API calls in try/catch and verifies `if (!chrome.runtime?.id) return;`.",
         "Suppress unhandled runtime errors gracefully; display a subtle notification instructing user to refresh the page.",
         "Content scripts injected by the previous extension instance cannot be re-bound to the new runtime ID without a page refresh."),
         
        (21, "Server-Side Request Forgery (SSRF) Parameter in URL Query",
         "A URL parameter instructs the server to fetch remote data (`?url=http://169.254.169.254/latest/meta-data/`).",
         "content/url-security.js and content/cve-registry.js.",
         "url-security.js regex matches query parameters containing internal loopback IPs, localhost, or cloud metadata endpoints.",
         "Matches CWE-918; flags 'POTENTIAL_SSRF_PARAMETER' (CRITICAL); maps to MITRE T1190 Exploit Public-Facing Application.",
         "Provide developer code snippet showing DNS resolution and private IP validation before fetching external URLs.",
         "Cannot determine passively whether the backend server actually makes outbound HTTP requests using the parameter."),
         
        (22, "Path Traversal / Local File Inclusion (LFI) in Query String",
         "A URL contains directory traversal sequences (`?page=../../../../etc/passwd`).",
         "content/url-security.js and content/cve-registry.js.",
         "Parse URL searchParams; test parameter values against path traversal regexes (`\\.\\.\\/` and `%2e%2e%2f`).",
         "Flags 'PATH_TRAVERSAL_PARAMETER' (HIGH severity); associates with CWE-22; provides basename sanitization remediation.",
         "Advise developer to use basename() and validate against an allowlist of permitted view templates.",
         "Cannot confirm whether the backend web server runs Linux, Windows, or if the parameter is vulnerable without active exploitation."),
         
        (23, "Form Submitting Passwords to Cross-Origin Untrusted Domain",
         "A form on `mysite.com` sets `action='https://evil-analytics.com/collect'`, siphoning form inputs.",
         "content/form-security.js.",
         "Compare form.action hostname against window.location.hostname.",
         "form-security.js flags 'CROSS_ORIGIN_FORM_ACTION' (HIGH); checks whether target origin is a verified corporate subdomain.",
         "Alert user to potential credential harvesting; advise developer to restrict form submission endpoints to the same origin.",
         "Legitimate third-party payment gateways (PayPal, Stripe) also use cross-origin form actions; requires domain allowlisting."),
         
        (24, "Password Field Lacking Minimum Modern Security Attributes",
         "A password input lacks `autocomplete='new-password'`, `minlength`, or has `type='text'` revealing plaintext characters.",
         "content/form-security.js.",
         "Query input[type='password']; inspect autocomplete, minlength, and required attributes.",
         "form-security.js records finding if password field lacks modern browser security hints or allows trivially short inputs.",
         "Advise developer to set autocomplete='current-password' or 'new-password' and enforce client/server length minimums.",
         "Minor hygiene issue; does not inherently indicate an active remote exploit."),
         
        (25, "Malicious Webpage Attempts to Fingerprint or Tamper with ThreatLens",
         "A hostile site runs JavaScript trying to detect or modify ThreatLens content script variables.",
         "content/content.js (Isolated World Security).",
         "Host page scripts attempt to read `window.__threatlens_headers` or overwrite `scanPage()`.",
         "Chrome's Isolated World architecture completely separates the content script execution heap from the webpage's JavaScript context.",
         "Keep all internal state inside private IIFE closures and module scopes; never attach sensitive functions to the global `window` object.",
         "Webpages can observe side-effects (e.g. DOM modifications or timing differences), but cannot directly read private extension variables."),
         
        (26, "Multiple Weak Signals Triggering Composite Risk Escalation",
         "A page has a self-signed HTTP port, an unverified form, and a suspicious TLD (.xyz). None is critical alone, but together they indicate fraud.",
         "content/risk-engine.js (applyCorrelationRules).",
         "risk-engine.js checks combinations of LOW and MEDIUM findings across URL, DOM, and Form categories.",
         "Correlation rule triggers: `if (hasHttp && hasForm && hasSuspiciousTLD) escalate to CRITICAL`.",
         "Update toolbar badge to RED 'CRIT'; generate composite threat reason card in the dashboard.",
         "Correlation rules require empirical tuning to prevent over-escalating benign development environments on localhost."),
         
        (27, "Enterprise SOC Requires Automated CEF Log Streaming to Splunk",
         "A corporate security team needs browser threat events formatted for direct ingestion into Splunk SIEM.",
         "content/siem-engine.js and dashboard/dashboard.js.",
         "siem-engine.js formats findings into ArcSight Common Event Format: `CEF:0|ThreatLens|Scanner|1.0.13|CWE-89|...`.",
         "User clicks 'Export CEF' in dashboard; dashboard.js generates a downloadable `.cef` log file with MITRE technique headers.",
         "SOC analyst imports `.cef` file into Splunk indexer or configures a local forwarder.",
         "Browser sandbox blocks raw UDP/TCP socket transmission; logs must be exported via file download or authenticated HTTPS webhook."),
         
        (28, "Offline Security Audit of Local Docker Container (DVWA on Port 4280)",
         "A cybersecurity student audits Damn Vulnerable Web App running locally in Docker without internet access.",
         "Entire ThreatLens Engine (Zero Backend Dependency).",
         "Navigate to `http://localhost:4280/vulnerabilities/sqli/`. Verify ThreatLens functions 100% without internet.",
         "Content scripts execute locally; CVE registry matches MySQL errors; form-security flags GET submission; offline engine renders fixes.",
         "ThreatLens operates with zero cloud telemetry, proving it is a complete self-contained ethical hacking station.",
         "AI generative explanations require Gemini API key and internet; offline mode provides deterministic fixes instead."),
         
        (29, "Malicious Webpage Launches DOM Node Flooding Attack (100,000 Nodes)",
         "An adversarial site generates 100,000 DOM div elements to exhaust browser memory and freeze security extensions.",
         "content/content.js and content/dom-security.js.",
         "Observe CPU usage and scan duration when navigating to massive DOM pages.",
         "content.js limits querySelectorAll traversals; MutationObserver debouncing (300ms) prevents continuous event loop thrashing.",
         "Implement node traversal caps (e.g., maximum 5,000 inspected nodes per category) to ensure extension never freezes the browser.",
         "Limiting node inspection could theoretically allow an adversary to hide an exploit beyond the node cutoff threshold."),
         
        (30, "AI Model Hallucinates Non-Existent Vulnerabilities in JSON Response",
         "Gemini AI hallucinates that the page contains an iframe or script that does not actually exist in the DOM.",
         "background/service-worker.js and dashboard/dashboard.js.",
         "Inspect AI JSON output: verify whether reported vulnerability locations correspond to actual findings in `aiPayload`.",
         "System prompt in service-worker.js strictly instructs: 'Analyze the EXACT page and environment. Do NOT invent generic iframes or scripts that do not exist.'",
         "dashboard.js cross-references AI-generated vulnerability titles with actual local findings before rendering, filtering out unverified claims.",
         "Probabilistic nature of LLMs means minor hallucinations can occur; local deterministic scanning remains the source of truth.")
    ]
    
    for sc in scenarios_data:
        format_scenario(doc, *sc)

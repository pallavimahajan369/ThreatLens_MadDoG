from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def build_part1(doc):
    add_heading_1(doc, "PART 1: COMPLETE PROJECT SOURCE CODE AUDIT & FILE-BY-FILE INVENTORY")
    
    add_paragraph(doc, 
        "This section represents a rigorous, line-by-line architectural audit of the entire ThreatLens codebase. "
        "Every file in the repository has been evaluated against Google Chrome Manifest V3 standards, modern "
        "Application Security paradigms, DOM traversal performance metrics, and defensive engineering practices. "
        "No assumptions have been made; all analyses reflect actual lines of code present in the repository."
    )
    
    add_callout(doc, 
        "CRITICAL AUDIT SUMMARY:\n"
        "• Total Core Project Files: 23 (Manifest: 1, Background: 1, Content Modules: 15, Dashboard UI: 3, Popup UI: 3)\n"
        "• Manifest Specification: Google Chrome Extension Manifest Version 3 (Service Worker lifecycle)\n"
        "• Architecture Pattern: Decoupled Multi-Tier Architecture (Injected Content DOM Scanners -> Background Service Worker Orchestrator -> Unified Security Operations Dashboard)\n"
        "• Execution Model: 100% Client-Side Passive Evaluation with optional Direct-to-Gemini REST AI Enrichment\n"
        "• Inlined Components Discovered: content/extension-security.js logic was migrated directly into background/service-worker.js (Line 125), leaving the content file redundant.",
        title="AUDIT SUMMARY & DISCOVERY FINDINGS",
        alert_type="IMPORTANT"
    )
    
    add_heading_2(doc, "1.1 File-by-File Technical Inventory (All 23 Files)")
    
    # List of files to detail
    files_data = [
        {
            "name": "manifest.json",
            "path": "c:/Users/ajmah/OneDrive/Desktop/level-1/level-1/manifest.json",
            "q1": "Chrome Extension Manifest V3 configuration manifest defining metadata, permissions, host access rules, service workers, content script arrays, and security policies.",
            "q2": "Mandatory configuration root required by Chromium browsers to parse, sandbox, permission, and load an extension.",
            "q3": "Declares extension identity, Manifest V3 compliance, granular permissions ('storage', 'tabs', 'management', 'unlimitedStorage', 'webRequest'), broad host_permissions ('<all_urls>'), background service worker entry, popup UI, and sequential content script injection list.",
            "q4": "Static declarative JSON parsed by Chrome engine at extension installation and update. Injects 13 content scripts sequentially at 'document_idle' across all HTTP/HTTPS frames.",
            "q5": "Declarative JSON structure; keys: 'manifest_version', 'permissions', 'host_permissions', 'background.service_worker', 'content_scripts', 'content_security_policy'.",
            "q6": "Inputs: Read by Chrome browser engine. Outputs: Instantiated Service Worker runtime, injected content script context, registered browser action button.",
            "q7": "Directly bootstraps background/service-worker.js, popup/popup.html, and content script sequence (cve-registry.js through content.js).",
            "q8": "Browser reads manifest, validates JSON schema, requests declared privileges during extension install, assigns isolated storage partition, registers event listeners.",
            "q9": "Enforces Least Privilege and Content Security Policy ('script-src self; object-src self'), blocking dangerous eval() or remote code execution in extension origin.",
            "q10": "Malformed JSON syntax prevents extension loading; missing permissions cause runtime exceptions when calling chrome.* APIs; broad '<all_urls>' host permission triggers security warnings during Web Store submission.",
            "q11": "Does not inject into browser internal URLs (chrome://, edge://, about:blank), file:// unless user explicitly permits it in extension settings."
        },
        {
            "name": "background/service-worker.js",
            "path": "background/service-worker.js (1807 lines)",
            "q1": "Central event-driven background service worker orchestrating security header interception, extension privilege audits, storage coordination, badge updates, and direct AI analysis.",
            "q2": "Manifest V3 mandates ephemeral service workers instead of persistent background pages to reduce browser memory usage and improve stability.",
            "q3": "Monitors chrome.webRequest.onHeadersReceived for security headers (CSP, HSTS, X-Frame-Options); scans installed extensions via chrome.management.getAll(); dispatches messages between popup, dashboard, and content scripts; communicates directly with Google Gemini API.",
            "q4": "Uses importScripts to load content/ai-sanitizer.js, risk-engine.js, security-auditor.js, and siem-engine.js. Implements asynchronous listeners on chrome.runtime.onMessage and chrome.webRequest.",
            "q5": "getStorage(), setStorage(), analyzeExtensionSecurity(), scanInstalledExtensions(), requestAIAnalysis(), buildAISecurityPayload(), calculateCombinedRisk(), updateKeyStatusBadge().",
            "q6": "Inputs: Messages from content scripts (SCAN_RESULT), popup/dashboard requests (REQUEST_SCAN, RUN_AI_SCAN, GET_EXTENSIONS), webRequest HTTP response headers. Outputs: JSON responses, badge text/colors, AI insights, cached findings in chrome.storage.local.",
            "q7": "Communicates with content.js, popup.js, dashboard.js, chrome.storage.local, chrome.tabs, chrome.management, and Google Gemini API (generativelanguage.googleapis.com).",
            "q8": "Wakes on events (tab open, webRequest, message); executes handler; persists state to chrome.storage.local; terminates after 30 seconds of inactivity.",
            "q9": "Extracts raw HTTP response headers that content scripts cannot view; audits browser extensions for excessive privileges (e.g. cookies, webRequest); redacts data before AI dispatch.",
            "q10": "Service Worker inactivity timeout (30 seconds) can terminate long-running async promises if not properly coordinated; network drop during Gemini fetch throws unhandled promise rejections if unhandled.",
            "q11": "Cannot access DOM directly; must communicate with tabs via chrome.tabs.sendMessage; service worker terminates when idle."
        },
        {
            "name": "content/ai-sanitizer.js",
            "path": "content/ai-sanitizer.js (229 lines)",
            "q1": "Pre-flight data sanitization, token redaction, and data loss prevention (DLP) engine for AI prompts.",
            "q2": "To prevent accidental leakage of sensitive customer data, credentials, session cookies, and private tokens to cloud LLM providers.",
            "q3": "Strips authentication credentials from URLs; scrubs session IDs, JWTs, AWS keys, Bearer tokens, private keys, passwords, and emails from finding reasons and DOM snippets.",
            "q4": "Uses regex-based token matching and URL parameter rewriting. Sets a strict character length cap (400 chars per reason, 1000 chars total) and validates severity enums via safeEnum().",
            "q5": "safeEnum(), sanitizeUrl(), sanitizeReason(), sanitizeFindings(), sanitizeCorrelations(), buildAISecurityPayload().",
            "q6": "Inputs: Raw scan findings array, current URL, page title, detected risk levels. Outputs: Sanitized, redacted JSON payload guaranteed free of credentials and PII.",
            "q7": "Imported by background/service-worker.js; testable via scratch/test_ai_sanitization.js.",
            "q8": "Parses URL using the URL API; deletes username and password; iterates searchParams to redact known token keys; applies regex replacements across all textual reason strings; bounds payload size.",
            "q9": "Core privacy control ensuring GDPR / HIPAA compliance and zero-knowledge transmission before external AI processing.",
            "q10": "Novel or non-standard token formats (e.g. proprietary hash formats) could slip past regex; overly aggressive regex could truncate legitimate debugging info.",
            "q11": "Pattern-based heuristic sanitizer; does not perform semantic entropy analysis or deep AST deconstruction."
        },
        {
            "name": "content/content.js",
            "path": "content/content.js (314 lines)",
            "q1": "Master client-side content script orchestrating DOM inspections, heuristic evaluators, SPA mutation monitoring, and background messaging.",
            "q2": "Acts as the central conductor inside the web page's isolated world context, executing all security modules in a coordinated lifecycle.",
            "q3": "Executes scanPage('page-load'); collects findings from URL, DOM, forms, scripts, sensitive data, web vulnerabilities, prompt injections, and phishing; applies CSP mitigations; computes overall risk; sends SCAN_RESULT to service worker; monitors SPA mutations via MutationObserver.",
            "q4": "Runs at document_idle. Wraps each detection module in try/catch blocks to ensure single-detector errors never crash the entire scanner. Uses a 300ms debounce timer for DOM mutation scans.",
            "q5": "scanPage(reason), isSecurityRelevantMutation(mutations), runtime.onMessage listener.",
            "q6": "Inputs: Live DOM tree, window.location.href, incoming messages from popup/dashboard, HTTP headers from service worker. Outputs: Comprehensive scan result object sent via chrome.runtime.sendMessage.",
            "q7": "Coordinates cve-registry.js, url-security.js, dom-security.js, form-security.js, script-iframe-security.js, sensitive-data-security.js, web-vulnerability-security.js, phishing-security.js, prompt-injection-security.js, risk-engine.js, security-auditor.js, siem-engine.js; sends data to service-worker.js.",
            "q8": "Page finishes loading -> scanPage executes -> sub-analyzers run -> findings normalized -> CSP mitigations applied -> overall risk calculated -> payload transmitted to service worker.",
            "q9": "Provides real-time, zero-backend visibility into client-side vulnerabilities directly as the user browses.",
            "q10": "Extremely complex DOMs (e.g. 50,000 nodes) can cause brief CPU spikes during deep traversal; invalid extension context (e.g. after extension reload) causes 'Extension context invalidated' warning.",
            "q11": "Runs in Chrome's Isolated World; cannot directly access JavaScript variables defined in the webpage's main world without injecting script tags."
        },
        {
            "name": "content/cve-registry.js",
            "path": "content/cve-registry.js (831 lines)",
            "q1": "Data-driven vulnerability signature dictionary and Common Weakness Enumeration (CWE) knowledge base.",
            "q2": "Decouples vulnerability definitions, regular expressions, and remediation guides from detection logic, allowing seamless rule addition without modifying engine code.",
            "q3": "Stores static CVE and OWASP vulnerability definitions across SQL Injection, Command Injection, LFI/Path Traversal, SSRF, XSS, and Outdated Libraries (e.g. jQuery CVE-2020-11022).",
            "q4": "Exports a global CVE_REGISTRY object containing rule arrays. Each rule defines id, name, cwe, cvss, severity, attackPattern, detectionRegex, description, remediation, and references.",
            "q5": "getRegisteredVulnerability(cveId), getAllRegisteredVulnerabilities().",
            "q6": "Inputs: cveId string or query requests. Outputs: Full vulnerability definition object with CVSS score, description, and remediation guidance.",
            "q7": "Queried by web-vulnerability-security.js, security-auditor.js, siem-engine.js, and dashboard.js.",
            "q8": "Loaded into memory during content script injection; provides instant lookup tables for pattern matching against page source and error messages.",
            "q9": "Standardizes vulnerability detection to industry standards (CWE-89, CWE-79, CWE-78, CWE-22, CWE-918).",
            "q10": "Regex catastrophic backtracking if poorly constructed regex encounters unexpected input; outdated signature list if new CVEs are not added.",
            "q11": "Only contains signatures coded into the array; cannot dynamically download external threat feeds due to Chrome MV3 remote code restrictions."
        },
        {
            "name": "content/dom-security.js",
            "path": "content/dom-security.js (455 lines)",
            "q1": "Client-side DOM vulnerability and dangerous sink analyzer.",
            "q2": "To identify dangerous DOM manipulation patterns, mixed content, insecure hyperlink configurations, and tabnabbing risks.",
            "q3": "Audits DOM for dangerous sinks (document.write, innerHTML, eval), HTTP mixed content assets on HTTPS pages, target='_blank' links missing rel='noopener noreferrer', and hidden form inputs.",
            "q4": "Traverses DOM nodes using document.querySelectorAll; generates exact CSS DOM selectors (e.g. 'body > div#container > a:nth-of-type(2)') and code previews for each finding.",
            "q5": "getDomSecurityDomPath(), getDomDocumentFileName(), getResourceFileName(), analyzeDOM(activeCsp).",
            "q6": "Inputs: DOM elements, optional active CSP object. Outputs: Array of DOM security finding objects with severity, location, preview, and remediation advice.",
            "q7": "Called by content.js; findings fed into risk-engine.js and security-auditor.js.",
            "q8": "Queries anchor tags, script tags, stylesheets, and inline event handlers; cross-references with active CSP to avoid false positives.",
            "q9": "Prevents Reverse Tabnabbing (window.opener hijacking), Mixed Content degradation, and DOM-based XSS vectors.",
            "q10": "Legitimate analytics scripts with hidden tracking pixels may be flagged as suspicious hidden elements; dynamic DOM changes require re-scan.",
            "q11": "Static DOM inspection cannot evaluate dynamic runtime data flow or taint analysis of JavaScript variables."
        },
        {
            "name": "content/extension-security.js",
            "path": "content/extension-security.js (219 lines)",
            "q1": "Standalone module for evaluating permissions and privilege risks of installed browser extensions.",
            "q2": "Created during early development to modularize extension privilege analysis.",
            "q3": "Defines analyzeExtensionSecurity(extension) to flag high-risk permissions ('cookies', 'webRequest', 'webRequestBlocking', 'debugger', 'management', '<all_urls>').",
            "q4": "Inspects permissions array and hostPermissions array of extension objects; assigns severity (HIGH, MEDIUM, LOW) based on risky permission counts.",
            "q5": "analyzeExtensionSecurity(extension).",
            "q6": "Inputs: Chrome extension metadata object from chrome.management.getAll(). Outputs: Analysis object with risk level ('HIGH', 'MEDIUM', 'LOW') and findings list.",
            "q7": "Originally intended for content script, but chrome.management API is restricted to service worker. The function was copied into background/service-worker.js (line 125).",
            "q8": "Checks if permissions include dangerous capabilities; counts risky permissions; flags excessive permissions if >= 2 high-risk capabilities exist.",
            "q9": "Protects users against malicious, hijacked, or overly permissive extensions that could spy on cookies or inject ads.",
            "q10": "Currently redundant because it is not listed in manifest.json content_scripts and its code is already inlined in service-worker.js.",
            "q11": "Cannot execute in content script context; requires management permission in background."
        },
        {
            "name": "content/form-security.js",
            "path": "content/form-security.js (387 lines)",
            "q1": "Interactive HTML form and credential transmission security auditor.",
            "q2": "To detect insecure form handling, plaintext password transmission, missing anti-CSRF tokens, and parameter exposure.",
            "q3": "Audits all <form> elements on the page for HTTP action endpoints, GET method password submissions, missing autocomplete='off' on credit cards, cross-origin actions, and missing CSRF tokens.",
            "q4": "Iterates document.forms, inspects attributes (action, method), queries input types (password, text, hidden), and checks target URL protocols.",
            "q5": "getFormDomPath(), getDocumentFileName(), analyzeFormSecurity().",
            "q6": "Inputs: HTMLFormElement instances in the current DOM. Outputs: Array of FORM security findings with exact form CSS selector, action URL, and vulnerability reason.",
            "q7": "Called by content.js; findings consumed by phishing-security.js and risk-engine.js.",
            "q8": "Iterates every form; checks if page is HTTP while containing password inputs; checks if form action sends credentials over HTTP; verifies presence of hidden CSRF token inputs.",
            "q9": "Prevents Man-in-the-Middle (MitM) credential interception, URL history password leaks via GET forms, and Cross-Site Request Forgery (CSRF).",
            "q10": "Modern Single Page Applications (SPAs) handling form submissions via JavaScript fetch()/axios without an action attribute may trigger false positives for missing action.",
            "q11": "Cannot inspect JavaScript event listeners attached to form submit buttons (e.g. e.preventDefault() -> fetch)."
        },
        {
            "name": "content/phishing-security.js",
            "path": "content/phishing-security.js (218 lines)",
            "q1": "Client-side phishing threat intelligence and domain heuristic engine.",
            "q2": "To detect fraudulent, impersonated, or deceptive websites attempting credential harvesting.",
            "q3": "Analyzes domain structure, top-level domains (TLDs), Punycode/IDN homograph attacks, IP-based URLs, and brand spoofing keywords.",
            "q4": "Correlates URL signals with page findings (e.g. password fields on newly registered or suspicious TLDs like .xyz, .top, .click, .tk). Calculates cumulative phishing risk score.",
            "q5": "analyzePhishingRisk(urlFindings, domFindings, formFindings, scriptIframeFindings).",
            "q6": "Inputs: Outputs from URL, DOM, Form, and Script analyzers. Outputs: Phishing risk object { score: number, risk: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', signals: string[] }.",
            "q7": "Invoked in content.js after primary analyzers complete.",
            "q8": "Calculates heuristic score: +35 for IP address URL, +25 for suspicious TLD, +30 for brand spoofing pattern with password input, +20 for Punycode homograph. Maps score to risk level.",
            "q9": "Protects end-users from zero-day phishing pages before traditional blacklists (Google Safe Browsing) have indexed them.",
            "q10": "Legitimate sites hosted on non-standard TLDs (.xyz) or internal development IPs (192.168.x.x) may receive elevated phishing scores.",
            "q11": "Cannot verify domain registration age (WHOIS) client-side without external API calls."
        },
        {
            "name": "content/prompt-injection-security.js",
            "path": "content/prompt-injection-security.js (280 lines)",
            "q1": "AI Safety and LLM prompt injection detector in web content.",
            "q2": "To protect AI browser agents (e.g. Copilot, Gemini in Chrome, AutoGPT) and users from indirect prompt injection attacks embedded in untrusted web pages.",
            "q3": "Scans page text and hidden elements for prompt injection attack patterns ('Ignore previous instructions', 'You are now DAN', 'System prompt override', 'Print all instructions').",
            "q4": "Extracts document.body innerText; checks for hidden DOM elements (opacity: 0, font-size: 0px, display: none, off-screen absolute positioning) containing instruction override keywords.",
            "q5": "analyzePromptInjection().",
            "q6": "Inputs: Page text content and styled DOM elements. Outputs: Array of PROMPT_INJECTION findings containing injection type (Direct vs Indirect), matched pattern, preview snippet, and risk score.",
            "q7": "Called by content.js; findings included in risk aggregation and AI sanitization.",
            "q8": "Searches for adversarial LLM jailbreaks and prompt hijacking strings; inspects CSS styles of containing elements to detect hidden / steganographic text injections.",
            "q9": "Prevents AI browser agents from executing unauthorized actions (e.g. exfiltrating browsing history, transferring funds, executing rogue instructions) triggered by malicious web text.",
            "q10": "Cybersecurity blog posts discussing prompt injection examples can trigger false positives; obfuscated prompt injections (Base64, rot13, leetspeak) can evade regex.",
            "q11": "Relies on regex heuristic patterns; cannot semantically evaluate LLM intent without executing a secondary safety LLM."
        },
        {
            "name": "content/risk-engine.js",
            "path": "content/risk-engine.js (410 lines)",
            "q1": "Multi-signal risk aggregation, finding normalization, and correlation engine.",
            "q2": "To combine dozens of disparate security findings into a single, reliable, mathematically weighted risk posture (SAFE, LOW, MEDIUM, HIGH, CRITICAL).",
            "q3": "Normalizes findings from all analyzers; assigns severity weights; applies multi-finding correlation rules (e.g. Password Input + HTTP + Suspicious Domain -> Escalated CRITICAL); generates human-readable risk reasons.",
            "q4": "Implements a deterministic scoring matrix: CRITICAL = 25 pts, HIGH = 15 pts, MEDIUM = 8 pts, LOW = 3 pts. Applies threshold brackets and correlation escalation rules.",
            "q5": "normalizeFindings(), getSeverityWeight(), applyCorrelationRules(), hasFinding(), calculateOverallRisk().",
            "q6": "Inputs: Array of raw findings from all content modules. Outputs: Risk assessment object { level: 'SAFE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', reasons: string[], score: number }.",
            "q7": "Called by content.js; imported by service-worker.js; testable via scratch/calibrate_severities.js.",
            "q8": "Flattens finding arrays; computes cumulative numerical score; evaluates correlation conditions; caps maximum risk level; returns structured risk summary.",
            "q9": "Eliminates alert fatigue by prioritizing high-severity attack chains over minor informational warnings.",
            "q10": "Tuning weights too high can make every site appear HIGH risk; tuning too low can under-report genuine compound threats.",
            "q11": "Thresholds are rule-based and static; does not employ Bayesian probability or adaptive machine learning."
        },
        {
            "name": "content/script-iframe-security.js",
            "path": "content/script-iframe-security.js (501 lines)",
            "q1": "Client-side script integrity, third-party code, and iframe sandbox security auditor.",
            "q2": "To identify insecure script loading, missing Subresource Integrity (SRI), dangerous inline event handlers, hidden clickjacking iframes, and un-sandboxed third-party embeds.",
            "q3": "Audits all <script> and <iframe> elements for SRI attributes, dangerous inline code, zero-dimension hidden frames, and missing sandbox attributes.",
            "q4": "Queries document.scripts and querySelectorAll('iframe'); checks for 'integrity' attribute on external CDNs; checks iframe sandbox flags ('allow-scripts allow-same-origin'); checks dimensions (width <= 1, height <= 1).",
            "q5": "getScriptDomPath(), getScriptDocumentFileName(), getScriptFileName(), analyzeScriptIframeSecurity(activeCsp).",
            "q6": "Inputs: DOM script and iframe elements, active CSP object. Outputs: Array of SCRIPT_IFRAME security findings with DOM path, source URL, preview, and severity.",
            "q7": "Called by content.js; mitigations applied by security-auditor.js.",
            "q8": "Loops through scripts; flags external scripts without SRI; loops through iframes; flags hidden iframes (clickjacking/drive-by); verifies sandbox attributes.",
            "q9": "Mitigates CDN supply-chain tampering (Magecart attacks), Clickjacking, Cross-Frame Scripting, and Drive-By downloads.",
            "q10": "Legitimate tracking pixels (e.g. Google Analytics iframe) or third-party widgets without SRI may trigger warnings; CSP script-src can mitigate but needs correlation.",
            "q11": "Cannot verify cryptographically if the remote script content matches an SRI hash without downloading the file."
        },
        {
            "name": "content/security-auditor.js",
            "path": "content/security-auditor.js (734 lines)",
            "q1": "Enterprise reconnaissance, Content Security Policy (CSP) parser, and false-positive mitigation engine.",
            "q2": "To inspect HTTP security headers, parse CSP directives, and dynamically down-grade finding severities if an active, strict CSP neutralizes the exploit vector.",
            "q3": "Parses CSP strings into structured directives (default-src, script-src, object-src, frame-ancestors); detects technology stack (PHP, Apache, Nginx); calculates CVSS v3.1 scores; downgrades XSS/script warnings if CSP blocks inline scripts.",
            "q4": "Uses regex and string parsing on window.__threatlens_headers or meta tags. Intercepts findings before risk calculation and adjusts severity based on defense-in-depth controls.",
            "q5": "parseCspString(), detectAndParseActiveCsp(), applyCspMitigations(), mitigateFinding(), analyzeSecurityAudit(), getVulnerabilityCvssAndGuide().",
            "q6": "Inputs: Raw HTTP response headers, meta CSP tags, scan findings. Outputs: Parsed CSP object, technology stack inventory, adjusted finding array with mitigated severities.",
            "q7": "Called by content.js and background/service-worker.js; testable via scratch/test_csp_mitigation.js.",
            "q8": "Checks headers for CSP; evaluates if script-src lacks 'unsafe-inline'; if so, flags inline scripts as mitigated; marks finding severity reduced.",
            "q9": "Prevents false-positive inflation and rewards websites implementing robust defense-in-depth headers.",
            "q10": "Complex CSP with nonces or hashes may be misparsed if regex fails on unconventional whitespace.",
            "q11": "Content scripts cannot see all response headers without webRequest API assistance from background worker."
        },
        {
            "name": "content/sensitive-data-security.js",
            "path": "content/sensitive-data-security.js (453 lines)",
            "q1": "Client-side Data Loss Prevention (DLP) and exposed secret scanner.",
            "q2": "To detect sensitive data exposure in web pages, comments, and form fields before attackers can harvest them.",
            "q3": "Scans page HTML, comments, and scripts for credit cards (validated via Luhn algorithm), AWS access keys, JWT tokens, private RSA keys, API keys, Bearer tokens, and email addresses.",
            "q4": "Performs regex pattern matching; applies Luhn checksum algorithm (isValidLuhn) to eliminate false credit card numbers; checks keyword context for AWS secret keys (hasAWSSecretContext).",
            "q5": "isValidLuhn(), hasAWSSecretContext(), analyzeSensitiveData().",
            "q6": "Inputs: document.documentElement.innerHTML, HTML comments (NodeFilter.SHOW_COMMENT). Outputs: Array of SENSITIVE_DATA findings with redacted secret preview, line location, and severity.",
            "q7": "Called by content.js; findings included in risk score and SIEM log generation.",
            "q8": "Traverses DOM text and comments; runs regex; validates numeric matches with mathematical checksums; truncates and masks matches for safe reporting.",
            "q9": "Prevents accidental leakage of cloud credentials (AWS keys), developer secrets, session tokens, and customer payment data.",
            "q10": "High-density number sequences (tracking numbers, ISBNs) could pass Luhn if mathematically valid; large DOMs increase regex execution time.",
            "q11": "Only scans static text and comments visible in client DOM; cannot scan backend database contents or server memory."
        },
        {
            "name": "content/siem-engine.js",
            "path": "content/siem-engine.js (484 lines)",
            "q1": "Security Information and Event Management (SIEM) correlation engine and MITRE ATT&CK mapper.",
            "q2": "To bridge client-side browser findings to enterprise SOC workflows and SIEM ingestion pipelines.",
            "q3": "Maps findings to MITRE ATT&CK Tactics (Initial Access, Execution, Credential Access, Exfiltration) and Techniques; generates correlated security event objects; exports logs in CEF, JSONL, and Syslog formats.",
            "q4": "Uses a mapping dictionary between CWE/finding types and MITRE ATT&CK IDs (e.g. CWE-89 -> T1190 Exploit Public-Facing Application). Formats event strings according to ArcSight Common Event Format (CEF) and RFC 5424 Syslog standards.",
            "q5": "resolveMitreAttack(), getSeverityScore(), generateSiemEventsFromScan(), correlateSiemEvents(), exportToCef(), exportToJsonl(), exportToSyslog().",
            "q6": "Inputs: Comprehensive scan results from content.js. Outputs: Correlated SIEM event objects, downloadable log files (.cef, .jsonl, .log).",
            "q7": "Used by dashboard.js for SIEM table view and export center; imported by service-worker.js; tested in scratch/test_siem_engine.js.",
            "q8": "Iterates findings; enriches each with MITRE tactic/technique; detects multi-event correlation patterns (e.g. Brute Force + SQLi); serializes events into standard log formats.",
            "q9": "Enables instant integration into enterprise SOC platforms (Splunk, Elasticsearch, IBM QRadar, Datadog) without custom log parsers.",
            "q10": "Mapping table must be maintained as MITRE updates framework; exporting massive logs in browser memory could consume RAM.",
            "q11": "Runs client-side in browser; does not transmit syslog over UDP/TCP directly (browser sandbox prohibits raw sockets); provides file download instead."
        },
        {
            "name": "content/url-security.js",
            "path": "content/url-security.js (331 lines)",
            "q1": "URL structure, network port, protocol, and query parameter security inspector.",
            "q2": "To identify network-layer anomalies, unencrypted HTTP connections, non-standard port exposures, and query-based attack vectors.",
            "q3": "Audits current URL protocol (HTTP vs HTTPS); flags non-standard ports (8080, 8443, 4280, 3000); scans query parameters for SQL injection payloads, Path Traversal (../), and Open Redirects.",
            "q4": "Parses URL using the standard browser URL API; extracts protocol, hostname, port, pathname, and searchParams; evaluates query values against attack regexes.",
            "q5": "analyzeURL(rawUrl).",
            "q6": "Inputs: Raw URL string (window.location.href). Outputs: Array of URL security findings with risk level, category, parameter name, and remediation.",
            "q7": "Called by content.js; findings used in phishing calculation and risk engine.",
            "q8": "Checks url.protocol === 'http:'; checks if port is non-empty and not in standard ports [80, 443]; iterates searchParams for dangerous patterns.",
            "q9": "Alerts users when browsing insecure test environments, exposed administrative ports, or clicking URLs containing active exploit payloads.",
            "q10": "Legitimate web developers testing on localhost:3000 will receive non-standard port warnings (by design).",
            "q11": "Only inspects the active browser URL; cannot see backend server redirect chains that occurred prior to final page load unless captured by webRequest."
        },
        {
            "name": "content/web-vulnerability-security.js",
            "path": "content/web-vulnerability-security.js (149 lines)",
            "q1": "Active web application vulnerability scanner and CVE matching bridge.",
            "q2": "To connect the static cve-registry.js database to live page content and detect visible exploit traces.",
            "q3": "Matches page source text, visible error strings, and URL parameters against registered CVEs and OWASP attack patterns (SQL errors, command outputs, LFI traces).",
            "q4": "Queries getAllRegisteredVulnerabilities() from cve-registry.js; tests page body innerHTML and URL parameters against each rule's detectionRegex.",
            "q5": "analyzeWebVulnerabilities(activeCsp).",
            "q6": "Inputs: Active CSP object, DOM HTML, current URL. Outputs: Array of WEB_VULNERABILITY findings with CVE ID, CWE, CVSS score, location, and code preview.",
            "q7": "Called by content.js; relies on cve-registry.js.",
            "q8": "Iterates vulnerability registry; runs regex against page content; if match found, generates finding with exact line/preview; attaches remediation guidance.",
            "q9": "Detects active exploitation and critical backend vulnerabilities (e.g. exposed MySQL syntax errors, PHP CGI arguments) passively without sending attack traffic.",
            "q10": "Blind SQL injection or vulnerabilities that do not leak error messages into the DOM cannot be detected passively.",
            "q11": "Passive scanner only; does not send active fuzzed payloads to verify exploitability."
        },
        {
            "name": "dashboard/dashboard.html",
            "path": "dashboard/dashboard.html (621 lines)",
            "q1": "Comprehensive standalone Security Operations Center (SOC) and Penetration Testing Command Dashboard UI.",
            "q2": "To provide security analysts, developers, and students with an enterprise-grade visual interface to explore threats, review MITRE tactics, inspect extensions, and export reports.",
            "q3": "Renders UI layout: Top navigation, Threat Overview gauge, Severity Summary cards, Tabbed navigation (Overview, Vulnerability Explorer, MITRE ATT&CK Matrix, Extension Auditor, SIEM Logs, AI Mentor, Settings), and Export modals.",
            "q4": "HTML5 semantic markup styled with modern dark-mode CSS theme. Uses IDs and data-attributes for dynamic DOM rendering by dashboard.js.",
            "q5": "Semantic structure containing views: #overviewView, #findingsView, #mitreView, #extensionsView, #siemView, #aiView, #settingsView.",
            "q6": "Inputs: Rendered by Chrome browser when user opens chrome-extension://.../dashboard/dashboard.html. Outputs: Interactive DOM structure.",
            "q7": "Loaded by popup.js or extension menu; linked to dashboard.css and dashboard.js.",
            "q8": "Browser parses HTML; loads CSS stylesheets and JavaScript; builds DOM tree; triggers dashboard.js initialization.",
            "q9": "UI representation layer; does not execute privileged code directly; adheres to strict CSP ('script-src self').",
            "q10": "Missing element IDs in HTML would cause dashboard.js querySelector calls to return null and throw errors.",
            "q11": "Static HTML skeleton; entirely dependent on JavaScript for data population."
        },
        {
            "name": "dashboard/dashboard.css",
            "path": "dashboard/dashboard.css (2862 lines)",
            "q1": "Enterprise dark-mode stylesheet for the SOC Dashboard.",
            "q2": "To deliver a high-contrast, professional cybersecurity interface modeled after modern enterprise SOC platforms (Splunk, CrowdStrike, Datadog).",
            "q3": "Defines CSS custom properties (colors, spacing, shadows), responsive flex/grid layouts, animated risk gauges, severity badges, syntax code highlights, and modal transitions.",
            "q4": "Uses modern CSS variables (:root), CSS Grid, Flexbox, media queries, and transition animations without any external CSS frameworks (zero Tailwind, zero Bootstrap).",
            "q5": "Classes: .risk-gauge, .severity-badge, .mitre-cell, .finding-card, .btn-primary, .modal-backdrop, .ai-chat-bubble.",
            "q6": "Inputs: Parsed by browser rendering engine. Outputs: Styled, responsive visual layout.",
            "q7": "Applied to dashboard/dashboard.html.",
            "q8": "Applies typography, color schemes, elevation shadows, and hover states to dashboard elements.",
            "q9": "Pure styling; zero security risk; no remote font or icon requests (100% offline self-contained).",
            "q10": "Excessive specificity or overlapping rules can make UI overrides complex.",
            "q11": "Scoped strictly to extension dashboard page."
        },
        {
            "name": "dashboard/dashboard.js",
            "path": "dashboard/dashboard.js (2418 lines)",
            "q1": "Master client-side application logic for the Security Command Center Dashboard.",
            "q2": "To manage state, render interactive views, handle user clicks, communicate with background service worker, validate Gemini API keys, and generate downloadable reports.",
            "q3": "Fetches current scan results from chrome.storage.local; renders threat overview and risk score gauge; populates expandable finding cards; renders MITRE ATT&CK matrix; audits extensions; manages AI Mentor prompts; generates Markdown, CEF, and JSONL exports.",
            "q4": "Event-driven ES6+ JavaScript. Listens to storage changes (chrome.storage.onChanged); handles tab switching; implements file download logic using Blob and URL.createObjectURL.",
            "q5": "initDashboard(), renderThreatOverview(), renderFindingsList(), renderMitreMatrix(), renderExtensionsView(), renderAiAnalysis(), exportMarkdownReport(), exportSiemLogs(), updateKeyStatusBadge().",
            "q6": "Inputs: Stored scan results from storage.local, user input (API key, export clicks). Outputs: Dynamic DOM updates, downloadable audit files (.md, .cef, .jsonl), messages to service worker.",
            "q7": "Communicates with background/service-worker.js, chrome.storage.local, chrome.tabs, and downloads API.",
            "q8": "On load: reads active tab URL; loads scan findings; populates UI tabs; registers click event listeners; initializes settings state.",
            "q9": "Validates API keys locally; escapes HTML strings (escapeHtml) before inserting into DOM to prevent DOM-based XSS in the dashboard itself.",
            "q10": "Failure to escape user-controlled page titles or findings could introduce XSS in the dashboard; mitigated by escapeHtml().",
            "q11": "Can only display findings that content script and service worker have successfully scanned and stored."
        },
        {
            "name": "popup/popup.html",
            "path": "popup/popup.html (79 lines)",
            "q1": "Toolbar popup user interface skeleton.",
            "q2": "To give users an instantaneous 2-second security snapshot without needing to open the full dashboard.",
            "q3": "Renders extension header, active tab domain, current risk level badge, quick threat metrics count, 'Open Dashboard' button, and 'Re-Scan' action.",
            "q4": "Lightweight HTML markup loaded when the extension icon in Chrome toolbar is clicked.",
            "q5": "Container elements: #riskBadge, #siteUrl, #criticalCount, #highCount, #btnOpenDashboard, #btnRescan.",
            "q6": "Inputs: Loaded by browser on extension action click. Outputs: Compact popup window.",
            "q7": "Linked to popup.css and popup.js.",
            "q8": "Browser opens 360x480px popup; renders markup; executes popup.js.",
            "q9": "Strict CSP; no inline scripts or remote styles.",
            "q10": "Popup closes automatically when user clicks outside, destroying ephemeral state.",
            "q11": "Space-constrained; cannot display deep technical CVE details or SIEM logs."
        },
        {
            "name": "popup/popup.css",
            "path": "popup/popup.css (307 lines)",
            "q1": "Stylesheet for toolbar popup window.",
            "q2": "To style the compact popup with high readability, smooth badge animations, and consistent branding.",
            "q3": "Provides layout rules, color-coded risk badges (green, yellow, orange, red), typography, and button states.",
            "q4": "Compact CSS styles optimized for fixed 360px popup width.",
            "q5": "Classes: .badge-safe, .badge-warning, .badge-danger, .metric-pill, .btn-action.",
            "q6": "Inputs: Evaluated by browser rendering engine. Outputs: Styled popup interface.",
            "q7": "Applied to popup/popup.html.",
            "q8": "Applies layout and theme colors instantaneously on popup open.",
            "q9": "Self-contained; zero remote network dependencies.",
            "q10": "Fixed width can cause text overflow if URL is extremely long; mitigated by text-overflow: ellipsis.",
            "q11": "Limited to popup viewport."
        },
        {
            "name": "popup/popup.js",
            "path": "popup/popup.js (280 lines)",
            "q1": "Toolbar popup application controller.",
            "q2": "To retrieve active tab scan status, update badge indicators, and handle quick user actions.",
            "q3": "Queries active tab (chrome.tabs.query); fetches scan results from storage; renders risk badge and finding counters; opens dashboard in a full tab on button click; requests on-demand scan.",
            "q4": "Asynchronous ES6+ script. Uses chrome.tabs.create to launch dashboard.html; uses chrome.tabs.sendMessage to request immediate scans.",
            "q5": "isRestrictedUrl(), isSamePage(), renderPopup(), addEventListeners.",
            "q6": "Inputs: Active tab metadata, scan results from chrome.storage.local. Outputs: Rendered popup DOM, new browser tab launching dashboard.",
            "q7": "Communicates with background/service-worker.js, content.js, and chrome.storage.local.",
            "q8": "Queries current active tab -> checks if URL is restricted (chrome://) -> retrieves stored scan -> updates DOM counters -> attaches click handlers.",
            "q9": "Prevents crashes on restricted browser internal pages by checking isRestrictedUrl().",
            "q10": "If content script has not finished scanning when popup opens, displays loading skeleton; auto-refreshes on storage change.",
            "q11": "Lifecycle ends immediately when popup loses focus."
        }
    ]
    
    for f in files_data:
        add_heading_3(doc, f"File: {f['name']}")
        add_paragraph(doc, f"Repository Path: {f['path']}", bold_prefix="Path: ", italic=True)
        
        # 11 questions
        add_bullet(doc, f['q1'], bold_prefix="1. What is this file? ")
        add_bullet(doc, f['q2'], bold_prefix="2. Why was it created? ")
        add_bullet(doc, f['q3'], bold_prefix="3. Responsibility: ")
        add_bullet(doc, f['q4'], bold_prefix="4. How code works: ")
        add_bullet(doc, f['q5'], bold_prefix="5. Important functions: ")
        add_bullet(doc, f['q6'], bold_prefix="6. Inputs & Outputs: ")
        add_bullet(doc, f['q7'], bold_prefix="7. Communication: ")
        add_bullet(doc, f['q8'], bold_prefix="8. Internal execution: ")
        add_bullet(doc, f['q9'], bold_prefix="9. Security purpose: ")
        add_bullet(doc, f['q10'], bold_prefix="10. What can go wrong: ")
        add_bullet(doc, f['q11'], bold_prefix="11. Limitations: ")
        
        doc.add_paragraph() # spacing
        
    add_heading_2(doc, "1.2 Project Implementation Status, Bugs, Weaknesses & Code Audit Findings")
    
    add_paragraph(doc, 
        "Following a complete static code analysis across all 23 project files, the functional implementation status "
        "has been categorized below with high technical fidelity."
    )
    
    # Implementation Table
    table_headers = ["Feature / Component", "Implementation State", "Source File Reference", "Technical Audit Notes"]
    table_data = [
        ["Passive DOM Security Scanner", "Fully Implemented", "content/dom-security.js", "Detects dangerous sinks, mixed content, reverse tabnabbing, and hidden elements with exact DOM selectors."],
        ["HTML Form Credential Auditor", "Fully Implemented", "content/form-security.js", "Flags plaintext passwords, GET forms, and missing anti-CSRF tokens with zero false crashes."],
        ["Luhn Checksum Credit Card DLP", "Fully Implemented", "content/sensitive-data-security.js", "Mathematical Luhn algorithm eliminates false positives; regex scans AWS keys, JWTs, and private keys."],
        ["CVE Signature Registry", "Fully Implemented", "content/cve-registry.js", "Data-driven rule catalog covering SQLi, Command Injection, LFI, SSRF, XSS, and vulnerable jQuery."],
        ["MITRE ATT&CK Matrix & SIEM Engine", "Fully Implemented", "content/siem-engine.js", "Correlates events, maps to MITRE tactics/techniques, and exports valid CEF, JSONL, and Syslog."],
        ["Response Headers & CSP Mitigation", "Fully Implemented", "service-worker.js & security-auditor.js", "Captures live HTTP headers via webRequest; dynamically downgrades false positives if CSP protects page."],
        ["Privacy Mode & AI Consent Controls", "Fully Implemented", "service-worker.js & dashboard.js", "Privacy Mode defaults to TRUE; AI disabled by default; requires explicit user consent."],
        ["Pre-Flight AI Sanitizer & Redactor", "Fully Implemented", "content/ai-sanitizer.js", "Strips auth, session IDs, JWTs, emails, and passwords from URLs and reasons before AI dispatch."],
        ["Direct Google Gemini API Integration", "Fully Implemented", "background/service-worker.js", "Direct client-side fetch to Gemini 2.5/2.0/1.5 Flash with fallback candidate models and cooldowns."],
        ["Offline Deterministic Remediation Engine", "Fully Implemented", "background/service-worker.js", "Built-in fallback generator produces actionable developer code fixes when AI is offline."],
        ["Extension Privilege Auditor", "Partially Implemented", "service-worker.js & extension-security.js", "Scans extensions via chrome.management. However, content/extension-security.js is redundant/unused."],
        ["Multi-Page Web Crawler", "Missing / Out of Scope", "N/A", "Only audits the active DOM of currently loaded tabs; does not spider or crawl entire web domains."]
    ]
    create_styled_table(doc, table_headers, table_data, [1.8, 1.2, 1.6, 2.2])
    
    add_heading_3(doc, "Key Code Weaknesses & Identified Bugs")
    add_bullet(doc, "Redundant File: content/extension-security.js exists in the repository but is omitted from manifest.json content_scripts because content scripts cannot access the chrome.management API. The logic was inlined into background/service-worker.js (line 125).", bold_prefix="Redundant Code: ")
    add_bullet(doc, "Ephemeral Service Worker Lifecycle: In Chromium Manifest V3, service workers sleep after 30 seconds of inactivity. If a Gemini API call hangs beyond 30 seconds without resolving, the worker could terminate prematurely. A keepalive port or timeout abort controller (currently 8s) mitigates this, but requires careful handling.", bold_prefix="Worker Termination Risk: ")
    add_bullet(doc, "Heuristic SPA Limitations: While MutationObserver detects DOM node additions with debouncing, client-side routing changes that alter the URL via window.history.pushState without a full page reload require background tabs.onUpdated tracking to consistently trigger re-scans.", bold_prefix="SPA Navigation Tracking: ")
    add_bullet(doc, "Storage Limit Handling: Scan history stores full vulnerability payloads in chrome.storage.local. While 'unlimitedStorage' permission is declared in manifest.json, unbounded history accumulation over months could increase memory footprint on low-RAM workstations.", bold_prefix="Storage Growth: ")

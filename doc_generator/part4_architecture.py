from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def build_part4(doc):
    add_heading_1(doc, "PART 4: COMPLETE PROJECT ARCHITECTURE & DATA FLOW")
    
    add_paragraph(doc,
        "ThreatLens is engineered around the Google Chrome Manifest V3 specification. It follows a decoupled, "
        "event-driven architecture where presentation (Popup/Dashboard), execution/orchestration (Background Service Worker), "
        "and client-side telemetry (Content Scripts) operate across strict process and security boundaries. "
        "This section details the architectural blueprint, data pipelines, IPC message topologies, and component lifecycles."
    )
    
    add_heading_2(doc, "4.1 Architecture Topology & Component Breakdown")
    
    add_paragraph(doc,
        "The system comprises three primary execution tiers communicating asynchronously via Chrome Inter-Process Communication (IPC):"
    )
    
    add_bullet(doc, "Tier 1: Client Content DOM Scanners (13 Injected Modules): Injected at 'document_idle' into the web page's Isolated World. Executes passive DOM queries, regex scans, algorithmic checksums, and MutationObservers without interfering with the page's host JavaScript environment.", bold_prefix="Content Execution Layer: ")
    add_bullet(doc, "Tier 2: Background Service Worker Orchestrator (service-worker.js): Ephemeral Chromium Service Worker running in the extension origin. Intercepts HTTP response headers (webRequest), audits installed extensions (management), coordinates isolated storage, updates browser UI badges, and manages AI interactions.", bold_prefix="Core Orchestration Layer: ")
    add_bullet(doc, "Tier 3: Presentation & Security Command Center (popup & dashboard): Independent extension pages running in isolated tabs/views. Renders threat gauges, MITRE ATT&CK matrices, extension risk audits, and exports SIEM streams (CEF, JSONL, Syslog) and Markdown reports.", bold_prefix="Presentation Layer: ")
    add_bullet(doc, "Tier 4: Serverless AI Integration (Direct Google Gemini REST API): Communicates directly from background/service-worker.js to Google Gemini endpoints via HTTPS. Operates under strict user consent, with pre-flight PII/credential sanitization and an offline deterministic fallback generator.", bold_prefix="AI Intelligence Layer: ")
    
    add_heading_2(doc, "4.2 Architecture ASCII Flow Diagrams")
    
    add_heading_3(doc, "Diagram 1: End-to-End System Architecture")
    add_code_block(doc,
r"""
+----------------------------------------------------------------------------------------------------+
|                                    TARGET WEB BROWSER PAGE                                         |
|  [ DOM Tree ]  <--->  [ Forms / Scripts / Iframes ]  <--->  [ Text Content / Exposed Secrets ]    |
+----------------------------------------------------------------------------------------------------+
                                      | (Passive In-Memory Inspection)
                                      v
+----------------------------------------------------------------------------------------------------+
|                          CHROME CONTENT SCRIPT RUNTIME (Isolated World)                             |
|  +--------------------+  +--------------------+  +--------------------+  +----------------------+  |
|  | url-security.js    |  | dom-security.js    |  | form-security.js   |  | script-iframe-sec.js |  |
|  +--------------------+  +--------------------+  +--------------------+  +----------------------+  |
|  | sensitive-data.js  |  | cve-registry.js    |  | phishing-sec.js    |  | prompt-injection.js  |  |
|  +--------------------+  +--------------------+  +--------------------+  +----------------------+  |
|                                     |                                                              |
|                                     v                                                              |
|                     [ security-auditor.js (CSP Mitigation) ]                                       |
|                                     v                                                              |
|                     [ risk-engine.js (Weighted Scoring) ]                                          |
|                                     v                                                              |
|                     [ content.js (Master Coordinator) ]                                            |
+----------------------------------------------------------------------------------------------------+
                                      |
                                      | chrome.runtime.sendMessage({ type: "SCAN_RESULT" })
                                      v
+----------------------------------------------------------------------------------------------------+
|                         BACKGROUND SERVICE WORKER (service-worker.js)                              |
|  +-----------------------------+  +-------------------------------+  +--------------------------+  |
|  | chrome.webRequest (Headers) |  | chrome.management (Extensions)|  | Action Badge Controller  |  |
|  +-----------------------------+  +-------------------------------+  +--------------------------+  |
|                                      |                                                             |
|                  +-------------------+--------------------+                                        |
|                  |                                        |                                        |
|                  v                                        v                                        |
|      [ chrome.storage.local ]               [ AI Analysis Decision Gate ]                          |
|      (Cached per Tab/URL)                   (PrivacyMode==True? AI==Enabled?)                     |
|                  ^                                        |                                        |
|                  |                                        v                                        |
|                  |                       [ ai-sanitizer.js (Pre-Flight DLP) ]                      |
|                  |                       (Masks Tokens, Passwords, Session IDs)                    |
|                  |                                        |                                        |
|                  |                               +--------+--------+                               |
|                  |                               |                 |                               |
|                  |                               v                 v                               |
|                  |                      [ Gemini API ]    [ Offline Fallback ]                     |
|                  |                      (HTTPS REST)      (Deterministic Fixes)                    |
|                  |                               |                 |                               |
|                  +-------------------------------+-----------------+                               |
+----------------------------------------------------------------------------------------------------+
                                      |
                      +---------------+---------------+
                      |                               |
                      v                               v
+------------------------------------+  +------------------------------------------------------------+
|        TOOLBAR POPUP VIEW          |  |                   FULL SOC DASHBOARD                       |
|   (popup.html / popup.js)          |  |             (dashboard.html / dashboard.js)                |
|  - Real-time Threat Badge          |  |  - Threat Overview Gauge & Metric Summary Cards            |
|  - High/Critical Counter Pills     |  |  - Interactive Finding Explorer with DOM Selectors         |
|  - Quick Re-scan Trigger           |  |  - MITRE ATT&CK Matrix Navigator                           |
|  - 'Open Full Dashboard' Link      |  |  - Installed Browser Extension Privilege Auditor           |
|                                    |  |  - AI Security Mentor Panel (Analogy & Developer Patch)    |
|                                    |  |  - SIEM Log Exporter (CEF / JSONL / Syslog)                |
|                                    |  |  - Audit-Ready Markdown Pentest Report Generator           |
+------------------------------------+  +------------------------------------------------------------+
""", language="ASCII Architecture Diagram")
    
    add_heading_3(doc, "Diagram 2: Dynamic CSP Mitigation & False-Positive Reduction Flow")
    add_code_block(doc,
r"""
[ Web Server ] ---> HTTP 200 OK Response Headers (Content-Security-Policy: script-src 'self')
                          |
                          v
        [ background/service-worker.js ]
        Intercepts headers via chrome.webRequest.onHeadersReceived
        Stores headerData in tabSecurityHeaders Map & chrome.storage.local
                          |
                          v (Dispatched to Content Script)
        [ content/security-auditor.js (detectAndParseActiveCsp) ]
        Parses CSP directives: script-src, default-src, frame-ancestors
                          |
                          v
        [ Finding Detected ]: Inline <script> tag detected in DOM
                          |
                          v
        [ Evaluation ]: Does active CSP enforce script-src 'self' without 'unsafe-inline'?
                          |
            +-------------+-------------+
            | YES                       | NO
            v                           v
   [ Mitigate Finding ]:          [ Maintain Finding ]:
   - Severity downgraded          - Severity remains HIGH
   - Marked: "[CSP MITIGATED]"   - Risk score increased
   - Exploit vector blocked       - Remediation required
""", language="ASCII CSP Flow")
    
    add_heading_3(doc, "Diagram 3: Privacy Gate & Pre-Flight AI Sanitization Pipeline")
    add_code_block(doc,
r"""
[ User Requests AI Remediation / Auto-Scan Triggered ]
                          |
                          v
[ Decision Gate 1 ]: Is privacyMode == true?
                          |
                          v
[ Decision Gate 2 ]: Is aiEnabled == true AND aiConsent == true?
                          |
            +-------------+-------------+
            | NO (Default State)        | YES (Explicit Consent Granted)
            v                           v
  [ Trigger Offline Engine ]     [ Decision Gate 3 ]: Is Gemini API Key Configured?
  - Generates deterministic,                   |
    syntax-highlighted code        +-----------+-----------+
    remediation locally            | NO                    | YES
  - Zero network packets sent      v                       v
                          [ Trigger Offline Engine ]  [ Execute Pre-Flight Sanitizer ]
                                                      (content/ai-sanitizer.js)
                                                      - sanitizeUrl(): strip user:pass, tokens
                                                      - sanitizeReason(): strip JWTs, AWS keys,
                                                        passwords, cookies, session IDs
                                                      - Character bounding (max 400 chars/reason)
                                                           |
                                                           v
                                                      [ Dispatch HTTPS to Google Gemini API ]
                                                      (generativelanguage.googleapis.com)
                                                           |
                                           +---------------+---------------+
                                           | HTTP 200 OK                   | Error / Timeout (8s)
                                           v                               v
                                  [ Parse Gemini JSON ]         [ Fallback to Offline Engine ]
                                  - Layman analogy              - Deterministic code snippets
                                  - Developer code patch        - Preserves user experience
""", language="ASCII AI Pipeline")
    
    add_heading_2(doc, "4.3 Step-by-Step Execution Lifecycle Walkthrough")
    
    steps = [
        ("Step 1: Installation & Initialization",
         "When the extension is loaded or installed into Chrome, the background service worker initializes. It inspects chrome.storage.local for configuration flags. If uninitialized, it sets privacyMode: true, aiEnabled: false, and aiConsent: false. It also registers listeners for chrome.webRequest.onHeadersReceived, chrome.runtime.onMessage, and chrome.tabs.onRemoved."),
        
        ("Step 2: User Navigates to a Website",
         "The user enters a URL (e.g., http://pentest-ground.com:4280/login.php). Before the HTML renders, the web server returns HTTP response headers. The background service worker intercepts these headers, extracts Content-Security-Policy, HSTS, X-Frame-Options, and Server tokens, and caches them in tabSecurityHeaders under the active tab ID."),
        
        ("Step 3: Content Script Infiltration at document_idle",
         "Once the DOM finishes parsing ('document_idle'), Chrome injects the 13 content scripts declared in manifest.json into the page's isolated world. content.js triggers scanPage('page-load'). It immediately queries the background service worker via chrome.runtime.sendMessage({ type: 'GET_SECURITY_HEADERS' }) to pull the live response headers into the page context."),
        
        ("Step 4: Parallel Modular Inspection",
         "The content script executes individual analyzers in safe try/catch sandboxes:\n"
         "• url-security.js checks protocol (HTTP), non-standard port (4280), and query parameters.\n"
         "• dom-security.js queries for dangerous sinks (document.write, eval) and mixed content assets.\n"
         "• form-security.js inspects all forms for plaintext HTTP actions and password inputs.\n"
         "• sensitive-data-security.js scans DOM text and comments for AWS keys, JWTs, and credit cards (Luhn algorithm).\n"
         "• web-vulnerability-security.js matches page text against CVE signatures (SQL errors, LFI, SSRF).\n"
         "• prompt-injection-security.js scans for instruction overrides and hidden injection divs.\n"
         "• phishing-security.js correlates domain structure, TLD, and password fields to compute phishing score."),
        
        ("Step 5: Defense-in-Depth CSP Mitigation",
         "Before calculating final risk, security-auditor.js evaluates active Content Security Policies. If the page defines a strict script-src directive preventing 'unsafe-inline', inline script findings are mitigated, down-grading severity and marking the issue as safely defended by the server."),
        
        ("Step 6: Risk Normalization & Aggregation",
         "All normalized findings pass to risk-engine.js. Severity weights are summed (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3). Compound correlation rules execute: if an insecure form is paired with a suspicious domain, risk escalates to CRITICAL. The overall risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL) is derived."),
        
        ("Step 7: Transmission & Badge Update",
         "content.js packages the entire scan result and transmits it to the background service worker via chrome.runtime.sendMessage({ type: 'SCAN_RESULT', data: result }). The service worker stores the result in chrome.storage.local under the tab key, computes combined risk including installed browser extension privileges, and updates the Chrome action badge (e.g., Red 'CRIT' or Green 'SAFE')."),
        
        ("Step 8: UI Dashboard Presentation",
         "When the user clicks the extension toolbar icon, popup.js reads the stored result and displays an immediate risk badge. Clicking 'Open Dashboard' launches dashboard.html. dashboard.js renders the full Security Command Center: populating the Threat Gauge, the interactive Finding Explorer with exact DOM selectors, the MITRE ATT&CK Matrix heatmap, the Browser Extension Auditor, and the SIEM export tools."),
        
        ("Step 9: AI Enrichment or Offline Fallback",
         "If the user views the AI Mentor panel or clicks 'Request AI Analysis', service-worker.js evaluates privacy gates. If AI is enabled with a valid Gemini key, ai-sanitizer.js redacts all tokens, and an HTTPS POST is sent to Gemini Flash. If AI is disabled or offline, our deterministic engine generates rich, syntax-highlighted code fixes locally within 5 milliseconds."),
        
        ("Step 10: Single-Page Application (SPA) Monitoring",
         "If the website is an SPA (React, Vue, Angular) that dynamically mutates the DOM without full reloads, a debounced MutationObserver (300ms delay) detects added form or script nodes and triggers scanPage('dom-mutation'), ensuring continuous real-time protection.")
    ]
    
    for s_title, s_desc in steps:
        add_heading_3(doc, s_title)
        add_paragraph(doc, s_desc)

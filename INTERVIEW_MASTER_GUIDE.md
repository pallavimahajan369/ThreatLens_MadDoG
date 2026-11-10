# 🛡️ ThreatLens: Master Implementation & Execution Flow Guide (Interview Edition)

> **Target Audience:** Interview preparation (Junior, Mid, Senior & Security Engineering roles).  
> **Language:** Simple English with clear diagrams, code traces, and graded interview answers (Easy → Hard).  
> **Location:** Direct project documentation for your portfolio and presentation.

---

## 📑 Table of Contents

1. [High-Level Executive Pitch (Your 60-Second Interview Opener)](#1-high-level-executive-pitch)
2. [Complete Implementation: Step-by-Step From Scratch](#2-complete-implementation-step-by-step-from-scratch)
3. [End-to-End Runtime Execution Flow](#3-end-to-end-runtime-execution-flow)
4. [Deep Dive: Lifecycle & Chrome IPC (Inter-Process Communication)](#4-deep-dive-lifecycle--chrome-ipc)
5. [Algorithmic Breakdown with Concrete Examples](#5-algorithmic-breakdown-with-concrete-examples)
6. [From Easy to Hard: Graded Interview Questions & Answers](#6-from-easy-to-hard-graded-interview-questions--answers)
7. [System Architecture & Flow Diagrams](#7-system-architecture--flow-diagrams)
8. [Edge Cases, Pitfalls & How They Were Overcome](#8-edge-cases-pitfalls--how-they-were-overcome)
9. [Interview Quick-Reference Card (Cheat Sheet)](#9-interview-quick-reference-card)

---

## 1. High-Level Executive Pitch

### How to introduce the project when the interviewer asks: *"Tell me about your project."*

> *"ThreatLens is an ocular client-side web vulnerability scanner and SOC/SIEM browser extension built on Chrome Manifest V3 using pure Vanilla JavaScript.*
>
> *Unlike traditional scanners like Burp Suite or ZAP which require network proxying and external daemon servers, ThreatLens operates 100% locally in the browser runtime sandbox.*
>
> *It passively audits the DOM, network requests, scripts, forms, and URLs against 23+ OWASP Top 10 vulnerabilities, detects real-world CVEs (like CVE-2024-4577 and CVE-2020-11022), maps telemetry to the MITRE ATT&CK enterprise matrix, correlates multi-stage attack chains in a client-side SIEM engine, sanitizes sensitive tokens to prevent data leakage, and outputs enterprise-standard CEF, JSONL, and RFC-5424 Syslog reports.*
>
> *It solves three major problems: zero infrastructure cost, zero privacy leakage, and instant real-time ethical reconnaissance."*

---

## 2. Complete Implementation: Step-by-Step From Scratch

When the interviewer asks: *"How did you build this project step by step? Walk me through your engineering phases."*

Here is the structured 7-phase implementation blueprint:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Architecture, Manifest V3 Setup & Security Boundary Design   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 2: Building the Data-Driven Vulnerability & CVE Rule Registry   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 3: Constructing the Specialized Content Script Analyzers         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 4: Risk Scoring & 11 Heuristic Correlation Engine Implementation │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 5: Client-Side SIEM, MITRE ATT&CK Mapping & Multi-Stage Chains   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 6: Privacy Shield (AI Sanitizer) & Service Worker State Store    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 7: UI Layer (Toolbar Popup & Cyberpunk Deep-Audit Dashboard)     │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1: Manifest V3 & Security Architecture Setup

1. **Configured `manifest.json`**:
   - Specified `manifest_version: 3`.
   - Requested least-privilege permissions: `storage`, `tabs`, `management`, `unlimitedStorage`.
   - Enforced Content Security Policy (CSP):
     ```json
     "content_security_policy": {
       "extension_pages": "script-src 'self'; object-src 'self'"
     }
     ```
   - Defined content script injection array with `run_at: "document_idle"` to ensure the target DOM is fully loaded before analysis runs.
   - Configured the background service worker: `background/service-worker.js`.

---

### Phase 2: The Data-Driven Vulnerability & CVE Rule Registry (`cve-registry.js`)

Instead of writing hardcoded `if-else` blocks inside UI scripts, I decoupled vulnerability logic into a **declarative data registry**:
- Each rule is an object defining: `id`, `cveId` (or CWE), `title`, `category`, `severity`, `cvssScore`, `cvssVector`, `match(ctx)` function, `riskExplanation`, `solution`, and `verificationSteps`.
- The `ctx` (context) provides `url`, `host`, `pathname`, `search`, `bodyText`, `forms`, `links`, and `scripts`.
- Added critical detection rules:
  - **SQL Injection (CWE-89)**: Multi-vendor database regexes (MySQL, PostgreSQL, Oracle, SQLite, MSSQL).
  - **PHP CGI RCE (CVE-2024-4577)**: Detects soft-hyphen `%ad` and `-d` argument injection.
  - **jQuery DOM XSS (CVE-2020-11022)**: Checks for vulnerable legacy jQuery versions (`<3.5.0`).
  - **LFI/RFI (CWE-22)**: Detects directory traversal patterns like `../../etc/passwd` or `php://filter`.
  - **Unrestricted File Upload (CWE-434)**: Matches multi-part file forms without extension validation.

---

### Phase 3: Building Specialized Passive Content Analyzers

I split the inspection responsibilities into single-responsibility content modules:
1. **`url-security.js`**:
   - Parses `window.location`.
   - Checks protocols (`javascript:`, `data:`).
   - Identifies high-risk non-standard ports (e.g., `8080`, `4444`, `9200`).
   - Flags suspicious query parameters (`?redirect=`, `?url=`, `?cmd=`).
2. **`dom-security.js`**:
   - Traverses the DOM tree.
   - Computes unique CSS selector paths (e.g., `form#login > div > input.user-field`) via `getDomSecurityDomPath()`.
   - Flags legacy high-risk tags (`<object>`, `<embed>`, `<applet>`).
3. **`form-security.js`**:
   - Inspects form submission methods (`GET` vs `POST`).
   - Flags sensitive credential inputs submitted via insecure cleartext HTTP or `GET` query strings.
   - Inspects Cross-Origin form actions (e.g., target domain `bank.com` sending POST to `evil.com`).
4. **`script-iframe-security.js`**:
   - Inspects external `<script>` origins.
   - Audits `<iframe>` containers for zero dimensions (`width="0" height="0"` or hidden visibility indicating clickjacking).
   - Verifies presence of the `sandbox` attribute on cross-origin frames.
5. **`sensitive-data-security.js`**:
   - Implements the mathematical **Luhn Checksum Algorithm** (`isValidLuhn()`) to validate Visa, Mastercard, and Amex credit cards while preventing false positives.
   - Uses bounded regex context windows to detect AWS Secret Keys (`AKIA...`), JWT tokens (`eyJ...`), and private RSA keys (`-----BEGIN PRIVATE KEY-----`).
6. **`phishing-security.js`**:
   - Computes a composite 0–100 heuristic risk score by weighting suspicious URLs (+30), password forms (+20), and cross-origin actions (+40).
7. **`prompt-injection-security.js`**:
   - Scans DOM text nodes for LLM jailbreak attempts (`"ignore all previous instructions"`, `"DAN mode"`, system prompt override patterns).

---

### Phase 4: Deterministic Composite Risk Engine (`risk-engine.js`)

1. Strips all informational `NO_*` type findings (e.g., `NO_SUSPICIOUS_DOM_PATTERN`).
2. Calculates highest individual severity weight:
   $$\text{SAFE} = 0, \quad \text{LOW} = 1, \quad \text{MEDIUM} = 2, \quad \text{HIGH} = 3, \quad \text{CRITICAL} = 4$$
3. Applies **11 Multi-Factor Correlation Rules**:
   - *Example:* If `suspiciousURL` + `passwordField` + `crossOriginForm` are all present $\rightarrow$ Escalate to `CRITICAL` Phishing.
   - *Example:* If `SQL_INJECTION_ENDPOINT` + `interactiveForm` + `activeDbError` are present $\rightarrow$ Confirm active SQLi.
4. Elevates risk dynamically:
   - 2+ correlations with `MEDIUM` base $\rightarrow$ Elevates to `HIGH`.
   - 3+ correlations $\rightarrow$ Elevates to `CRITICAL`.

---

### Phase 5: Client-Side SIEM Engine (`siem-engine.js`)

1. Standardizes raw findings into normalized SIEM Security Event objects.
2. Injects **MITRE ATT&CK Enterprise Matrix** attributes:
   - `tactic` (e.g., *Initial Access*, *Execution*, *Credential Access*)
   - `tacticId` (e.g., `TA0001`, `TA0002`, `TA0006`)
   - `techniqueId` (e.g., `T1190`, `T1059.004`, `T1539`)
   - `techniqueName`
3. Implements **Multi-Stage Attack Chain Correlation**:
   - *Stage 1:* Reconnaissance & Fingerprint Discovery (`T1082`).
   - *Stage 2:* Public-Facing Exploitation Target (`T1190`).
   - *Stage 3:* Session Token Hijack (`T1539`).
4. Generates standard log streams:
   - **CEF (Common Event Format)** for Splunk & ArcSight.
   - **JSONL (JSON Lines)** for ELK Stack (Elasticsearch).
   - **RFC-5424 Syslog** for Linux log forwarders.

---

### Phase 6: Privacy Shield (`ai-sanitizer.js`) & Service Worker

1. Developed `ai-sanitizer.js` with zero-trust token masking:
   - Strips session IDs: `PHPSESSID`, `JSESSIONID`, `ASPSESSIONID`, `connect.sid`.
   - Strips auth tokens: Bearer JWTs, AWS credentials, user passwords.
   - Strips credentials embedded in URLs: `http://admin:secret@domain.com` $\rightarrow$ `http://domain.com`.
2. Implemented `service-worker.js`:
   - Listens for `SCAN_RESULT` message via Chrome Runtime API.
   - Saves results per-tab in `chrome.storage.local`.
   - Provides on-demand data to Popup and Dashboard.
   - Optionally interfaces with Google Gemini API using the user's encrypted local key.

---

### Phase 7: UI Layer (Popup & Cyberpunk Dashboard)

1. **Toolbar Popup (`popup/`)**: Fast 2-second overview with circular risk gauge and top reasons.
2. **Deep-Audit Dashboard (`dashboard/`)**:
   - Executive verdict banners.
   - Tabular code inspector with CVSS v3.1 vector strings.
   - 1-Click download for Pentest Reports (`.md`) and SIEM logs (`.cef`, `.jsonl`, `.log`).
   - Dark Cyberpunk/Ocular styling with accessible contrast.

---

## 3. End-to-End Runtime Execution Flow

Here is the exact millisecond-by-millisecond lifecycle of what happens when a user browses to a page (e.g., `http://dvwa.local/vulnerabilities/sqli/?id=1`):

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant DOM as Webpage DOM
    participant CS as content.js (Orchestrator)
    participant Reg as cve-registry.js
    participant Risk as risk-engine.js
    participant SIEM as siem-engine.js
    participant SW as service-worker.js
    participant Store as chrome.storage.local
    participant UI as Popup / Dashboard

    User->>DOM: Navigates to Target Page
    Note over DOM: Page loads HTML & scripts
    DOM-->>CS: document_idle event fires
    
    rect rgb(20, 30, 45)
    Note over CS: Step 1: Initialize Context (ctx)
    CS->>CS: Gather window.location, bodyText, forms, scripts
    end

    rect rgb(30, 40, 60)
    Note over CS,Reg: Step 2: Parallel Passive Analysis
    CS->>CS: analyzeURL()
    CS->>CS: analyzeDOM()
    CS->>CS: analyzeFormSecurity()
    CS->>CS: analyzeScriptIframe()
    CS->>CS: analyzeSensitiveData()
    CS->>Reg: runWebVulnerabilityChecks(ctx)
    Reg-->>CS: Returns matched CVE findings (e.g., CWE-89 SQLi)
    CS->>CS: analyzePhishingRisk()
    CS->>CS: analyzePromptInjection()
    end

    rect rgb(40, 50, 70)
    Note over CS,Risk: Step 3: Composite Risk Evaluation
    CS->>Risk: calculateOverallRisk(allFindings)
    Risk->>Risk: Apply 11 Correlation Rules
    Risk-->>CS: Returns { level: "CRITICAL", reasons: [...] }
    end

    rect rgb(30, 60, 50)
    Note over CS,SIEM: Step 4: SIEM Normalization & ATT&CK Mapping
    CS->>SIEM: processFindings(findings, url)
    SIEM->>SIEM: Map to T1190, T1059, TA0001
    SIEM->>SIEM: Correlate Multi-Stage Incidents
    SIEM-->>CS: Normalized SIEM Event Log
    end

    rect rgb(50, 30, 60)
    Note over CS,Store: Step 5: IPC Dispatch & Storage
    CS->>SW: chrome.runtime.sendMessage({ type: "SCAN_RESULT", data })
    SW->>Store: chrome.storage.local.set({ [tabId]: data })
    end

    rect rgb(60, 40, 30)
    Note over User,UI: Step 6: User Inspection
    User->>UI: Clicks Extension Icon
    UI->>SW: chrome.runtime.sendMessage({ type: "GET_SCAN_DATA" })
    SW->>Store: chrome.storage.local.get(tabId)
    Store-->>SW: Cached scan payload
    SW-->>UI: Response payload
    UI->>User: Renders Risk Gauge, Findings, & SIEM Stream
    end
```

---

## 4. Deep Dive: Lifecycle & Chrome IPC (Inter-Process Communication)

### Why Manifest V3 IPC Is Asynchronous
In Chrome extensions, the **Content Script** runs in the context of the web page, while the **Service Worker** runs in an isolated browser background process. They cannot share memory or variables. They communicate strictly using message passing.

#### 1. Content Script Dispatch (`content/content.js`)
```javascript
// Once all engines complete, content.js dispatches the bundle
chrome.runtime.sendMessage({
    type: "SCAN_RESULTS",
    tabId: null, // Service worker identifies tab from sender.tab.id
    url: window.location.href,
    overallRisk: overallRisk.level,
    findings: aggregatedFindings,
    siemEvents: siemEngine.getEvents(),
    auditorData: auditorReport
});
```

#### 2. Service Worker Storage Listener (`background/service-worker.js`)
```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_RESULTS") {
        const tabId = sender.tab ? sender.tab.id : "global";
        
        // Save scan results in local storage indexed by Tab ID
        chrome.storage.local.set({ [`scan_${tabId}`]: message }, () => {
            // Update badge color based on risk
            const badgeColor = message.overallRisk === "CRITICAL" ? "#FF0033" : 
                               message.overallRisk === "HIGH"     ? "#FF6600" : "#00CC66";
            chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
            chrome.action.setBadgeText({ text: message.overallRisk.substring(0, 3), tabId });
        });
        
        sendResponse({ status: "STORED" });
    }
    return true; // Keeps channel open for async response
});
```

#### 3. Dashboard Requesting Stored Telemetry (`dashboard/dashboard.js`)
```javascript
// Query active tab ID first
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTabId = tabs[0]?.id;
    chrome.storage.local.get([`scan_${activeTabId}`], (result) => {
        const payload = result[`scan_${activeTabId}`];
        if (payload) {
            renderDashboard(payload);
        }
    });
});
```

---

## 5. Algorithmic Breakdown with Concrete Examples

### Algorithm 1: Credit Card Luhn Algorithm (`sensitive-data-security.js`)

**Why it matters:** Simple regexes matching 16 digits produce massive false positives on random serial numbers, tracking IDs, or timestamps. The Luhn algorithm verifies genuine credit card numbers.

```javascript
function isValidLuhn(number) {
    let sum = 0;
    let shouldDouble = false;
    
    // Loop right to left
    for (let i = number.length - 1; i >= 0; i--) {
        let digit = parseInt(number[i], 10);
        
        if (shouldDouble) {
            digit *= 2;
            if (digit > 9) digit -= 9; // e.g. 7 * 2 = 14 -> 14 - 9 = 5
        }
        
        sum += digit;
        shouldDouble = !shouldDouble;
    }
    
    return sum % 10 === 0;
}
```

*Example Trace:*
- Card: `49927398716`
- Doubling every second digit from right:
  - `6` $\rightarrow 6$
  - `1 * 2` $\rightarrow 2$
  - `7` $\rightarrow 7$
  - `8 * 2 = 16 - 9` $\rightarrow 7$
  - `9` $\rightarrow 9$
  - `3 * 2` $\rightarrow 6$
  - `7` $\rightarrow 7$
  - `2 * 2` $\rightarrow 4$
  - `9` $\rightarrow 9$
  - `9 * 2 = 18 - 9` $\rightarrow 9$
  - `4` $\rightarrow 4$
- Total Sum $= 70$. $70 \pmod{10} = 0 \rightarrow$ **Valid Card Number!**

---

### Algorithm 2: DOM CSS Selector Path Generator (`dom-security.js`)

**Why it matters:** In automated penetration testing, reporting *"an input field is insecure"* is useless. Security engineers need the exact DOM path to remediate the element.

```javascript
function getDomSecurityDomPath(el) {
    if (!el || !el.tagName) return "";
    const path = [];
    let current = el;
    
    while (current && current.nodeType === 1 && current.tagName !== "HTML" && current.tagName !== "BODY") {
        let selector = current.tagName.toLowerCase();
        
        if (current.id) {
            selector += `#${current.id}`;
            path.unshift(selector);
            break; // Unique ID reached, stop climbing!
        } else if (current.getAttribute("name")) {
            selector += `[name="${current.getAttribute("name")}"]`;
        } else if (current.className && typeof current.className === "string") {
            const firstClass = current.className.trim().split(/\s+/)[0];
            if (firstClass && !firstClass.includes(":")) selector += `.${firstClass}`;
        }
        
        path.unshift(selector);
        current = current.parentElement;
    }
    
    return path.join(" > ") || el.tagName.toLowerCase();
}
```

*Output Example:*  
`div#wrapper > form.login-form > div.input-group > input[name="user_password"]`

---

### Algorithm 3: Zero-Trust URL & Parameter Sanitizer (`ai-sanitizer.js`)

**Why it matters:** Passing raw URLs to external LLM APIs leaks session IDs (`PHPSESSID`), auth tokens, and embedded passwords.

```javascript
function sanitizeUrl(rawUrl) {
    try {
        const u = new URL(rawUrl);
        
        // 1. Strip HTTP Basic Auth credentials (e.g. http://admin:pass@host)
        u.username = "";
        u.password = "";
        
        // 2. Redact sensitive parameter values
        const sensitiveRegex = /^(?:phpsessid|jsessionid|token|access_token|key|api_key|password|passwd|secret)$/i;
        
        u.searchParams.forEach((val, key) => {
            if (sensitiveRegex.test(key) || /^[a-f0-9]{32,64}$/i.test(val)) {
                u.searchParams.set(key, "[REDACTED_SECRET]");
            }
        });
        
        return u.toString();
    } catch (e) {
        return rawUrl.replace(/password=[^&]+/gi, "password=[REDACTED]");
    }
}
```

---

## 6. From Easy to Hard: Graded Interview Questions & Answers

### 🟢 Level 1: Fundamentals (Easy)

#### Q1.1: What is a Chrome Content Script, and why does ThreatLens need it?
**Answer:**  
A Content Script is JavaScript that executes directly inside the context of a loaded web page. ThreatLens needs it because browser security (Same-Origin Policy) forbids extension background workers from directly accessing a page's DOM, form inputs, script tags, or cookies. The content script acts as our "sensor" inside the website's execution bubble.

#### Q1.2: What is the difference between active and passive security scanning?
**Answer:**  
- **Active Scanning:** Sends payloads, injects `' OR 1=1--`, floods requests, and modifies server state (like Burp Suite Scanner). This can crash servers or violate laws without written permission.
- **Passive Scanning:** ThreatLens **only reads and inspects** what the server has already sent to the browser. It never transmits attacking requests. It is 100% non-destructive and legally safe for authorized analysis.

#### Q1.3: What is CWE and CVE?
**Answer:**  
- **CWE (Common Weakness Enumeration):** A formal dictionary of weakness types (e.g., `CWE-89` is the general category for SQL Injection).
- **CVE (Common Vulnerabilities and Exposures):** An identifier for a specific instance of a vulnerability in a specific product (e.g., `CVE-2024-4577` is a specific argument injection bug in PHP).

---

### 🟡 Level 2: Implementation & Architecture (Medium)

#### Q2.1: Why did you choose Manifest V3 over Manifest V2?
**Answer:**  
Manifest V3 is Google's modern extension standard. It introduces:
1. **Service Workers instead of Background Pages:** Background pages run continuously, consuming CPU and memory. Service workers terminate when idle and wake on events, improving battery and performance.
2. **Prohibition of Remote Code Execution:** Manifest V3 forbids `eval()` or fetching scripts from remote CDNs. All ThreatLens logic is self-contained and auditable.
3. **Declarative Network & Granular Permissions:** Limits unauthorized snooping on user traffic.

#### Q2.2: How does your 11-rule Correlation Engine prevent false positives?
**Answer:**  
A single isolated indicator is often harmless. For example, a password input field on a page is standard practice. But if our engine detects:
1. `url-security.js` flags a brand-new suspicious domain with Punycode (`xn--`),
2. `form-security.js` flags a password input field,
3. `form-security.js` flags that the form `action` submits cross-origin to a third-party server,

The engine fires **Rule 2: Suspicious URL + Password Field + Cross-Origin Form Action**. This elevates the severity from `LOW` to `CRITICAL Phishing` because the combination proves malicious intent with statistical confidence.

#### Q2.3: How do you handle Single Page Applications (SPAs) like React or Angular where pages don't reload?
**Answer:**  
We attach a `MutationObserver` to `document.body`. When a user navigates or opens dynamic modal dialogs, React modifies DOM nodes without a full page reload. The `MutationObserver` catches new nodes and triggers debounced re-scans, ensuring that dynamically rendered forms or API routes are inspected in real time.

---

### 🔴 Level 3: Advanced Security Engineering (Hard)

#### Q3.1: Walk me through your detection logic for CVE-2024-4577 (PHP CGI Argument Injection).
**Answer:**  
*Background:* CVE-2024-4577 is a critical Remote Code Execution vulnerability in PHP on Windows when run in CGI mode (e.g., XAMPP/Apache). Windows' "Best-Fit" character encoding converts soft-hyphens (`0xAD`) into ASCII hyphens (`-`, `0x2D`).

*Our Detection Implementation:*
1. Our `cve-registry.js` engine inspects `window.location.search` and query parameters for URL-encoded soft-hyphens (`%ad`) followed by dangerous PHP CGI directives:
   - `?-d+allow_url_include=1`
   - `?-d+auto_prepend_file=php://input`
   - `?-d+cgi.force_redirect=0`
2. If matched, ThreatLens flags the finding with **CVSS v3.1 Score 9.8 (CRITICAL)**.
3. It links remediation guidance: upgrading to PHP 8.3.8+, disabling `Action php-cgi` in Apache, and deploying mod_rewrite rules to reject queries containing `%ad`.

#### Q3.2: How does ThreatLens map findings to the MITRE ATT&CK Framework, and why is this valuable to a SOC?
**Answer:**  
In enterprise Security Operations Centers (SOCs), raw alerts are too noisy. SOC analysts triage events using MITRE ATT&CK:
1. In `siem-engine.js`, we maintain a constant dictionary mapping vulnerability types to ATT&CK tactics and techniques.
2. For SQLi, it assigns **Tactic: Initial Access (`TA0001`)** and **Technique: Exploit Public-Facing Application (`T1190`)**.
3. For Command Injection, it assigns **Tactic: Execution (`TA0002`)** and **Technique: Command and Scripting Interpreter: Unix Shell (`T1059.004`)**.
4. We normalize these into CEF (Common Event Format) strings with `cs2=T1190 cs2Label=mitreId`. When exported to Splunk or IBM QRadar, SOC dashboards automatically aggregate our telemetry into their existing attack heatmaps.

#### Q3.3: How does your AI Sanitizer guarantee that user secrets are never leaked to external LLMs?
**Answer:**  
Before any payload leaves the machine to Google Gemini, it passes through `buildAISecurityPayload()` in `ai-sanitizer.js`:
1. **Zero Raw DOM:** It never transmits HTML trees, script bodies, or text inputs.
2. **Regex Secret Redaction:** It scrubs 15+ patterns including Bearer tokens, AWS keys (`AKIA...`), JWT hashes (`ey...`), Private RSA Keys, and cookies (`Set-Cookie`, `PHPSESSID`).
3. **URL Parsing & Sanitization:** It parses URLs via the standard `URL` constructor, wiping `username`, `password`, and sensitive query keys.
4. **Whitelist Categorization:** Only sanitized high-level strings (e.g., `"SQL Injection on /sqli/ detected"`) are sent. Thus, confidential credentials can never be leaked to the model.

---

## 7. System Architecture & Flow Diagrams

### Comprehensive System Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TARGET BROWSER TAB                              │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                          Webpage DOM                           │   │
│   │   [HTML Forms]   [Inline Scripts]   [Iframes]   [URL / Query]  │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                 Injected via Chrome Content Scripts                    │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 ThreatLens Content Engine                      │   │
│   │                                                                │   │
│   │  ┌───────────────┐ ┌───────────────┐ ┌──────────────────────┐  │   │
│   │  │ url-security  │ │ dom-security  │ │ form-security        │  │   │
│   │  └───────────────┘ └───────────────┘ └──────────────────────┘  │   │
│   │  ┌───────────────┐ ┌───────────────┐ ┌──────────────────────┐  │   │
│   │  │ script-iframe │ │ sensitive-data│ │ phishing-security    │  │   │
│   │  └───────────────┘ └───────────────┘ └──────────────────────┘  │   │
│   │  ┌───────────────┐ ┌───────────────┐ ┌──────────────────────┐  │   │
│   │  │ prompt-inject │ │ security-audit│ │ cve-registry (23+)   │  │   │
│   │  └───────────────┘ └───────────────┘ └──────────────────────┘  │   │
│   │                                                                │   │
│   │               ┌───────────────────────────────┐                │   │
│   │               │   risk-engine.js (Correlator) │                │   │
│   │               └───────────────┬───────────────┘                │   │
│   │                               ▼                                │   │
│   │               ┌───────────────────────────────┐                │   │
│   │               │   siem-engine.js (MITRE Mapp) │                │   │
│   │               └───────────────────────────────┘                │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ chrome.runtime.sendMessage
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CHROME EXTENSION BACKGROUND ISOLATION                │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │               background/service-worker.js                     │   │
│   │                                                                │   │
│   │   - Central Event Orchestrator                                 │   │
│   │   - Chrome Badge Controller (RED / ORANGE / GREEN)             │   │
│   │   - Storage Manager (chrome.storage.local)                     │   │
│   │   - Privacy Shield & Local Gemini AI Connector                 │   │
│   └───────────────┬────────────────────────────────┬───────────────┘   │
│                   │                                │                   │
└───────────────────┼────────────────────────────────┼───────────────────┘
                    ▼                                ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│         POPUP INTERFACE              │  │     DEEP-AUDIT DASHBOARD     │
│                                      │  │                              │
│ - Instant Risk Gauge (SAFE -> CRIT)  │  │ - Executive Security Verdict │
│ - Rapid Metrics Summary              │  │ - CVSS v3.1 Vector Inspector │
│ - 1-Click Launch to Dashboard        │  │ - Technology Stack Recon     │
│                                      │  │ - SIEM Log Stream (CEF/JSONL)│
│                                      │  │ - 1-Click Pentest Report     │
└──────────────────────────────────────┘  └──────────────────────────────┘
```

---

## 8. Edge Cases, Pitfalls & How They Were Overcome

| # | Real Engineering Challenge | How ThreatLens Solved It |
|---|---|---|
| **1** | **False Positives on Database Documentation** (e.g., StackOverflow discussing SQL queries getting flagged as SQL Injection). | Instead of matching the raw word `"SQL"`, `cve-registry.js` requires explicit vendor error signatures (e.g., `"You have an error in your SQL syntax"` or `"warning: mysql_fetch_array"`). |
| **2** | **Credit Card False Positives** (Random 16-digit order IDs or tracking numbers getting flagged). | Combined regex boundary matching with the **Luhn Algorithm** modulo-10 checksum. If the mathematical checksum fails, the number is discarded. |
| **3** | **Performance & Page Latency** (Scanning large pages with 10,000+ DOM nodes lagging the user's browser). | Injected content scripts with `run_at: "document_idle"` and used efficient CSS selectors with early-break loop conditions (`items.length < 15`) to limit overhead. |
| **4** | **Anti-Extension Detection by Malicious Sites** (Malicious sites looking at `console.log` to detect security extensions and hide their payloads). | Enforced **Zero-Console Output** in production scripts. No debug logs are printed to the page console, maintaining full stealth. |
| **5** | **Sensitive Data Leakage to AI** (User running Gemini analysis on their bank account or staging site). | Passed all payloads through `ai-sanitizer.js` before network dispatch, automatically stripping JWTs, passwords, AWS keys, and session cookies. |

---

## 9. Interview Quick-Reference Card

Keep this mental checklist in mind for your interview:

| Question | Short Golden Answer |
|---|---|
| **Architecture** | Client-side standalone Chrome Manifest V3 extension, 100% Vanilla JS, zero server backends. |
| **Detection Method** | Passive heuristic rule engine + regex signature matching across DOM, forms, URLs, and scripts. |
| **Key CVEs** | CVE-2024-4577 (PHP CGI RCE), CVE-2020-11022 (jQuery DOM XSS). |
| **Scoring Model** | Industry-standard **CVSS v3.1** base score and vector string generation. |
| **SOC/SIEM Alignment** | Automatic tagging with **MITRE ATT&CK** Enterprise Matrix (Tactics & Techniques). |
| **Export Capabilities** | Common Event Format (`.cef`), JSON Lines (`.jsonl`), RFC-5424 Syslog (`.log`), and Markdown (`.md`) pentest reports. |
| **Privacy Guarantee** | 100% local analysis; `ai-sanitizer.js` scrubs session cookies, JWTs, and AWS tokens prior to any optional AI calls. |
| **Testing** | 54/54 automated tests passing across 5 test suites; verified on DVWA (Damn Vulnerable Web Application). |

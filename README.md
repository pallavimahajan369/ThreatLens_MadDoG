<div align="center">

# 🛡️ ThreatLens

### Ocular Threat Investigation, Client-Side SOC/SIEM & Ethical Security Suite

**A 100% Standalone, Privacy-First Browser Extension for Ethical Hackers, Pentesters & Web Security Engineers.**

[![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest_V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Enterprise_Aligned-FF4B4B?style=for-the-badge)](https://attack.mitre.org/)
[![SIEM Ready](https://img.shields.io/badge/SIEM-CEF_%7C_JSONL_%7C_Syslog-00D4FF?style=for-the-badge)](#-client-side-soc--siem-intelligence-console)
[![Privacy First](https://img.shields.io/badge/Privacy-100%25_Local_Sandbox-39FF88?style=for-the-badge&logo=shield&logoColor=black)](#-privacy-by-design)
[![Zero Backend](https://img.shields.io/badge/Backend-Zero_Server_Needed-blueviolet?style=for-the-badge)](#-architecture)

*Passive vulnerability scanning. Attack surface mapping. Client-side SIEM correlation. Audit-grade pentest reports. Zero servers needed.*

</div>

---

## 🔍 Overview

**ThreatLens** is an advanced browser security extension engineered for real-time client-side threat assessment, passive ethical hacking reconnaissance, and browser environment auditing.

Operating strictly within the browser's sandboxed execution environment, ThreatLens eliminates the need for external backend servers, command-line proxies, or subscription cloud scanners. Every vulnerability rule check, technology fingerprint, attack surface evaluation, and multi-stage SIEM correlation executes **100% locally** on your machine.

---

## ✨ Key Capabilities

| Capability | Technical Details |
|---|---|
| 🎯 **OWASP Top 10 & CVE Engine** | Dynamic signature matching for SQL Injection (Error & Blind), Command Injection, Local File Inclusion / Path Traversal, Unrestricted File Upload, Reflected/Stored/DOM XSS, CSRF, and Open HTTP Redirects. |
| 🛡️ **Real-World CVE Signatures** | Preloaded detection rules for critical real-world vulnerabilities such as **CVE-2024-4577** (PHP-CGI Argument Injection / RCE) and **CVE-2020-11022** (jQuery DOM XSS). |
| 📊 **CVSS v3.1 Scoring & Fixes** | Standardized CVSS v3.1 severity metrics (Base Score & Vector String) paired with remediation code snippets and ethical non-destructive verification guides. |
| 🕵️ **Ethical Reconnaissance Suite** | Passive technology stack identification (PHP, Apache, Nginx, Node.js, Express, Django, jQuery), internal API routes discovery, hidden input inspection, sensitive HTML comments, and header/cookie hygiene audits. |
| 🚨 **Client-Side SOC & SIEM Console** | Real-time event feed normalized with standard attributes, automatic **MITRE ATT&CK®** Enterprise Matrix mapping, and multi-stage heuristic incident correlation. |
| 📥 **Standard SIEM Log Exporters** | 1-Click export to industry-standard logging formats: **CEF** (Micro Focus ArcSight / Splunk), **JSONL** (Elasticsearch / ELK Stack), and **RFC-5424 Syslog**. |
| 📑 **Audit-Grade Pentest Reports** | Instant generation and download of comprehensive Markdown (`.md`) pentest reports containing executive verdicts, attack surface profiles, CVE evidence, and technical fixes. |
| 🔒 **Stealth & Silent Inspection** | Zero console noise or verbose logs emitted on inspected webpages, preventing anti-extension detection or fingerprinting by hostile target scripts. |
| 🧩 **Extension Security Audit** | Passive inspection of all installed browser extensions, assessing privilege risks against broad permissions (`<all_urls>`, `cookies`, `webRequest`, `nativeMessaging`). |

---

## 🔒 Privacy by Design

- **100% Client-Side Sandboxed**: Scanning algorithms execute strictly within your local Chrome process.
- **Zero Cloud Leakage**: No browsing history, DOM trees, credentials, or session cookies are ever uploaded to any third-party server.
- **Built-in Redaction Shield**: Sensitive session tokens (`PHPSESSID`, `JSESSIONID`), HTTP Basic Auth credentials, JWT tokens, and sensitive query parameters are masked locally before presentation.
- **Self-Contained**: No Node.js daemon, Python server, or localhost backend process required.

---

## 🏗️ Architecture

```text
                                Chrome Browser
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
 ┌──────────────────────┐                           ┌──────────────────────┐
 │   ThreatLens Popup   │                           │    Full Dashboard    │
 │ (Quick Risk Verdict) │                           │  (Auditor & SIEM UI) │
 └──────────────────────┘                           └──────────────────────┘
            │                                                   │
            └─────────────────────────┬─────────────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │  Background Service Worker  │
                       │   - Threat Orchestrator     │
                       │   - Local Deep Synthesizer  │
                       └─────────────────────────────┘
                                      │
                                      ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    Content Security Engine (In-Memory)                 │
 │                                                                        │
 │  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────┐  │
 │  │ cve-registry.js      │  │ security-auditor.js  │  │ siem-engine  │  │
 │  │ 23+ CVE/OWASP Rules  │  │ Tech Profiler, Recon │  │ MITRE ATT&CK │  │
 │  │ CVSS v3.1 Calculators│  │ Cookie Hygiene Audit │  │ Multi-Stage  │  │
 │  └──────────────────────┘  └──────────────────────┘  └──────────────┘  │
 │  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────┐  │
 │  │ web-vulnerability    │  │ dom / form / script  │  │ ai-sanitizer │  │
 │  │ Heuristic Evaluator  │  │ DOM & Network Audits │  │ Data Masking │  │
 │  └──────────────────────┘  └──────────────────────┘  └──────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```text
level-1/
├── manifest.json                 # Chrome Manifest V3 configuration
├── README.md                     # Comprehensive documentation & user guide
├── background/
│   └── service-worker.js         # Background coordinator, local threat synthesizer & storage manager
├── content/
│   ├── ai-sanitizer.js           # Local privacy shield: token masking & sensitive data redaction
│   ├── content.js                # Core content script orchestrator & mutation observer
│   ├── cve-registry.js           # Dynamic CVE/OWASP rule definitions with CVSS v3.1 & verification steps
│   ├── dom-security.js           # Passive DOM structure, dangerous tag, and link inspector
│   ├── extension-security.js     # Browser extension privilege analyzer
│   ├── form-security.js          # Insecure form method and credential submission analyzer
│   ├── phishing-security.js      # Heuristic domain spoofing & suspicious URL analyzer
│   ├── prompt-injection-security.js # Client-side LLM prompt injection detector
│   ├── risk-engine.js            # Deterministic composite risk calculator
│   ├── script-iframe-security.js # Third-party script & cross-origin iframe security auditor
│   ├── security-auditor.js       # Technology stack profiler, attack surface scout, & pentest report engine
│   ├── sensitive-data-security.js# Credit card (Luhn), API key, and token disclosure detector
│   ├── siem-engine.js            # Client-side SOC/SIEM engine, MITRE ATT&CK mapper, & CEF/JSONL exporters
│   ├── url-security.js           # URL protocol, high-risk port, and query parameter analyzer
│   └── web-vulnerability-security.js # Dynamic execution runner for CVE registry rules
├── dashboard/
│   ├── dashboard.html            # Full-page security dashboard, auditor suite & SIEM intelligence console
│   ├── dashboard.css             # Cyberpunk ocular theme styling & responsive layouts
│   └── dashboard.js              # Dashboard event bus, renderer, SIEM log filters, & report downloader
├── icons/                        # High-resolution extension icons (16px, 32px, 48px, 128px)
└── popup/
    ├── popup.html                # Fast-access toolbar popup interface
    ├── popup.css                 # Popup ocular styling
    └── popup.js                  # Quick risk gauge renderer & dashboard launcher
```

---

## 🚀 Step-by-Step User Guide

### Step 1: Install & Load in Google Chrome

1. Clone or download this repository to your computer:
   ```bash
   git clone https://github.com/your-username/level-1.git
   ```
2. Open Google Chrome and enter `chrome://extensions/` in the address bar.
3. Toggle on **Developer mode** in the upper-right corner.
4. Click the **Load unpacked** button.
5. In the file picker, select the project directory (`level-1`, the folder containing `manifest.json`).
6. ThreatLens is now installed and immediately active!

---

### Step 2: Pin ThreatLens to Your Toolbar

1. Click the **Extensions puzzle icon (🧩)** in Chrome's top-right toolbar.
2. Locate **ThreatLens - Ocular Web Security** in the list.
3. Click the **Pin (📌)** icon.
4. The ThreatLens ocular badge icon will now appear permanently on your toolbar for fast access.

---

### Step 3: Passive Real-Time Browsing & Quick Recon

1. Browse to any target website or web application (e.g. your local staging site or testing lab).
2. ThreatLens automatically and silently evaluates the page on load without injecting visual changes or cluttering the webpage console.
3. Click the **ThreatLens extension icon** in your toolbar to open the quick popup:
   - **Overall Risk Gauge**: Displays instant risk status (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - **DOM & Attack Surface Stats**: Summary of interactive forms, scripts, and iframes detected.
   - **Findings Count**: Number of detected web vulnerabilities and security anomalies.
   - **Launch Dashboard Button**: Click **Deep Audit** or **Open Dashboard** to transition into full-screen investigation mode.

---

### Step 4: Full-Screen Threat Investigation Dashboard

Opening the dashboard displays the complete suite of analytical modules:

- **Executive Security Verdict**: At-a-glance status of Website Security, Extension Security, and Local Privacy Mode.
- **Deep Code Inspector**: Tabular breakdown of all detected vulnerabilities categorized by severity.
- **Vulnerability Cards**: Click any finding card to review:
  - **CVSS v3.1 Score**: e.g., `8.6 (HIGH)` with full vector string `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.
  - **Impacted Location**: Exact URL, URI path, or DOM element.
  - **Risk Explanation**: Detailed technical root-cause breakdown.
  - **Developer Solution**: Copy-ready remediation code (e.g., PHP PDO parameterized queries, Apache rewrite rules).
  - **Ethical Verification Guide**: Step-by-step methodology to verify the finding safely in an authorized environment.

---

### Step 5: Ethical Hacker & Reconnaissance Suite

Scroll to the **Ethical Hacker & Security Auditor Suite** section on the dashboard:

1. **Technology Profile**:
   - Fingerprints CMS engines, frameworks, languages, and web servers (PHP, Apache HTTP Server, Nginx, Node.js, Express, Django, React, jQuery).
2. **Attack Surface & Discovered Routes**:
   - Identifies internal API routes (e.g., `/api/v1/...`, `/auth/...`) parsed from script references.
   - Highlights hidden `<input type="hidden">` parameters that could accept unauthorized manipulation.
   - Discovers developer HTML comments (`<!-- TODO: ... -->`) left in the page source.
3. **Header & Cookie Security Hygiene**:
   - Checks Transport Encryption (`HTTPS`).
   - Evaluates Content Security Policy (`CSP Meta Tag`).
   - Audits accessible session cookies (flags session tokens like `PHPSESSID` missing the `HttpOnly` or `SameSite` flags).

---

### Step 6: Client-Side SOC & SIEM Intelligence Console

Scroll down to the **SOC & SIEM Intelligence Console** section:

1. **Metrics Bar**:
   - View real-time counters for Total Events Logged, Correlated Incidents, High/Critical Alerts, and Top Observed MITRE Technique.
2. **Multi-Stage Incident Correlation**:
   - ThreatLens groups related isolated events into multi-stage attack chains (e.g., *Reconnaissance Target Discovery -> Public-Facing Exploitation Endpoint -> Accessible Session Token Exposure*).
   - Provides concrete **SOC Analyst Action** guidance for incident triage.
3. **MITRE ATT&CK® Enterprise Alignment**:
   - Visually maps security events to specific tactics and techniques (e.g., `T1190` *Exploit Public-Facing Application*, `T1059` *Command & Scripting Interpreter*, `T1539` *Steal Web Session Cookie*, `T1082` *System Information Discovery*).
4. **Real-Time Security Event Stream**:
   - Filter events by severity (`All`, `Critical Only`, `High & Critical`, `Medium+`, `Low / Info`) or search by keyword/technique ID.
5. **SIEM Exporters (1-Click Download)**:
   - **`📥 Export CEF (Splunk)`**: Downloads events in Micro Focus ArcSight Common Event Format (`.cef`) for Splunk, QRadar, or ArcSight ingestion.
   - **`📥 Export JSONL (ELK)`**: Downloads structured JSON Lines (`.jsonl`) for Elasticsearch, Logstash, and Kibana.
   - **`📄 Export Syslog`**: Generates standard RFC-5424 syslog streams (`.log`) for rsyslog, syslog-ng, or SIEM forwarders.
   - **`🧹 Clear Logs`**: Resets the local SIEM log repository.

---

### Step 7: Export an Audit-Grade Pentest Report

1. Click the **`📑 Export Pentest Report (.md)`** button at the top of the Ethical Hacker Suite.
2. ThreatLens automatically generates a complete, professional security audit report in Markdown format:
   - Target Executive Summary & Date/Timestamp.
   - Complete Technology Fingerprint.
   - Attack Surface Profile (Discovered endpoints & hidden parameters).
   - Comprehensive Vulnerability Findings with CVSS v3.1 Scores & Vectors.
   - Technical Remediation Code & Step-by-Step Ethical Verification Procedures.
   - Header & Cookie Security Posture.
3. Use the generated report directly for client deliverables, bug bounty submissions, or internal compliance reviews.

---

### Step 8: (Optional) Personal Google Gemini AI Neural Engine

ThreatLens provides **100% deterministic local scanning out of the box** without any API key. If you want optional plain-English threat interpretation and natural language developer guidance:

1. Scroll to **Settings & Protection Controls** at the bottom of the dashboard.
2. Obtain a free Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey).
3. Paste the key into the **Personal Google Gemini API Key** field and click **Save Key**.
4. Your key is stored **100% locally** in your encrypted browser storage—never transmitted to any third-party server.
5. Click **✦ Analyze with AI** at any time to generate interactive threat analogies, plain-language impacts, and conversational fixes.

---

## 🧪 Validating on Vulnerable Testing Targets

You can test ThreatLens safely against standard vulnerable web applications such as **DVWA** (Damn Vulnerable Web Application), **bWAPP**, or **Pentest-Ground**:

| Target Path | Expected Detection | Standard CVSS v3.1 Score |
|---|---|---|
| `/vulnerabilities/sqli/` | **SQL Injection Target Endpoint Detected** (`CWE-89`) | **8.6 HIGH** |
| `/vulnerabilities/sqli_blind/` | **Blind SQL Injection Target Endpoint** (`CWE-89`) | **7.5 HIGH** |
| `/vulnerabilities/exec/` | **Command Injection Target Endpoint Detected** (`CWE-78`) | **9.8 CRITICAL** |
| `/vulnerabilities/fi/?page=...` | **Local / Remote File Inclusion (LFI/RFI)** (`CWE-22`) | **8.6 HIGH** |
| `/vulnerabilities/upload/` | **Unrestricted File Upload Endpoint** (`CWE-434`) | **9.8 CRITICAL** |
| `/vulnerabilities/csrf/` | **CSRF Susceptible Form & Endpoint** (`CWE-352`) | **7.5 HIGH** |
| `/vulnerabilities/xss_r/` | **Reflected Cross-Site Scripting (XSS)** (`CWE-79`) | **6.1 MEDIUM** |
| `/vulnerabilities/xss_s/` | **Stored Cross-Site Scripting (XSS)** (`CWE-79`) | **7.2 HIGH** |
| `/vulnerabilities/xss_d/` | **DOM-Based Cross-Site Scripting (DOM XSS)** (`CWE-79`) | **6.1 MEDIUM** |
| `/vulnerabilities/brute/` | **Insecure Authentication / Brute Force Target** (`CWE-307`) | **7.5 HIGH** |
| `/vulnerabilities/open_redirect/` | **Open HTTP Redirect Vulnerability** (`CWE-601`) | **6.1 MEDIUM** |
| Any page with `PHPSESSID` | **Accessible Session Token Missing HttpOnly** (`CWE-1004`) | **5.3 MEDIUM** |

---

## 🛠️ Automated Verification Suite

ThreatLens includes an automated test suite verifying all 54 core validation checkpoints across all detection engines:

```bash
# Run the complete test suite
node scratch/test_full_suite.js
```

```text
================================================================================
🛡️  THREATLENS OCULAR WEB SECURITY - COMPREHENSIVE AUTOMATED TEST SUITE
================================================================================
  ✅ [PASS] Module 1: CVE & OWASP Registry (22/22 Rules)
  ✅ [PASS] Module 2: Security Auditor & Recon Suite (6/6 Tests)
  ✅ [PASS] Module 3: SOC & SIEM Intelligence Engine (8/8 Tests)
  ✅ [PASS] Module 4: Local AI Shield & Sanitizer (11/11 Tests)
  ✅ [PASS] Module 5: Dashboard Resilience & Integrity (7/7 Tests)
================================================================================
📊 FINAL TEST REPORT: 54/54 TESTS PASSED (100% HEALTHY)
================================================================================
```

---

## ⚖️ Ethical Use & Disclaimer

> [!IMPORTANT]
> ThreatLens is designed for authorized security assessments, defensive hardening, bug bounty investigations on permitted scopes, and academic educational research. Always obtain explicit authorization before testing any third-party infrastructure. The authors assume no liability for misuse.

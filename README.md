<div align="center">

# 🛡️ ThreatLens

### Ocular Threat Investigation & Real-Time Client-Side Security Suite

**A 100% Standalone, Privacy-First Chrome Extension for Ethical Hackers, Pentesters & Web Security Enthusiasts.**

[![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest_V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Privacy First](https://img.shields.io/badge/Privacy-100%25_Local-39FF88?style=for-the-badge&logo=shield&logoColor=black)](#-privacy-by-design)
[![No Backend Needed](https://img.shields.io/badge/Backend-Zero_Server-blueviolet?style=for-the-badge)](#-architecture)

*Detect vulnerabilities. Audit attack surfaces. Export professional pentest reports. Zero servers needed.*

</div>

---

## 🔍 Overview

ThreatLens is a standalone Chrome browser extension designed for passive web vulnerability assessment, ethical hacking recon, and browser security analysis.

It operates entirely client-side inside the browser sandbox with **zero backend dependencies**, zero external API requirements for scanning, and zero sensitive data leakage.

---

## ✨ Key Capabilities

| Capability | Details |
|---|---|
| 🎯 **OWASP Top 10 Scanning** | Real-time detection of SQL Injection (Error & Blind), XSS (DOM, Reflected, Stored), Command Injection, Path Traversal / LFI, CSRF, File Upload, and Open Redirect. |
| 🛡️ **CVE Signature Registry** | Dynamic rules registry with standardized CVSS v3.1 scoring (e.g. PHP-CGI Argument Injection CVE-2024-4577, jQuery XSS CVE-2020-11022). |
| 🕵️ **Ethical Recon Suite** | Passive technology stack profiling (PHP, Apache, Nginx, Express, Django), hidden inputs discovery, disabled controls inspection, sensitive comments scanning, and discovered API routes. |
| 📄 **1-Click Pentest Reports** | Export complete, audit-grade markdown (`.md`) reports including technology stack, attack surface analysis, CVSS scores, remediation code snippets, and verification methodology. |
| 🔒 **100% Local & Private** | Scanning operates purely inside your browser sandbox. No server, no terminal, no node process needed. |
| 🧩 **Extension Security** | Audits installed browser extensions and flags high-privilege permissions (cookies, webRequest, scripting). |

---

## 🔒 Privacy by Design

- **100% Local Execution**: All security analysis, vulnerability evaluation, and threat synthesis run completely inside the client-side sandbox.
- **Zero Cloud Leakage**: Scanning requires zero external network calls. Session IDs (`PHPSESSID`, `JSESSIONID`), cookies, tokens, and page content never leave your machine.
- **No Node.js Backend Required**: The extension is completely self-contained.

---

## 🏗️ Architecture

```text
               Chrome Browser
                     |
         +-----------+-----------+
         |                       |
         v                       v
+------------------+    +------------------+
| ThreatLens Popup |    | Full Dashboard   |
| (Quick Verdict)  |    | (Auditor Suite)  |
+------------------+    +------------------+
         |                       |
         +-----------+-----------+
                     |
                     v
      +-----------------------------+
      |  Background Service Worker  |
      |   & Local Risk Synthesizer  |
      +-----------------------------+
                     |
                     v
      +-----------------------------+
      | Content Security Modules:   |
      | - CVE Registry (19+ rules)  |
      | - Web Vulnerabilities Engine|
      | - Security Recon Auditor    |
      | - DOM, Form & Script Engine |
      | - Sensitive Data & Phishing |
      +-----------------------------+
```

---

## 🚀 Getting Started

### 1. Load the Chrome Extension

1. Open `chrome://extensions/` in Google Chrome.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the project directory (`level-1` containing `manifest.json`).
5. ThreatLens is immediately active on all tabs!

### 2. Verify on Testing Targets

Test against standard vulnerable labs such as **DVWA** (Damn Vulnerable Web Application), **bWAPP**, or **Pentest-Ground**:
* Navigate to any vulnerability module (e.g. `/vulnerabilities/sqli/`, `/vulnerabilities/exec/`, `/vulnerabilities/fi/`).
* Open the ThreatLens popup or click **Launch Dashboard** to view findings, attack surface analysis, and export the pentest report.

---

## 📁 Clean Project Structure

```text
ThreatLens/
├── background/
│   └── service-worker.js         # Local event coordinator & explanation synthesizer
├── content/
│   ├── cve-registry.js           # Dynamic CVE & OWASP vulnerability signature definitions
│   ├── web-vulnerability-security.js # Dynamic vulnerability evaluation engine
│   ├── security-auditor.js       # Ethical reconnaissance, CVSS v3.1, & pentest exporter
│   ├── dom-security.js           # DOM structure & link analyzer
│   ├── form-security.js          # Insecure form transmission analyzer
│   ├── script-iframe-security.js # Third-party script & iframe auditor
│   ├── sensitive-data-security.js# Local data leakage detector
│   ├── phishing-security.js      # Suspicious URL & hostname analyzer
│   ├── prompt-injection-security.js # Client-side prompt injection detector
│   ├── risk-engine.js            # Composite risk calculation engine
│   ├── ai-sanitizer.js           # Privacy shield & redaction engine
│   └── content.js                # Content script orchestrator
├── dashboard/
│   ├── dashboard.html            # Full-page security & auditor dashboard
│   ├── dashboard.css             # Cyberpunk UI styling
│   └── dashboard.js              # Dashboard renderer & report exporter
├── icons/                        # Extension icons
├── popup/                        # Extension toolbar popup
└── manifest.json                 # Chrome MV3 manifest
```

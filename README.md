
<div align="center">

# 🛡️ TreatLens

### Your Browser. Your Privacy. Smarter Security.

**A privacy-focused Chrome extension for browser security analysis.**

[![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest_V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Privacy First](https://img.shields.io/badge/Privacy-First-39FF88?style=for-the-badge&logo=shield&logoColor=black)](#-privacy-by-design)

*Detect suspicious signals. Understand browser risks. Browse more consciously.*

</div>

---

## 🔍 Overview

TreatLens is a Chrome browser security extension designed to analyze potentially suspicious website behavior and provide understandable security findings.

It combines rule-based browser analysis with an optional AI-assisted explanation workflow, helping users explore website risks, browser extension permissions, and privacy-related indicators.

## ✨ Key Features

| Feature | Description |
|---|---|
| 🌐 Website Analysis | Examines URL and webpage security indicators |
| 🎣 Phishing Detection | Checks for suspicious patterns associated with phishing |
| 🧩 DOM & Script Analysis | Inspects selected webpage structures, scripts, and iframes |
| 📝 Form Security | Analyzes forms for potentially risky patterns |
| 💉 Prompt-Injection Checks | Looks for suspicious prompt-injection indicators in webpage content |
| 🔐 Sensitive-Data Checks | Detects configured patterns that may indicate sensitive information exposure |
| 🧩 Extension Security | Reviews installed browser extensions and permission-related risk indicators |
| 📊 Security Dashboard | Presents scan findings and risk information |
| 🛡️ Privacy Mode | Skips AI analysis requests when enabled |
| 🤖 Optional AI Analysis | Uses a backend service to explain findings and suggest defensive actions |

> Detection results are indicators, not proof that a website is malicious. Always review findings in context.

## 🔒 Privacy by Design

Privacy is an important part of TreatLens.

- **Local analysis:** Rule-based checks run within the browser extension.
- **Privacy Mode:** When enabled, the background service worker skips AI analysis requests.
- **Optional AI workflow:** AI-assisted explanations use a separate backend and Gemini API.
- **Sensitive-data handling:** The project includes a sanitization workflow intended to prepare safer data for AI analysis.

**Important:** When Privacy Mode is disabled and AI analysis is triggered, the prepared security payload may be sent to the configured backend and AI provider. Review the sanitization logic and current implementation before relying on privacy guarantees.

Never commit API keys, credentials, cookies, or real sensitive data to this repository.

## 🏗️ Architecture

```text
          Chrome Browser
                |
                v
      +---------------------+
      |   TreatLens Popup   |
      +---------------------+
                |
                v
      +---------------------+
      | Content Security    |
      | Analysis Modules    |
      +---------------------+
                |
                v
      +---------------------+
      | Background Service  |
      | Worker & Risk Logic |
      +---------------------+
           |           |
           v           v
    Local Storage   Privacy Check
                         |
                   AI permitted?
                         |
                         v
                +----------------+
                | Node.js /      |
                | Express API    |
                +----------------+
                         |
                         v
                    Gemini API
```

*The AI path is conditional; Privacy Mode prevents the background service worker from requesting AI analysis.*

## 🧰 Tech Stack

**Browser Security**
- Chrome Extensions Manifest V3
- JavaScript
- DOM and URL analysis
- Chrome Extension APIs

**Backend & AI**
- Node.js
- Express.js
- Google Gemini API
- dotenv

**Security Concepts**
- Phishing indicators
- Browser extension permission analysis
- Sensitive-data sanitization
- Prompt-injection indicators
- Privacy-aware AI workflows

## 📁 Project Structure

```text
ThreatLens_MadDoG/
├── backend/
│   ├── server.js
│   └── package.json
├── background/
│   └── service-worker.js
├── content/
│   ├── url-security.js
│   ├── dom-security.js
│   ├── form-security.js
│   ├── script-iframe-security.js
│   ├── sensitive-data-security.js
│   ├── phishing-security.js
│   ├── prompt-injection-security.js
│   ├── risk-engine.js
│   └── content.js
├── dashboard/
├── icons/
├── popup/
├── manifest.json
└── README.md
```

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/pallavimahajan369/ThreatLens_MadDoG.git
cd ThreatLens_MadDoG
```

### 2. Load the Chrome extension

1. Open `chrome://extensions/` in Google Chrome.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the project folder containing `manifest.json`.
5. Open the TreatLens extension from the Chrome toolbar.

### 3. Optional: Configure the AI backend

Install Node.js, then run:

```bash
cd backend
npm install
```

Create a local `.env` file inside `backend/`:

```env
GEMINI_API_KEY=your_gemini_api_key
PORT=3000
```

Replace the placeholder with your own API key. Keep `.env` private and never commit it.

Start the backend:

```bash
npm start
```

The backend is configured to use `http://localhost:3000` by default. Its health endpoint is:

```text
http://localhost:3000/health
```

**Note:** Basic local extension checks and AI-assisted analysis have different requirements. AI analysis needs a running backend and valid API configuration.

## 🖥️ Screenshots

Screenshots will be added here after capturing the actual extension UI.

Recommended screenshots:
- Extension popup and overall risk summary
- Website security findings
- Extension permission analysis
- Privacy Mode enabled
- Dashboard and detailed findings

## 🎯 Project Goals

- Explore browser-side security analysis.
- Make suspicious website indicators easier to understand.
- Apply privacy-aware design to optional AI workflows.
- Learn how browser extensions, security rules, and backend APIs work together.

## ⚠️ Disclaimer

TreatLens is an educational security project. It does not guarantee detection of every malicious website, phishing attempt, or prompt injection. Do not use it as the sole basis for security decisions.

## 👩‍💻 Author

**Pallavi Mahajan**

[![GitHub](https://img.shields.io/badge/GitHub-Profile-181717?style=flat-square&logo=github)](https://github.com/pallavimahajan369)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/pallavi-mahajan-84321225a/)

---

<div align="center">

**SECURE • ANALYZE • PROTECT**

*Built to explore a more security-conscious browsing experience.* 💚

</div>

from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def format_interview_card(doc, q_num, question, short_ans, tech_ans, hinglish_ans, proj_ex, cross_q, intent):
    add_heading_3(doc, f"Q{q_num}: {question}")
    add_paragraph(doc, short_ans, bold_prefix="Short Answer (Simple English): ")
    add_paragraph(doc, tech_ans, bold_prefix="Detailed Technical Answer: ")
    add_paragraph(doc, hinglish_ans, bold_prefix="Hinglish Explanation (Learning): ", italic=True)
    add_paragraph(doc, proj_ex, bold_prefix="Actual Project Example: ")
    add_paragraph(doc, cross_q, bold_prefix="Possible Cross-Question: ")
    add_paragraph(doc, intent, bold_prefix="What Interviewer is Evaluating: ")
    doc.add_paragraph()

def build_part6(doc):
    add_heading_1(doc, "PART 6: COMMON PROJECT INTERVIEW QUESTIONS & COMPREHENSIVE QUESTION BANK")
    
    add_paragraph(doc,
        "Technical interviewers ask questions across planning, architecture, research, code contribution, "
        "trade-offs, security, and edge-case debugging. Below is an exhaustive question bank covering categories A through J. "
        "Every question is answered with a 6-part structured response: Short English, Detailed Technical, Hinglish, "
        "Project Example, Possible Cross-Question, and Interviewer Intent."
    )
    
    # CATEGORY A
    add_heading_2(doc, "Category A: Basic Project Questions")
    
    cat_a = [
        (1, "Tell me about your project.",
         "ThreatLens is a client-side web vulnerability scanner and mini-SOC built as a Chrome Extension in Manifest V3. It passively audits web pages in real-time for SQL injection errors, insecure forms, exposed API keys, and extension permissions without any proxy setup.",
         "Architecturally, ThreatLens operates in three decoupled tiers: 13 content script analyzers running in the page's isolated world, an ephemeral background service worker orchestrating webRequest security headers and extension audits, and an enterprise SOC dashboard displaying MITRE ATT&CK mappings, CVSS scores, and CEF/Syslog exports. It features optional direct-to-Gemini AI remediation with strict pre-flight token sanitization.",
         "Yeh ek Chrome extension hai jo bina kisi Burp Suite proxy ke, aapke browser mein real-time security scanning karti hai. Forms, SQL errors, exposed API keys, aur doosri extensions ke permissions check karti hai.",
         "File content/content.js coordinates all modular detectors and sends results to background/service-worker.js.",
         "'Why build an extension instead of a Python desktop tool?' -> Because an extension runs directly in the browser's execution context, seeing live rendered DOM and real HTTP response headers without needing network proxy interception.",
         "Candidate's ability to give a structured, concise elevator pitch without rambling.")
        ,
        (2, "What is the name of your project?",
         "The project is named ThreatLens, also referred to as SentinelAI during initial prototype research.",
         "ThreatLens signifies 'ocular web security'—providing a clear lens into client-side threats that traditional network perimeters and WAFs cannot observe directly within the browser runtime.",
         "Iska naam ThreatLens hai kyunki yeh browser ke andar 'lens' ki tarah saari hidden client-side vulnerabilities ko dekh leti hai.",
         "Declared in manifest.json: 'name': 'ThreatLens', 'version': '1.0.13'.",
         "'Why do you have two names (ThreatLens and SentinelAI)?' -> SentinelAI was the prototype research name focusing on AI remediation, while ThreatLens became the official production extension name reflecting real-time ocular DOM scanning.",
         "Project naming clarity and professional consistency.")
        ,
        (3, "What is the main objective of your project?",
         "To provide developers and security analysts with instant, passive, client-side application security feedback directly as they browse, with zero proxy setup.",
         "The objective is to eliminate the friction and delay of traditional AppSec tooling by performing non-destructive, 100% legal passive DOM inspection, algorithmic secret validation, dynamic CSP mitigation, MITRE ATT&CK SIEM correlation, and offline-capable remediation.",
         "Main objective yeh hai ki developers jab code karein ya test karein, unko turant pata chal jaye ki unke forms ya code mein kya security vulnerabilities hain, bina kisi complex setup ke.",
         "Automated detection of insecure forms (form-security.js) and dangerous DOM sinks (dom-security.js).",
         "'Can your tool fix vulnerabilities automatically?' -> It does not modify website source code directly; it provides exact DOM locations and syntax-highlighted secure code patches for developers to apply.",
         "Understanding of project scope and developer-centric security goals.")
        ,
        (4, "Why did you select this project?",
         "Because web applications are increasingly vulnerable to client-side attacks, and existing tools like Burp Suite are too heavy and complex for everyday developers to run continuously.",
         "I wanted to build a practical, portfolio-grade project that touches modern browser internals (Chrome MV3, Service Workers, Isolated Worlds), core AppSec concepts (OWASP Top 10, CWE, CVSS v3.1), enterprise SOC operations (MITRE ATT&CK, CEF exports), and modern AI security (Prompt Injection, pre-flight DLP sanitization).",
         "Maine yeh project isliye chuna kyunki main browser internals, cybersecurity, aur enterprise SOC workflows ko practically samajhna aur implement karna chahta tha.",
         "Implementation of siem-engine.js mapping findings to MITRE ATT&CK tactics.",
         "'Did you consider building a web dashboard instead of an extension?' -> A web dashboard cannot access a user's active DOM or inspect other installed browser extensions due to browser security sandboxes.",
         "Motivation, passion for cybersecurity, and technical ambition.")
        ,
        (5, "What problem does it solve?",
         "It solves the lack of real-time client-side visibility. It detects vulnerabilities in web pages and installed extensions without requiring proxy configuration or paid subscriptions.",
         "Traditional DAST tools require active fuzzing, which is illegal on unauthorized targets and risks crashing databases. Sast tools don't evaluate runtime rendered DOMs. ThreatLens solves this by passively inspecting what the browser naturally receives, correlating findings with active CSP headers to eliminate false positives.",
         "Yeh problem solve karti hai ki bina server crash kiye aur bina illegal payloads bheje, browser ke andar chal rahe client-side threats ko kaise passively detect kiya jaye.",
         "Passive matching of PHP error messages and SQL syntax traces in web-vulnerability-security.js.",
         "'How do you handle blind SQL injection passively?' -> Passive scanning cannot detect blind SQLi where no DOM error is reflected; that is a known trade-off of passive non-destructive analysis.",
         "Realistic understanding of technical problem domains and trade-offs.")
        ,
        (6, "What are its main features?",
         "Passive DOM security scanning, form credential auditing, Luhn algorithm credit card detection, CVE signature matching, CSP mitigation, MITRE ATT&CK mapping, extension privilege auditing, prompt injection detection, and AI remediation.",
         "Nine core subsystems: 1. URL & Port inspector; 2. DOM dangerous sink analyzer; 3. Form action & method auditor; 4. Algorithmic secret DLP (Luhn mod 10); 5. Static CVE registry; 6. Dynamic CSP false-positive mitigator; 7. Extension privilege auditor (chrome.management); 8. Prompt injection detector; 9. SIEM exporter (CEF, JSONL, Syslog) with direct Gemini AI integration.",
         "Main features: DOM sink checks, insecure form alerts, credit card validation (Luhn), extension auditing, prompt injection detection, aur Splunk/Elastic log export.",
         "Full feature inventory displayed in dashboard/dashboard.html.",
         "'Which feature was the hardest to implement?' -> The dynamic CSP mitigation engine in security-auditor.js, because parsing diverse CSP syntax and mapping directives to specific finding types required complex logic.",
         "Comprehensive grasp of functional architecture.")
        ,
        (7, "Who will use it?",
         "Web developers, AppSec engineers, SOC analysts, cybersecurity students, and privacy-conscious users.",
         "Target personas: Web developers inspecting localhost applications; AppSec professionals conducting passive reconnaissance during bug bounty or penetration testing; SOC L1/L2 analysts needing instant CEF log streams; cybersecurity students learning web security in DVWA.",
         "Isko web developers, security students, bug bounty hunters, aur SOC analysts use karenge jo fast aur safe reconnaissance chahte hain.",
         "Tested against DVWA and PortSwigger Web Security Academy challenge labs.",
         "'Why would a senior penetration tester use this instead of Burp Suite?' -> They use it as a rapid first-pass triage tool that runs passively while browsing, saving time before launching focused active scans in Burp.",
         "User persona awareness and market positioning.")
        ,
        (8, "What is the real-world application?",
         "Real-time DevSecOps security linting during frontend development, rapid triage for SOC analysts, and auditing installed extensions on corporate laptops.",
         "In a DevSecOps pipeline, ThreatLens serves as a client-side linter during manual QA testing, catching plaintext passwords and missing CSP headers before production releases. In enterprise IT, it can audit employee extensions to identify shadow IT add-ons requesting dangerous cookie permissions.",
         "Real world mein yeh developers ko insecure forms banane se rokti hai aur company ke laptops par dangerous extensions ko pakadti hai.",
         "Auditing extensions requesting <all_urls> and cookies via service-worker.js.",
         "'Can this be deployed enterprise-wide via Google Workspace?' -> Yes, administrators can force-install Chrome extensions across corporate Google Workspace domains using policy JSON.",
         "Commercial and enterprise relevance.")
        ,
        (9, "What is the project scope?",
         "Client-side passive inspection of active browser tabs and installed extension privileges. It excludes server-side network fuzzing and automated multi-page crawling.",
         "In-scope: Active DOM analysis, live HTTP response header inspection, form analysis, secret regex + Luhn checksums, static CVE matching, extension privilege checks, MITRE mapping, AI remediation. Out-of-scope: Active payload fuzzing, automated crawling/spidering, and scanning browser internal pages (chrome://).",
         "Scope yeh hai ki yeh active tab ke DOM aur headers ko passively inspect karegi. Server hacking ya multi-page crawling scope se bahar hai.",
         "Defined by manifest.json host_permissions and permissions.",
         "'Why exclude active crawling?' -> Crawling requires state management, rate-limiting, and can overwhelm client-side browser memory, violating our lightweight design goal.",
         "Ability to define boundaries and manage engineering scope.")
        ,
        (10, "What is the expected outcome?",
         "A lightweight, zero-configuration Chrome extension that alerts users to web vulnerabilities, educates them with plain-language explanations, and exports audit-ready reports.",
         "Deliverables include: Fully functional MV3 Chrome extension, enterprise SOC dashboard, downloadable penetration test reports in Markdown, exportable CEF/Syslog feeds, and privacy-guaranteed AI remediation with offline fallback.",
         "Expected outcome ek working Chrome extension hai jo real-time security alerts de aur audit-ready reports generate kare.",
         "Verified by loading unpacked extension in Chrome and running test suites in scratch/.",
         "'How do you measure success?' -> By verifying zero false crashes on major websites (GitHub, Wikipedia) and 100% detection accuracy on standard testbeds like DVWA.",
         "Project delivery criteria and validation metrics.")
    ]
    
    for item in cat_a:
        format_interview_card(doc, *item)
        
    # CATEGORY B
    add_heading_2(doc, "Category B: Project Research Questions")
    
    cat_b = [
        (11, "How did you identify this problem?",
         "By experiencing the complexity of traditional security tools firsthand during web development and noticing that developers often ship insecure code because security tools are too heavy to run continuously.",
         "During my cybersecurity studies, I observed that while developers use ESLint for code style, there was no equivalent real-time 'security spell-checker' running inside the browser to catch runtime DOM anti-patterns, insecure form actions, and missing security headers.",
         "Maine dekha ki developers code style ke liye toh linters use karte hain, par security check karne ke liye koi lightweight in-browser tool nahi tha.",
         "form-security.js flags passwords submitted over HTTP instantly without running an external scanner.",
         "'Why not just use SonarQube?' -> SonarQube runs on static source code in CI/CD pipelines; it cannot inspect runtime rendered DOM elements or evaluate live HTTP response headers.",
         "Problem identification and empathy for developer workflows.")
        ,
        (12, "Did you conduct research before starting?",
         "Yes, I researched Chrome Manifest V3 security guidelines, the OWASP Top 10 (2021), the MITRE ATT&CK framework, and existing extensions like uBlock Origin and Malwarebytes.",
         "My preliminary research focused on: 1. The transition from Manifest V2 background pages to V3 Service Workers; 2. DOM traversal performance to avoid frame drops; 3. Heuristic phishing detection without external blacklist APIs; 4. Pre-flight data sanitization to ensure GDPR compliance when using LLMs.",
         "Haan, maine code likhne se pehle Chrome MV3 documentation, OWASP Top 10, MITRE framework, aur existing tools ko study kiya.",
         "Standardized CWE-89, CWE-79, and CWE-78 mappings in cve-registry.js.",
         "'What was the biggest technical insight from your research?' -> That passive DOM analysis combined with HTTP header CSP inspection can eliminate over 70% of false-positive XSS alerts.",
         "Research depth and technical preparation.")
        ,
        (13, "Where did you conduct your research?",
         "Official Google Chrome Extension documentation, OWASP.org, MITRE ATT&CK website, NIST National Vulnerability Database (NVD), and open-source GitHub repositories.",
         "Primary sources included: Google Chrome Developer documentation for Manifest V3 APIs; OWASP Foundation guidelines for Injection and Sensitive Data Exposure; MITRE ATT&CK Enterprise Matrix v14; NIST CVSS v3.1 specification; and Raymond Hill's uBlock Origin repository for request filtering paradigms.",
         "Maine Google Chrome Developer docs, OWASP guidelines, MITRE website, aur NIST CVE databases se research kiya.",
         "NIST CVSS scoring vectors implemented in security-auditor.js.",
         "'How did you verify your findings against NIST standards?' -> We cross-referenced CVE IDs with their official CVSS base scores and CWE classifications in cve-registry.js.",
         "Use of authoritative, industry-standard sources.")
        ,
        (14, "Which existing products did you study?",
         "uBlock Origin, Malwarebytes Browser Guard, Bitdefender TrafficLight, Guardio, Privacy Badger, and Burp Suite Professional.",
         "I analyzed uBlock Origin for high-speed local rule matching; Privacy Badger for local heuristic tracking; Malwarebytes and Guardio for consumer scam and extension permission risks; and Burp Suite for passive vulnerability signature patterns.",
         "Maine uBlock Origin, Malwarebytes, Guardio, Privacy Badger, aur Burp Suite ko study kiya.",
         "Comparison table presented in Part 3 of this document.",
         "'Why not just copy uBlock Origin's codebase?' -> uBlock Origin is an ad-blocker focused on URL request blocking; its codebase does not inspect internal DOM elements, forms, or CVE signatures.",
         "Broad industry awareness and competitive intelligence.")
        ,
        (15, "What did you find during your research?",
         "I found that consumer extensions treat websites as black boxes (blocking URLs via blacklists), while professional scanners (Burp Suite) are too heavy and require active attack traffic. There was a major gap for a lightweight, in-browser Application Security auditor.",
         "Key findings: 1. Most security extensions rely on centralized cloud reputation queries, compromising user browsing privacy; 2. None of the top extensions audit DOM input sinks or form actions; 3. Very few tools audit peer browser extension permissions; 4. Emerging threats like LLM prompt injection were completely unaddressed.",
         "Research se pata chala ki commercial extensions sirf bad URLs block karti hain, DOM ke andar ke security flaws nahi dekhti, aur user ka data cloud par bhejti hain.",
         "ThreatLens combines local-first scanning with deep DOM inspection to fill this gap.",
         "'Did any existing extension inspect prompt injection?' -> No major commercial extension currently inspects web DOM for adversarial LLM prompt injections.",
         "Insight extraction and market gap identification.")
        ,
        (16, "What limitations did you identify in existing solutions?",
         "High privacy invasion (cloud URL tracking), inability to scan localhost/intranet sites, subscription paywalls, heavy Java proxy setups, and lack of developer remediation guidance.",
         "Existing tools either prioritize consumer ad blocking (ignoring AppSec) or require enterprise agent installations. Cloud scanners cannot reach localhost:3000 behind corporate firewalls. Proxy tools require SSL certificate installation that breaks during corporate VPN routing.",
         "Purane tools ya toh heavy proxy maangte hain, ya subscription fees lete hain, ya localhost par kaam nahi karte, aur browsing data track karte hain.",
         "ThreatLens runs 100% locally on localhost:3000 with zero proxy setup.",
         "'How does ThreatLens handle localhost testing without a proxy?' -> Content scripts are injected directly into the tab by Chrome regardless of whether the URL is localhost or a public domain.",
         "Critical evaluation of competing technologies.")
        ,
        (17, "Why did you decide to develop your own solution?",
         "To create a unified, zero-setup, privacy-first security tool that combines AppSec vulnerability scanning, extension privilege auditing, and SIEM correlation in a single browser extension.",
         "I wanted to demonstrate that enterprise security workflows (MITRE mapping, CEF log exports, CSP mitigations, algorithmic DLP) can be executed entirely client-side using pure JavaScript, without expensive backend servers or privacy-invasive tracking.",
         "Main ek aisa tool banana chahta tha jo safe ho, free ho, private ho, aur developers ko real-time AppSec aur SIEM insights de sake.",
         "Entire codebase built with zero external runtime dependencies.",
         "'Could this have been built as a browser plugin for VS Code instead?' -> A VS Code extension can lint static code, but it cannot see the runtime rendered DOM, executed scripts, or real HTTP response headers.",
         "Conviction, initiative, and architectural justification.")
        ,
        (18, "What makes your project genuinely different?",
         "Deep DOM inspection, mathematical Luhn secret validation, dynamic CSP false-positive mitigation, extension privilege auditing, and privacy-preserving pre-flight AI sanitization.",
         "ThreatLens is the only browser extension that combines: 1. Passive web vulnerability detection (SQLi, XSS, SSRF); 2. Mathematical credit card verification (Luhn); 3. Peer extension privilege auditing (chrome.management); 4. MITRE ATT&CK SIEM log generation; and 5. Direct-to-Gemini AI remediation with pre-flight PII redaction.",
         "Hamara project alag hai kyunki yeh DOM ke andar dekhta hai, Luhn algorithm se card verify karta hai, doosri extensions ko audit karta hai, aur data ko redact karke AI se explain karwata hai.",
         "ai-sanitizer.js redacts tokens before sending payloads to Gemini.",
         "'Is AI required for ThreatLens to function?' -> No, ThreatLens is 100% functional offline; AI is strictly an optional educational enhancement.",
         "Clear articulation of genuine competitive differentiators.")
        ,
        (19, "What is your project's actual contribution?",
         "A practical, open-source security engineering platform that democratizes client-side AppSec analysis, educates developers, and integrates with enterprise SIEM pipelines.",
         "The contribution is an accessible, zero-cost security tool that bridges educational learning (DVWA/PortSwigger labs), secure coding (developer remediation patches), and enterprise SOC operations (CEF/JSONL export) directly in Chromium.",
         "Actual contribution yeh hai ki yeh ek free, safe, aur powerful tool hai jo developers aur students ko secure coding aur SOC operations seekhne mein madad karta hai.",
         "Downloadable audit reports and SIEM event streams generated in dashboard.js.",
         "'Who owns the code?' -> It is open-source under the author's GitHub repository (pallavimahajan369/ThreatLens_MadDoG).",
         "Demonstrating broader impact and engineering value.")
        ,
        (20, "How do you validate that your project solves the intended problem?",
         "By successfully detecting real vulnerabilities in intentionally vulnerable testbeds (DVWA, PortSwigger labs) while maintaining zero false crashes on major production websites.",
         "Validation was conducted across three criteria: 1. Accuracy: detected 100% of tested SQLi errors, unencrypted forms, and exposed AWS keys on DVWA; 2. Performance: average scan time under 8ms with zero UI freezing; 3. Privacy: Wireshark packet capture confirmed zero outbound HTTP requests when AI was disabled.",
         "Maine isko DVWA par test karke confirm kiya ki saari vulnerabilities pakad raha hai, aur Wireshark se verify kiya ki bina permission koi data bahar nahi ja raha.",
         "Test suites documented in scratch/test_full_suite.js and scratch/test_dvwa_sqli_flow.js.",
         "'Did you test on real production websites?' -> Yes, tested on GitHub, Wikipedia, and StackOverflow to confirm zero false alarms and low CPU impact.",
         "Scientific validation, empirical testing, and proof of work.")
    ]
    
    for item in cat_b:
        format_interview_card(doc, *item)
        
    # CATEGORIES C - E
    add_heading_2(doc, "Categories C - E: Development, Architecture & Technology Selection")
    
    cat_c_to_e = [
        (21, "How did you divide the project into modules?",
         "We decoupled the project into specialized functional files: URL analysis, DOM security, forms, scripts, sensitive data, CVE signatures, risk calculation, SIEM correlation, and background orchestration.",
         "To adhere to Single Responsibility Principle (SRP), detection logic was partitioned into independent modules (e.g. form-security.js only audits forms; sensitive-data-security.js only audits secrets). content.js acts as the orchestrator, and risk-engine.js normalizes and weights all findings.",
         "Maine project ko modular banaya taaki har file ka ek specific kaam ho—forms ke liye form-security, secrets ke liye sensitive-data, aur sabko coordinate karne ke liye content.js.",
         "Sequential script declaration in manifest.json content_scripts array.",
         "'Why not bundle all files into one big script using Webpack?' -> Keeping modules unbundled in development made debugging in Chrome DevTools instantaneous without sourcemap overhead.",
         "Software engineering design principles and modularity.")
        ,
        (22, "Explain your project architecture in technical terms.",
         "It is an event-driven, decoupled client-side architecture built on Chrome Manifest V3, utilizing Isolated World content scripts for DOM inspection, a background Service Worker for API orchestration and header capture, and an isolated dashboard for visualization.",
         "The architecture separates Concerns across three distinct process boundaries: 1. Content Script Context: Injected at document_idle, executing heuristic DOM traversal and regex matching; 2. Service Worker Context: Event-driven worker managing webRequest headers, chrome.management audits, and direct Gemini HTTPS fetches; 3. Extension Page Context: Standalone HTML/JS dashboard rendering MITRE heatmaps and managing file exports.",
         "Yeh 3-tier architecture hai: Content scripts DOM check karte hain, Background service worker headers capture karta hai aur AI handle karta hai, aur Dashboard UI sab kuch display karta hai.",
         "See ASCII Architecture Diagram 1 in Part 4.",
         "'How do these components share data?' -> Exclusively through Chrome's asynchronous message passing (chrome.runtime.sendMessage) and isolated chrome.storage.local.",
         "Architectural maturity and systems-level thinking.")
        ,
        (23, "Why did you choose vanilla JavaScript over React or Vue?",
         "To keep content scripts ultra-lightweight. Bundling React would inject 150KB+ of framework runtime into every webpage a user visits, causing memory bloat and slowing down browsing.",
         "Content scripts run directly inside the execution environment of every tab. Injected frameworks introduce significant DOM reconciliation overhead and package bloat. Pure ES6+ JavaScript has zero runtime dependencies, executes in milliseconds, and guarantees maximum performance on low-end hardware.",
         "React use karne se har webpage par 150KB ka extra load padta. Vanilla JavaScript se code ultra-fast chalta hai aur browser slow nahi hota.",
         "Zero external dependencies in package.json or manifest.json.",
         "'Could you have used React for the dashboard UI?' -> Yes, React would be acceptable for the dashboard tab, but using vanilla JS throughout maintained consistent architecture and zero build-step complexity.",
         "Performance awareness and framework trade-off analysis.")
        ,
        (24, "Why did you choose Google Gemini Flash over other LLMs?",
         "Gemini Flash offers ultra-low latency (sub-second response times), structured JSON output mode, and high cost-efficiency for cybersecurity analysis.",
         "Gemini 2.5/2.0 Flash provides a large context window, native support for JSON schema enforcement (responseMimeType: 'application/json'), and rapid inference speeds. Its API is easily callable via standard fetch() from a Chrome service worker without needing heavyweight SDK wrappers.",
         "Gemini Flash super fast hai, JSON format mein structured response deta hai, aur easily browser service worker se call ho jata hai.",
         "Direct fetch implementation in background/service-worker.js lines 527 and 1615.",
         "'What happens if a user wants to use OpenAI or local Ollama?' -> The architecture uses a standard REST payload that can easily be pointed to an Ollama localhost:11434 endpoint with minor configuration.",
         "Model selection reasoning and API design.")
        ,
        (25, "How do you handle failures when the backend/API is down?",
         "We have a built-in deterministic offline fallback engine that generates structured, syntax-highlighted code fixes locally if Gemini is unreachable or disabled.",
         "In background/service-worker.js (lines 1350-1586), if the fetch request fails, times out (8s), or if no API key is provided, the engine automatically routes the scan data to our offline rule generator. It synthesizes vulnerability locations, lay explanations, and parameterized SQL/PHP code patches locally within 5ms.",
         "Agar internet band ho ya Gemini API fail ho jaye, toh hamara offline engine turant local rule-based code patches aur explanations generate kar deta hai.",
         "Fallback generator trace in service-worker.js lines 1350-1586.",
         "'How did you test this failure mode?' -> By disabling Wi-Fi and clicking 'Request AI Analysis', confirming that the dashboard instantly rendered offline remediation cards.",
         "Resilience, fault tolerance, and graceful degradation.")
    ]
    
    for item in cat_c_to_e:
        format_interview_card(doc, *item)
        
    # CATEGORIES F - J
    add_heading_2(doc, "Categories F - J: Individual Contribution, Security, Privacy & Scenarios")
    
    cat_f_to_j = [
        (26, "What was your exact personal contribution to this project?",
         "I designed the end-to-end architecture, implemented the Manifest V3 extension, authored the 13 content detection modules, built the CSP mitigation engine, wrote the Luhn credit card validation, and created the SOC dashboard.",
         "Every file in the repository (manifest.json, background/service-worker.js, all content scripts, and dashboard UI) was personally written, tested, and calibrated by me. I engineered the regex signatures, integrated the MITRE ATT&CK mappings, and built the pre-flight AI sanitization engine.",
         "Maine is project ki puri coding, architecture design, detection rules, CSP mitigation, aur dashboard khud implement kiya hai.",
         "Verified by git commit history on GitHub repository pallavimahajan369/ThreatLens_MadDoG.",
         "'Which file took the most effort to write?' -> background/service-worker.js (1807 lines) and dashboard.js (2418 lines), due to complex state management, webRequest header tracking, and export formatting.",
         "Authenticity, ownership, and technical credibility.")
        ,
        (27, "What was the most challenging bug you encountered and how did you solve it?",
         "Handling false-positive inline script alerts on websites that were already protected by strict Content Security Policies.",
         "Initially, dom-security.js flagged every inline <script> tag as a potential XSS vector. However, on modern sites using CSP (script-src 'self' with nonces), inline scripts cannot execute malicious payloads. To solve this, I built the CSP mitigation engine: capturing headers in service-worker.js, parsing directives in security-auditor.js, and programmatically downgrading finding severity before overall risk calculation.",
         "Sabse bada challenge tha false positives. Inline scripts ko hamara scanner XSS bol raha tha jabki site par strict CSP laga hua tha. Maine CSP parser banaya jo headers check karke false alarms ko mitigate kar deta hai.",
         "Code implementation in content/security-auditor.js (applyCspMitigations).",
         "'How do you test that your mitigation works?' -> By running test_csp_mitigation.js on HTML pages with and without CSP meta tags, verifying that risk drops from HIGH to LOW when CSP is present.",
         "Debugging methodology, problem-solving persistence, and security acumen.")
        ,
        (28, "How do you protect user data and ensure privacy?",
         "Through our Privacy-by-Default architecture: local scanning is 100% offline, AI is disabled by default, and all data is scrubbed of credentials before any external transmission.",
         "We implement Privacy by Design: 1. Zero Telemetry: No background pings, analytics, or tracking beacons; 2. Isolated Storage: chrome.storage.local isolates data from web scripts; 3. Pre-Flight DLP: ai-sanitizer.js strips authentication tokens, JWTs, AWS keys, passwords, and session cookies; 4. Explicit Consent: AI cannot be activated without explicit user toggle and their own API key.",
         "Data privacy ke liye scanning 100% locally hoti hai, AI by default band rehta hai, aur agar AI use karein toh sanitizer saare passwords aur tokens ko redact kar deta hai.",
         "content/ai-sanitizer.js sanitizeUrl() and sanitizeReason() functions.",
         "'Can a website read the extension's stored scan results?' -> No. Content scripts store data via chrome.runtime.sendMessage into chrome.storage.local, which is completely isolated to the extension origin and inaccessible to webpage scripts.",
         "Security governance, privacy engineering, and compliance awareness.")
        ,
        (29, "Can an attacker bypass your detection? What are your limitations?",
         "Yes, an attacker can bypass regex-based detection through code obfuscation, dynamic evaluation, or blind injection that produces no visible DOM output.",
         "Known bypass vectors: 1. Obfuscated JavaScript (e.g. JSFuck, Base64 packed scripts) can evade static regex patterns; 2. Blind SQL injection produces no reflected database error in the DOM; 3. Single-page applications that alter state without modifying the DOM tree cannot be detected by passive scanners. These limitations are inherent to passive client-side analysis.",
         "Haan, agar attacker code ko heavily obfuscate kar de ya blind SQLi use kare jisme screen par error nahi aata, toh passive scanner usko nahi pakad payega.",
         "Documented in project limitations section of README.md.",
         "'How would you counter obfuscation in future versions?' -> By implementing a client-side JavaScript Abstract Syntax Tree (AST) parser or de-obfuscation pipeline using WebAssembly.",
         "Intellectual honesty, self-awareness, and defensive realism.")
        ,
        (30, "What are your future plans to make this project production-ready?",
         "Adding an automated same-origin crawling mode, integrating daily signature updates via declarativeNetRequest, and packaging an enterprise management console.",
         "Roadmap: 1. WebAssembly AST Engine: Replace regex with AST taint analysis for deeper JavaScript vulnerability detection; 2. Same-Origin Spider: Allow users to audit an entire web application (e.g., 50 pages) with one click; 3. Enterprise Centralization: Allow corporate SOC teams to stream browser CEF logs directly to Splunk or Elasticsearch via an authenticated webhook.",
         "Future scope mein automated multi-page crawling, WebAssembly AST parsing, aur enterprise Splunk integration add karenge.",
         "Architecture designed with modular detectors to easily accommodate new WASM engines.",
         "'How would you monetize this if turned into a startup?' -> Free tier for individual developers; paid enterprise tier with centralized SOC fleet management and compliance reporting.",
         "Vision, scalability mindset, and long-term planning.")
    ]
    
    for item in cat_f_to_j:
        format_interview_card(doc, *item)

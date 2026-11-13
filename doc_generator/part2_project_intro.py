from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def build_part2(doc):
    add_heading_1(doc, "PART 2: PROJECT INTRODUCTION & BASIC UNDERSTANDING")
    
    add_paragraph(doc,
        "ThreatLens (internally referred to as SentinelAI / ThreatLens_MadDoG) is an ocular, client-side web vulnerability "
        "scanner, browser extension privilege auditor, and real-time security intelligence platform engineered as a Google Chrome "
        "Extension using pure ES6+ JavaScript and Manifest V3. It transforms the standard Chromium browser into an ethical hacking "
        "and client-side Security Operations Center (SOC) investigation station with zero external proxy dependencies."
    )
    
    add_heading_2(doc, "2.1 Core Project Fundamentals (The 12 Foundational Questions)")
    
    q_and_a = [
        ("1. What is ThreatLens / SentinelAI?", 
         "ThreatLens is a lightweight, zero-backend, client-side security extension that passively audits websites in real-time. It inspects HTML DOM structures, HTTP response headers, interactive forms, scripts, third-party iframes, exposed secrets, phishing signals, and browser extension privileges, displaying findings in an enterprise SOC dashboard with MITRE ATT&CK mapping and AI-assisted remediation."),
        
        ("2. What problem does it solve?", 
         "Traditional web vulnerability scanners (Burp Suite, OWASP ZAP) require heavy Java installations, local proxy configuration (port 8080), custom CA certificates, and active attack fuzzing that can crash databases and is illegal on unauthorized targets. Meanwhile, cloud scanners (Snyk, Qualys) leak proprietary code and cannot scan localhost or firewalled staging environments. ThreatLens solves this by offering passive, non-destructive, zero-setup, 100% private in-browser security analysis that works seamlessly on both public websites and local development environments (e.g., localhost:3000, DVWA)."),
        
        ("3. Why is browser security important?", 
         "Modern web applications execute massive amounts of untrusted code directly inside the user's browser runtime. Browsers have become the de facto operating system for enterprise work (SaaS, banking, cloud consoles). Flaws like DOM XSS, reverse tabnabbing, credential harvesting, exposed API keys, and malicious browser extensions can lead to session hijacking, corporate data breaches, and account takeover directly on the client side, bypassing server-side firewalls."),
        
        ("4. What security threats can users face while browsing?", 
         "Users face: (a) Credential sniffing over unencrypted HTTP forms; (b) Reverse tabnabbing where malicious links hijack the parent tab; (c) Cross-Site Scripting (XSS) stealing authentication tokens; (d) Drive-by downloads and clickjacking via zero-pixel hidden iframes; (e) Exposed developer secrets (AWS keys, private keys, JWTs) left in client DOM; (f) Phishing and brand spoofing via Punycode/homograph domains; (g) Rogue browser extensions spying on cookies and web traffic; (h) Indirect prompt injection attacks manipulating AI browser agents."),
        
        ("5. Why did I decide to build this project?", 
         "As a fresher aspiring for Cybersecurity, SOC, and Application Security engineering roles, I wanted to build a practical tool that solves a real developer pain point. I noticed that web developers often deploy insecure code (like sending passwords via GET or leaving debug API keys in HTML comments) simply because security tools are too intimidating, expensive, or complex to run during daily development. I wanted to build an instant, passive 'security spell-checker' that educates developers as they browse."),
        
        ("6. Who are the intended users?", 
         "• Junior & Senior Web Developers wanting immediate security feedback on their localhost code.\n• Application Security (AppSec) Engineers conducting non-destructive passive reconnaissance.\n• SOC Analysts (L1/L2) needing rapid event correlation, MITRE mapping, and CEF/Syslog export.\n• Cybersecurity Students practicing web penetration testing in safe sandbox environments (DVWA, PortSwigger Web Security Academy).\n• Privacy-Conscious Power Users wanting to audit installed extension permissions."),
        
        ("7. What are the main objectives?", 
         "1. Passive Client-Side Reconnaissance: Zero active fuzzing, 100% legal, non-destructive.\n2. Defense-in-Depth Verification: Correlate DOM vulnerabilities with active Content Security Policies (CSP) to eliminate false positives.\n3. Enterprise SOC Integration: Map findings to MITRE ATT&CK Tactics/Techniques and export logs in industry-standard CEF, JSONL, and Syslog.\n4. Privacy-by-Default Architecture: 100% local operation with zero server telemetry; AI disabled by default with strict pre-flight sanitization.\n5. Educational Empowerment: Translate complex CVEs into plain English analogies and actionable developer code fixes."),
        
        ("8. What are the important features?", 
         "• Passive Vulnerability Engine: Detects SQLi errors, XSS sinks, LFI/Path Traversal, and SSRF parameters.\n• Algorithmic Secret Detection: Validates credit cards using the Luhn Algorithm; validates AWS keys, JWTs, and private keys.\n• HTTP Header & CSP Mitigation Engine: Intercepts real-time response headers via webRequest and adjusts threat risk dynamically.\n• Extension Privilege Auditor: Scans all installed extensions for excessive permissions (cookies, webRequest, <all_urls>).\n• Prompt Injection Detector: Identifies direct and indirect LLM jailbreak attempts in web content.\n• Enterprise Dashboard: MITRE ATT&CK Matrix, finding details with exact DOM selectors, CVSS scores, and CWE cross-references.\n• Export Center: Generates Markdown pentest reports and SIEM log streams (Splunk CEF, Elastic JSONL, Syslog).\n• AI Security Mentor: Google Gemini 2.5/2.0 Flash integration with deterministic offline fallback."),
        
        ("9. How does the project work?", 
         "When a tab loads (or user requests a scan), content.js executes inside Chrome's isolated world at 'document_idle'. It orchestrates modular detectors (URL, DOM, Forms, Scripts, Sensitive Data, CVEs, Phishing, Prompt Injection). Concurrently, background/service-worker.js captures live HTTP security headers via webRequest. Findings are normalized in risk-engine.js, mitigated against active CSP in security-auditor.js, and dispatched to service-worker.js. The worker updates the browser toolbar badge, audits extension privileges, and caches data in chrome.storage.local. The user views live findings, MITRE matrices, and AI fixes in dashboard.html."),
        
        ("10. What is its real-world application?", 
         "In real-world DevSecOps pipelines, ThreatLens acts as a continuous client-side security linter. During local web development and QA testing, engineers catch exposed secrets, insecure form methods, and missing security headers before code reaches production. In SOC teams, analysts use it to quickly triage suspicious URLs, inspect extension risk profiles, and generate SIEM-ready log streams during incident response."),
        
        ("11. What makes it different from a normal browser extension?", 
         "Commercial extensions (uBlock Origin, Malwarebytes, Norton) are primarily DNS/URL blocklist filters or ad blockers that check domains against remote blacklists. They treat web pages as black boxes. ThreatLens is an Application Security and Penetration Testing engine: it inspects the internal DOM, evaluates input sinks, validates cryptographic checksums (Luhn algorithm), parses HTTP CSP directives, maps threats to the MITRE ATT&CK matrix, audits peer extensions, and provides developer source-code remediation."),
        
        ("12. What are its strengths and limitations?", 
         "Strengths: Zero setup, zero proxy, 100% private/local, zero subscription fees, non-destructive passive testing, works on localhost, deep DOM inspection, MITRE integration, AI with offline fallback.\nLimitations: Passive analysis only (cannot detect blind backend vulnerabilities that produce no DOM reflection); single-page scope (does not spider or crawl entire websites); restricted from scanning browser internal pages (chrome://); regex-based pattern matching requires ongoing signature updates.")
    ]
    
    for q, a in q_and_a:
        add_heading_3(doc, q)
        add_paragraph(doc, a)
        
    add_heading_2(doc, "2.2 Tailored Elevator Pitches for Every Interview Setting")
    
    add_heading_3(doc, "30-Second Elevator Pitch (For Rapid Rounds & Quick Intros)")
    add_callout(doc,
        "\"ThreatLens is a client-side web vulnerability scanner and mini-SOC built as a Chrome Extension in Manifest V3. "
        "It passively inspects web pages in real-time for security flaws like SQL injection errors, exposed API keys, insecure forms, "
        "and phishing signals without needing any proxy setup like Burp Suite. Everything runs 100% locally on the browser, maps "
        "findings to the MITRE ATT&CK framework, and exports audit-ready penetration test reports and SIEM logs with one click.\"",
        title="30-SECOND SPEAKING SCRIPT",
        alert_type="TIP"
    )
    
    add_heading_3(doc, "1-Minute Elevator Pitch (Standard Interview Introduction)")
    add_callout(doc,
        "\"ThreatLens is an ocular client-side security scanner and browser extension auditor built using pure JavaScript and Manifest V3. "
        "Traditional application security tools like Burp Suite or OWASP ZAP are heavy, require complex network proxy configurations, and "
        "cannot safely run during routine browsing. ThreatLens solves this by passively analyzing the DOM, HTTP headers, and scripts as you browse.\n\n"
        "It detects SQL injection errors, dangerous DOM sinks, plaintext password forms, exposed cloud secrets validated with algorithms like Luhn, "
        "and even emerging threats like LLM prompt injection. It also audits other installed extensions for excessive permissions. Everything operates "
        "under a Privacy-by-Default architecture with zero external data leakage, while providing optional AI remediation via Google Gemini that is "
        "pre-sanitized. It turns the browser into a real-time security workstation.\"",
        title="1-MINUTE SPEAKING SCRIPT",
        alert_type="TIP"
    )
    
    add_heading_3(doc, "2-Minute In-Depth Project Explanation")
    add_callout(doc,
        "\"I developed ThreatLens to address a major gap between heavyweight penetration testing suites and lightweight ad blockers. "
        "Web developers and junior security analysts frequently deploy insecure code because enterprise scanners are expensive, complex, "
        "and cannot be pointed at local test environments without extensive configuration.\n\n"
        "ThreatLens is structured in three decoupled tiers: First, a set of 12 modular content scripts that run in Chrome's isolated world at document_idle. "
        "These modules inspect the URL, forms, scripts, iframes, and text nodes, matching them against an embedded CVE registry and mathematical algorithms like Luhn for credit cards.\n\n"
        "Second, an event-driven background service worker captures real-time HTTP response headers using the webRequest API, parsing Content Security Policies. "
        "Our engine dynamically mitigates false positives—if a page has a strict CSP blocking inline scripts, our auditor automatically downgrades the severity of inline script findings.\n\n"
        "Third, an enterprise SOC dashboard visualizes findings across the MITRE ATT&CK matrix, audits installed extension privileges, and exports logs in CEF, JSONL, "
        "and Syslog formats. It also includes an AI Security Mentor that provides plain-language analogies and copy-pasteable code fixes. Most importantly, it operates "
        "under a strict Privacy-First model: local scanning is always 100% offline, and AI data is scrubbed of all tokens and passwords before transmission.\"",
        title="2-MINUTE SPEAKING SCRIPT",
        alert_type="TIP"
    )
    
    add_heading_3(doc, "3-Minute Deep Technical Explanation (For Senior Security Engineers)")
    add_callout(doc,
        "\"Architecturally, ThreatLens is built strictly to the Google Chrome Manifest V3 standard using vanilla ES6+ JavaScript, avoiding heavy frameworks to maintain zero runtime DOM overhead.\n\n"
        "The detection engine executes in the content script lifecycle at 'document_idle'. When triggered, content.js orchestrates our specialized detection modules: "
        "url-security.js parses query strings for LFI traversal and SSRF targets; dom-security.js flags dangerous sinks like innerHTML and reverse tabnabbing; "
        "form-security.js inspects form action protocols and credential inputs; sensitive-data-security.js utilizes regex and the Luhn mathematical checksum to detect credit cards, AWS access keys, and JWTs; "
        "and prompt-injection-security.js detects adversarial LLM instruction overrides in visible and CSS-hidden DOM nodes.\n\n"
        "To eliminate false positives, security-auditor.js implements a dynamic CSP mitigation engine. It parses the active Content-Security-Policy captured by our background service worker via webRequest.onHeadersReceived. "
        "If a strict script-src directive without 'unsafe-inline' is enforced, the engine mitigates DOM script findings, reducing alert fatigue. "
        "All signals feed into risk-engine.js, which applies weighted scoring (CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3) and correlation rules to detect multi-stage attack patterns.\n\n"
        "Our background service worker performs cross-extension privilege analysis via chrome.management.getAll(), flagging extensions requesting dangerous combinations like <all_urls>, cookies, and webRequest. "
        "For AI remediation, service-worker.js interfaces directly with Google Gemini REST API. Crucially, before any payload leaves the machine, ai-sanitizer.js redacts all URLs, session IDs, JWTs, and passwords. "
        "If the network drops or AI is disabled, our built-in offline generator creates deterministic, syntax-highlighted PHP/SQL remediation patches. Finally, siem-engine.js maps CWEs to MITRE ATT&CK techniques (like T1190 and T1059.007) and exports CEF, JSONL, and RFC 5424 Syslog logs.\"",
        title="3-MINUTE SENIOR TECHNICAL SCRIPT",
        alert_type="TIP"
    )
    
    add_heading_3(doc, "Non-Technical Explanation for HR / Talent Acquisition")
    add_callout(doc,
        "\"In simple terms, ThreatLens is like a digital security guard and spell-checker that lives inside your web browser. "
        "Whenever a user or developer visits a website, it automatically checks the page for hidden security flaws—such as unencrypted password forms, "
        "fake phishing links, exposed credit card numbers, or dangerous browser add-ons that might be secretly reading private data.\n\n"
        "Instead of confusing users with complex technical jargon, it provides simple explanations with real-world analogies, like comparing an insecure form "
        "to sending a postcard with your password written on the back for anyone to read. It helps companies prevent data breaches early during development, "
        "and it is completely private—it never uploads browsing history to external servers.\"",
        title="HR & NON-TECHNICAL SCRIPT",
        alert_type="NOTE"
    )
    
    add_heading_3(doc, "Technical Explanation for a Technical Interviewer")
    add_callout(doc,
        "\"ThreatLens is a client-side passive Application Security and browser extension auditing platform. "
        "It leverages Chrome's Manifest V3 service worker and isolated world content scripts to perform passive DOM inspection, "
        "runtime HTTP header analysis, and extension privilege auditing. Key technical highlights include a data-driven CVE signature registry, "
        "Luhn checksum secret detection, dynamic CSP false-positive mitigation, a MITRE ATT&CK SIEM correlation engine exporting CEF and Syslog, "
        "and a privacy-preserving pre-flight sanitizer that enables secure, redacted LLM threat explanations with offline fallback.\"",
        title="TECHNICAL INTERVIEWER SCRIPT",
        alert_type="IMPORTANT"
    )
    
    add_heading_2(doc, "2.3 Hinglish Guide for Conceptual Mastery (Apni Bhasha Mein Samjhein)")
    add_callout(doc,
        "ThreatLens ko bilkul aasan shabdon mein samjhein:\n\n"
        "1. Problem kya thi?\n"
        "Jab bhi koi developer website banata hai ya security student testing karta hai, usko Burp Suite ya OWASP ZAP chalana padta hai. "
        "Burp Suite heavy hota hai, port 8080 par proxy lagani padti hai, custom SSL certificate install karna padta hai, aur agar bina permission kisi website par attack payloads bhej diye toh legal problem ho sakti hai. "
        "Doosri taraf, regular users ko pata hi nahi chalta ki unke browser mein jo doosri extensions installed hain, woh secretly unke cookies aur passwords chura sakti hain.\n\n"
        "2. ThreatLens ne kya kiya?\n"
        "ThreatLens ek Chrome Extension hai jo bina kisi proxy setup ke, 100% locally aapke browser ke andar chalti hai. "
        "Yeh 'Passive Scanning' karti hai—matlab website par koi attack payload nahi bhejti, balki jo HTML, DOM, forms, scripts, aur HTTP headers browser ko naturally receive hote hain, unko chupchap inspect karti hai.\n\n"
        "3. Yeh kya-kya pakadti hai?\n"
        "• Agar koi form password ko unencrypted HTTP par bhej raha hai ya GET method use kar raha hai.\n"
        "• Agar page ke andar koi SQL injection ka error (jaise MySQL syntax error) visible hai.\n"
        "• Agar developer ne code mein galti se AWS Secret Key, JWT token, ya credit card number chhod diya hai (jisko Luhn algorithm se verify kiya jata hai taaki false positive na ho).\n"
        "• Agar koi hidden iframe hai jo clickjacking ya silent malware download kar sakta hai.\n"
        "• Agar page par koi modern AI Prompt Injection hai jo AI browser agents ko manipulate kar sake.\n"
        "• Aur sabse best—yeh dekhti hai ki aapke browser mein installed doosri extensions ke paas kaun-kaun si dangerous permissions hain (jaise cookies ya webRequest).\n\n"
        "4. Data Privacy aur AI ka kya role hai?\n"
        "By default, iska Privacy Mode ON hota hai aur AI OFF hota hai. Koi data bahar nahi jata. "
        "Agar user AI ko enable karke apni Google Gemini API key daalta hai, tab bhi hamara 'ai-sanitizer.js' pehle saare URLs, session IDs, tokens, aur passwords ko mask [REDACTED] kar deta hai. "
        "AI sirf vulnerability ko explain karne aur secure code patch generate karne ke liye use hota hai. Agar internet na ho ya AI band ho, toh iske andar ek inbuilt offline engine hai jo automatic secure code fixes generate karta hai!\n\n"
        "5. Interview mein interviewer ko kya impress karega?\n"
        "Interviewer ko batayein ki aapne sirf simple regex nahi lagaye, balki:\n"
        "- False positives rokne ke liye Content Security Policy (CSP) parser banaya jo findings ko mitigate karta hai.\n"
        "- Credit card ke liye Luhn Algorithm lagaya.\n"
        "- Findings ko MITRE ATT&CK framework se map karke enterprise SIEM format (CEF, Syslog, JSONL) mein export karwaya.\n"
        "- Chrome Manifest V3 ke strict security rules follow kiye.",
        title="HINGLISH MASTER STUDY NOTES",
        alert_type="HINGLISH"
    )

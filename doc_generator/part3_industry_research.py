from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def build_part3(doc):
    add_heading_1(doc, "PART 3: INDUSTRY RESEARCH & EXISTING SOLUTIONS")
    
    add_paragraph(doc,
        "A critical mark of engineering maturity is conducting rigorous market and literature research prior to building software. "
        "Before writing a single line of code for ThreatLens, extensive market research was conducted into commercial browser security extensions, "
        "open-source content blockers, enterprise endpoint protection agents, and penetration testing tools. This section details the existing "
        "market landscape, identifies clear technical gaps, and defines the genuine architectural differentiators of ThreatLens."
    )
    
    add_heading_2(doc, "3.1 In-Depth Analysis of Existing Industry Solutions")
    
    products = [
        {
            "name": "uBlock Origin (Raymond Hill / Gorhill)",
            "p1": "Open-source, cross-platform content blocker and browser request filter developed by Raymond Hill.",
            "p2": "Solves memory consumption, intrusive advertising, web tracking, and malicious domains by blocking HTTP requests before they leave the browser.",
            "p3": "Declarative filter list matching (EasyList, EasyPrivacy), strict domain blocking, dynamic URL filtering, script blocking per site, zero telemetry.",
            "p4": "Malicious URLs, drive-by malware domains, cryptominers, tracking beacons, advertising networks.",
            "p5": "Hooks into Chromium's declarativeNetRequest / webRequest APIs to match outbound URLs against static pattern lists stored locally.",
            "p6": "100% Local rule-matching engine using highly optimized trie data structures; zero cloud queries.",
            "p7": "Gold standard in privacy: zero data collection, zero telemetry, no external server infrastructure.",
            "p8": "Treats web pages as black boxes; does not inspect internal DOM structures for application vulnerabilities (SQLi, XSS sinks, insecure form actions, or prompt injection); does not audit other installed extensions; does not provide developer remediation code.",
            "p9": "General internet users, privacy enthusiasts, and security-conscious consumers."
        },
        {
            "name": "Malwarebytes Browser Guard",
            "p1": "Commercial browser extension developed by Malwarebytes for Chrome, Firefox, and Edge.",
            "p2": "Protects consumers against tech support scams, phishing pages, malicious downloads, and intrusive trackers.",
            "p3": "Real-time malicious URL blocking, heuristic tech support scam detection, clickbait protection, ad/tracker blocking.",
            "p4": "Phishing websites, malware-hosting URLs, tech support scareware, scam popups, tracking scripts.",
            "p5": "Inspects outbound URLs and compares them against Malwarebytes cloud threat intelligence database; utilizes client-side heuristics for scareware text patterns.",
            "p6": "Hybrid: local signature cache combined with real-time cloud reputation queries to Malwarebytes cloud servers.",
            "p7": "Collects telemetry on visited domains and blocked threats; privacy policy permits collection of anonymous browsing metrics.",
            "p8": "Closed-source; focused strictly on consumer fraud and scam detection; does not detect web application vulnerabilities (CWE/OWASP); no MITRE mapping; no SIEM log exports; no extension privilege auditing.",
            "p9": "Everyday non-technical consumers seeking automated protection against fraud and scams."
        },
        {
            "name": "Bitdefender TrafficLight",
            "p1": "Free browser extension developed by Bitdefender for real-time web protection.",
            "p2": "Intercepts web threats, phishing attempts, and fraudulent websites before page contents load.",
            "p3": "Search engine result annotations (green/red safety icons), anti-phishing, anti-malware, tracker detector.",
            "p4": "Known phishing URLs, malware distribution points, fraudulent e-commerce portals, tracking scripts.",
            "p5": "Queries Bitdefender cloud reputation database for visited URLs; injects safety indicators into Google/Bing search result pages.",
            "p6": "Primarily Cloud Analysis: relies on Bitdefender cloud intelligence feeds for URL classification.",
            "p7": "Sends visited URLs to Bitdefender cloud infrastructure for classification and reputation lookups.",
            "p8": "No client-side DOM analysis; cannot inspect private intranet or localhost web applications; does not detect exposed developer secrets or prompt injections; closed-source.",
            "p9": "General consumers and enterprise end-users wanting automated URL reputation checks."
        },
        {
            "name": "Guardio",
            "p1": "Commercial cybersecurity browser extension focused on web safety and account protection.",
            "p2": "Prevents web-based account takeover, malicious extension hijacking, push notification scams, and phishing.",
            "p3": "Malicious extension detection, real-time phishing blocking, notification spam filtering, leaked credential monitoring.",
            "p4": "Rogue/hijacked browser extensions, phishing pages, malicious search engine hijackers, dangerous download links.",
            "p5": "Uses proprietary cloud machine learning models and browser hooks to analyze installed extensions and visited links.",
            "p6": "Cloud-heavy: feeds metadata and URLs to Guardio cloud AI models for behavioral threat classification.",
            "p7": "Requires user account; transmits browsing signals and extension lists to Guardio cloud servers.",
            "p8": "Paid subscription model ($10+/month); proprietary/closed-source; does not scan DOM for developer vulnerabilities (SQLi, XSS, SSRF); no SIEM integration.",
            "p9": "SMBs, remote workers, and non-technical consumers seeking proactive browser defense."
        },
        {
            "name": "Avast Online Security & Privacy",
            "p1": "Browser security extension developed by Avast (Gen Digital).",
            "p2": "Warns users about phishing sites, tracks privacy risks, and rates website safety.",
            "p3": "Website reputation scoring, anti-phishing, tracking prevention, search engine annotations.",
            "p4": "Phishing domains, spoofed banking sites, trackers, untrusted web origins.",
            "p5": "Checks domain names against Avast community reputation database; blocks known malicious hosts.",
            "p6": "Cloud Analysis: queries Avast threat intelligence servers for URL reputation.",
            "p7": "Past controversy regarding clickstream data collection (Jumpshot scandal in 2020); current versions have revised privacy policies but still query cloud servers.",
            "p8": "Cannot inspect local code or private applications; no Application Security capabilities; no developer code patches.",
            "p9": "Consumers looking for general web reputation ratings."
        },
        {
            "name": "Norton Safe Web",
            "p1": "Commercial security extension developed by Norton (Gen Digital).",
            "p2": "Provides safety ratings for websites and warns against fraudulent online shopping portals.",
            "p3": "URL reputation ratings, search result annotations, anti-phishing, e-commerce safety checks.",
            "p4": "Fake online stores, phishing portals, malware distribution points.",
            "p5": "Queries Symantec/Norton cloud URL reputation databases upon navigation.",
            "p6": "Cloud Analysis: relies on pre-crawled reputation databases.",
            "p7": "Transmits visited URLs to Norton servers for safety assessment.",
            "p8": "High false-positive rate on newly registered domains; no DOM inspection; cannot audit client-side forms or extension permissions; closed-source.",
            "p9": "Norton antivirus subscribers and everyday online shoppers."
        },
        {
            "name": "Microsoft Defender Browser Protection",
            "p1": "Chrome extension developed by Microsoft to bring SmartScreen protection to Chromium browsers.",
            "p2": "Protects users against malicious links in emails and web pages without requiring Microsoft Edge.",
            "p3": "Real-time URL blocking against Microsoft SmartScreen threat intelligence database.",
            "p4": "Phishing sites, socially engineered malware downloads, malicious redirect links.",
            "p5": "Queries Microsoft SmartScreen cloud services to verify if visited URLs match known malicious lists.",
            "p6": "100% Cloud-dependent: requires active connection to Microsoft SmartScreen API.",
            "p7": "Telemetry transmitted to Microsoft servers in accordance with Windows/Edge privacy policies.",
            "p8": "Strictly a URL blocklist filter; zero DOM analysis; does not detect exposed secrets, form flaws, prompt injections, or extension permissions; cannot run offline or on localhost.",
            "p9": "Enterprise and consumer Chrome users in Windows/Microsoft 365 environments."
        },
        {
            "name": "Privacy Badger (Electronic Frontier Foundation - EFF)",
            "p1": "Open-source privacy extension developed by the Electronic Frontier Foundation (EFF).",
            "p2": "Blocks invisible third-party trackers without relying on curated blocklists.",
            "p3": "Algorithmic tracker detection, heuristic third-party cookie analysis, Global Privacy Control (GPC) signal transmission.",
            "p4": "Third-party cross-site trackers, canvas fingerprinting scripts, tracking cookies.",
            "p5": "Observes third-party origins loaded across multiple sites; if an origin tracks the user across 3+ sites, it automatically blocks the origin.",
            "p6": "100% Local Heuristic Analysis: learns tracking behavior locally inside the browser profile.",
            "p7": "Exemplary privacy: zero telemetry, 100% open-source, non-profit stewardship.",
            "p8": "Not a security scanner; does not detect vulnerabilities, phishing, malware, or exposed secrets; focused solely on user privacy and tracking prevention.",
            "p9": "Privacy advocates, journalists, and everyday web users."
        }
    ]
    
    for p in products:
        add_heading_3(doc, f"Product: {p['name']}")
        add_bullet(doc, p['p1'], bold_prefix="1. What is the product? ")
        add_bullet(doc, p['p2'], bold_prefix="2. Problem solved: ")
        add_bullet(doc, p['p3'], bold_prefix="3. Main features: ")
        add_bullet(doc, p['p4'], bold_prefix="4. Threats detected: ")
        add_bullet(doc, p['p5'], bold_prefix="5. How it works: ")
        add_bullet(doc, p['p6'], bold_prefix="6. Analysis engine: ")
        add_bullet(doc, p['p7'], bold_prefix="7. Privacy approach: ")
        add_bullet(doc, p['p8'], bold_prefix="8. Limitations: ")
        add_bullet(doc, p['p9'], bold_prefix="9. Target audience: ")
        doc.add_paragraph()
        
    add_heading_2(doc, "3.2 Comprehensive Competitor Comparison Matrix")
    
    add_paragraph(doc,
        "The following matrix compares ThreatLens against existing commercial and open-source browser security extensions. "
        "Every capability has been verified against published product documentation. Features are strictly marked as "
        "Yes, No, Partial, or Not Publicly Documented."
    )
    
    comp_headers = [
        "Product", "Main Purpose", "Phishing Det.", "Malicious URL", "DOM & Script Audit", 
        "Form Security", "Prompt Injection", "Extension Audit", "AI Integration", "Local Scanning", "Privacy / Telemetry"
    ]
    
    comp_data = [
        ["ThreatLens (Ours)", "AppSec & Client SOC", "Yes", "Yes", "Yes", "Yes", "Yes", "Yes", "Yes (Gemini/Local)", "Yes (100% Offline)", "Zero Telemetry / Local-First"],
        ["uBlock Origin", "Ad & Request Blocker", "Partial", "Yes", "No", "No", "No", "No", "No", "Yes (Local Lists)", "Zero Telemetry / Private"],
        ["Malwarebytes Guard", "Scam & Malware Blocker", "Yes", "Yes", "No", "No", "No", "No", "No", "Partial (Cache)", "Telemetry to Cloud"],
        ["Bitdefender TrafficLight", "URL Reputation Filter", "Yes", "Yes", "No", "No", "No", "No", "No", "No (Cloud Query)", "URLs sent to Cloud"],
        ["Guardio", "Browser Hijack Protection", "Yes", "Yes", "No", "No", "No", "Yes", "Yes (Cloud ML)", "No (Cloud ML)", "Telemetry & Account Req."],
        ["Norton Safe Web", "Shopping & Site Safety", "Yes", "Yes", "No", "No", "No", "No", "No", "No (Cloud Query)", "URLs sent to Cloud"],
        ["MS Defender Extension", "SmartScreen URL Filter", "Yes", "Yes", "No", "No", "No", "No", "No", "No (SmartScreen)", "Telemetry to Microsoft"],
        ["Privacy Badger (EFF)", "Algorithmic Tracker Blocker", "No", "No", "No", "No", "No", "No", "No", "Yes (Local Learning)", "Zero Telemetry / Private"]
    ]
    
    create_styled_table(doc, comp_headers, comp_data, [1.0, 1.1, 0.6, 0.6, 0.7, 0.6, 0.6, 0.6, 0.7, 0.7, 0.9])
    
    add_heading_2(doc, "3.3 The 12 Critical Competitor Research Interview Questions")
    
    comp_qa = [
        ("1. If similar browser security extensions already exist, why did you build another one?",
         "Because existing extensions are fundamentally *Consumer Blocklists*, not *Application Security Scanners*. Tools like uBlock Origin or Malwarebytes treat websites as black boxes: they check whether an outbound domain is on a bad-domain list, but they have zero insight into the internal DOM. They cannot tell a developer that their form transmits passwords via GET, that an exposed AWS key is leaking in an HTML comment, or that an inline script violates CSP. ThreatLens bridges the gap between consumer blocklists and heavyweight proxy scanners (Burp Suite), offering real-time, in-browser Application Security analysis."),
        
        ("2. What research did you conduct before developing this project?",
         "I researched four core domains: (1) Google Chrome's Manifest V3 security specifications, specifically the migration from background pages to ephemeral service workers and isolated worlds; (2) The OWASP Top 10 (2021) and Common Weakness Enumeration (CWE) to ensure our vulnerability definitions conform to international standards; (3) The MITRE ATT&CK Enterprise Matrix to structure our SIEM event correlation; and (4) Existing market extensions to identify architectural gaps in client-side DOM inspection."),
        
        ("3. Which existing solutions did you study?",
         "I studied open-source tools like uBlock Origin (for request filtering performance) and Privacy Badger (for local heuristic learning), commercial endpoint protection extensions like Malwarebytes Browser Guard and Guardio (for scam and extension security models), and enterprise tools like Wappalyzer (for technology stack fingerprinting) and Burp Suite (for passive vulnerability signatures)."),
        
        ("4. What gaps did you identify in existing solutions?",
         "Gaps identified: (a) Zero DOM application vulnerability analysis (none check for SQLi errors, LFI parameters, or dangerous DOM sinks); (b) Inability to test localhost/offline staging environments; (c) High privacy invasion (most commercial tools send visited URLs to remote servers for classification); (d) Absence of developer-centric code remediation; (e) Lack of emerging AI threat detection (prompt injection)."),
        
        ("5. What problem were you specifically trying to solve?",
         "I wanted to solve the 'Security Feedback Lag' in web development. Developers often deploy vulnerable forms, exposed API keys, and missing security headers simply because setting up Burp Suite or running SonarQube is cumbersome and slow. ThreatLens provides instant, zero-setup, passive security linting directly in the browser as developers code and test."),
        
        ("6. What is genuinely new or different about your project?",
         "Three core differences: (1) Deep Client-Side Inspection: Passive DOM, form, and script analysis combined with cryptographic algorithms like Luhn; (2) Dynamic CSP Mitigation: Automatically adjusts vulnerability risk based on active defense-in-depth headers; (3) Unified SOC Architecture: Combines MITRE ATT&CK mapping, SIEM log generation (CEF/Syslog), extension privilege auditing, and pre-sanitized AI remediation into a single offline-first extension."),
        
        ("7. Why should someone use your extension instead of an existing product?",
         "They should use both! ThreatLens is not an ad-blocker replacement. A user can run uBlock Origin to block advertising and run ThreatLens as their Application Security and Extension Privilege auditor. Developers and ethical hackers choose ThreatLens because it works on localhost, requires zero proxy configuration, and generates audit-ready pentest reports."),
        
        ("8. What features did you implement that address the identified gaps?",
         "We implemented: (a) Passive CVE signature matching (cve-registry.js); (b) Form security analysis (form-security.js); (c) Luhn algorithm secret validation (sensitive-data-security.js); (d) Extension privilege auditing (service-worker.js); (e) LLM prompt injection detection (prompt-injection-security.js); (f) SIEM CEF/Syslog exporters (siem-engine.js)."),
        
        ("9. Is your project a replacement for commercial security products?",
         "No, and I would never claim that in an interview. Commercial endpoint products provide centralized enterprise management, multi-gigabyte threat intelligence feeds, and automated malware sandboxing. ThreatLens is a targeted, lightweight Application Security auditing and educational reconnaissance tool designed for developers, students, and AppSec analysts."),
        
        ("10. What are the limitations compared with commercial solutions?",
         "Commercial tools have full-time threat intelligence teams updating domain blacklists every minute. ThreatLens uses static local signatures and heuristic regexes. Furthermore, commercial tools integrate with corporate EDRs via system-level drivers, whereas ThreatLens is constrained to the Chrome extension sandbox."),
        
        ("11. What did you learn from competitor research?",
         "I learned that privacy is paramount. Many security extensions suffered severe reputational damage by harvesting user browsing history. This inspired our Privacy-by-Default architecture: local-first scanning, zero telemetry, AI disabled by default, and strict pre-flight token sanitization."),
        
        ("12. If you had more time, how would you improve it?",
         "I would: (1) Implement dynamic WebAssembly-based AST (Abstract Syntax Tree) parsing for deeper client-side taint analysis of JavaScript files; (2) Introduce an automated crawling mode that spiders internal links within the same origin; (3) Integrate an automated daily signature sync using Chrome's declarativeNetRequest rulesets.")
    ]
    
    for q, a in comp_qa:
        add_heading_3(doc, q)
        add_paragraph(doc, a)
        
    add_heading_2(doc, "3.4 Defining the Actual Uniqueness (Evidence-Based Differentiators)")
    
    add_paragraph(doc,
        "In a technical interview, claiming that your project is 'completely unique' or 'better than Google' will immediately hurt your credibility. "
        "Interviewers respect candidates who clearly distinguish between existing industry standards, combinations of existing ideas, "
        "and genuine implementation choices."
    )
    
    add_callout(doc,
        "EVIDENCE-BASED VALUE PROPOSITION:\n\n"
        "1. What is Standard Industry Practice?\n"
        "• Regex pattern matching, checking HTTP response headers, and checking domain blacklists are well-established techniques.\n\n"
        "2. What Did We Combine?\n"
        "• We took Application Security concepts (OWASP/CWE), Endpoint SIEM concepts (MITRE ATT&CK, CEF exports), and Browser Extension Auditing (chrome.management), and combined them into a zero-setup browser extension.\n\n"
        "3. What are Our Genuine Implementation Choices?\n"
        "• Dynamic CSP Mitigation Engine: Not just reporting 'Inline script found', but cross-referencing active CSP headers to downgrade severity if script-src protects the page.\n"
        "• Algorithmic Secret Verification: Using the Luhn mathematical checksum to prevent false-positive credit card alerts.\n"
        "• Pre-Flight AI Redaction: Building a zero-knowledge sanitizer that strips JWTs, passwords, and session cookies before LLM analysis.\n"
        "• Deterministic Offline Fallback: Providing syntax-highlighted code remediation even when internet or AI is completely unavailable.",
        title="GENUINE DIFFERENTIATORS BREAKDOWN",
        alert_type="IMPORTANT"
    )

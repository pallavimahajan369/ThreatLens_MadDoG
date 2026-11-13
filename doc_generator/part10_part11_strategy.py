from doc_generator.styles import (
    add_heading_1, add_heading_2, add_heading_3, add_paragraph,
    add_bullet, add_callout, add_code_block, create_styled_table
)

def build_part10_part11(doc):
    # PART 10
    add_heading_1(doc, "PART 10: PROJECT DOCUMENTATION STANDARDS & VISUAL COMPENDIUM")
    
    add_paragraph(doc,
        "Technical documentation must bridge the gap between engineering implementation and executive comprehension. "
        "ThreatLens incorporates an automated Markdown Penetration Testing Report generator and structured SIEM event streams. "
        "This section documents the reporting schemas, knowledge base integration, and visual indicators utilized across the platform."
    )
    
    add_heading_2(doc, "10.1 Automated Markdown Penetration Testing Report Schema")
    add_paragraph(doc,
        "When an analyst clicks 'Export Markdown Report' in the dashboard, dashboard.js dynamically compiles an "
        "audit-ready security assessment document adhering to NIST SP 800-115 penetration testing standards:"
    )
    
    add_code_block(doc,
"""# 🛡️ ThreatLens Penetration Testing & Vulnerability Assessment Report
**Target URL:** https://example-target.com:4280/login.php
**Assessment Date:** 2026-11-12T20:30:00.000Z
**Overall Risk Posture:** CRITICAL (Score: 78/100)
**Assessor:** ThreatLens Ocular Web Security Scanner v1.0.13

---

## 1. Executive Summary
During passive client-side reconnaissance of the target environment, ThreatLens identified 3 Critical, 
2 High, and 4 Medium severity security weaknesses. The primary attack surface stems from unencrypted 
credential transmission over HTTP, an exposed database syntax error (CWE-89), and missing Content Security Policies.

## 2. Risk Matrix & Severity Summary
- CRITICAL: 3
- HIGH: 2
- MEDIUM: 4
- LOW: 1

## 3. Detailed Vulnerability Findings
### [CRITICAL] SQL Injection Error (CWE-89 / CVE-2024-XXXX)
- **CVSS v3.1:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **Location:** Page Body > div#content > pre:nth-of-type(1)
- **Preview:** `You have an error in your SQL syntax near 'admin''`
- **Remediation:** Enforce parameterized queries using PDO prepared statements.

---
*Report generated automatically by ThreatLens Client-Side Security Suite.*
""", language="Markdown Report Schema")
    
    add_heading_2(doc, "10.2 SIEM Event Export Formats (CEF, JSONL, Syslog)")
    add_paragraph(doc,
        "ThreatLens formats security findings into industry-standard event schemas for immediate enterprise SIEM consumption:"
    )
    
    add_bullet(doc, "ArcSight Common Event Format (CEF): CEF:0|ThreatLens|ThreatLens_Scanner|1.0.13|CWE-89|SQL Injection|8|src=127.0.0.1 msg=MySQL syntax error detected in DOM cs1=T1190 cs1Label=MitreTechnique", bold_prefix="CEF Format: ")
    add_bullet(doc, "Elastic JSON-Lines (JSONL): {\"@timestamp\":\"2026-11-12T20:30:00Z\",\"event\":{\"category\":\"web_vulnerability\",\"type\":\"SQL_INJECTION\",\"severity\":\"CRITICAL\"},\"url\":\"http://target.com\",\"mitre\":{\"tactic\":\"TA0001\",\"technique\":\"T1190\"}}", bold_prefix="JSONL Format: ")
    add_bullet(doc, "RFC 5424 Syslog: <14>1 2026-11-12T20:30:00Z threatlens.local ThreatLens 1204 - [security@threatlens category=\"FORM\" severity=\"HIGH\"] Plaintext password submission over HTTP", bold_prefix="Syslog Format: ")
    
    # PART 11
    add_heading_1(doc, "PART 11: FINAL STUDY STRATEGY & DAY-BY-DAY PREPARATION PLAN")
    
    add_paragraph(doc,
        "To maximize retention and performance during interviews, follow this proven 7-day preparation roadmap. "
        "Each day targets specific modules, code components, and speaking scripts."
    )
    
    # 7-DAY SCHEDULE
    add_heading_2(doc, "11.1 Day-by-Day Preparation Sequence")
    
    schedule = [
        ("Day 1: Project Vision, Fundamentals & Elevator Pitches",
         "Topics: Part 2 questions (1-12); memorize 30-second and 1-minute elevator pitches; master Hinglish concepts.\n"
         "Code to Read: manifest.json and content/content.js lines 1-150.\n"
         "Goal: Speak the project introduction fluently without pausing."),
        
        ("Day 2: Chrome Extension Architecture & Manifest V3 Internals",
         "Topics: Part 4 Architecture; Isolated Worlds; Service Worker lifecycle; chrome.storage vs localStorage.\n"
         "Code to Read: background/service-worker.js lines 1-125; content/content.js lines 150-250.\n"
         "Goal: Explain why Manifest V3 deprecated background pages and how IPC messaging works."),
        
        ("Day 3: Threat Detection Engine & CVE Signatures",
         "Topics: Module 3 (Phases 11-16); Form security; URL structure; dangerous DOM sinks; cve-registry.js.\n"
         "Code to Read: content/cve-registry.js and content/form-security.js.\n"
         "Goal: Trace how a MySQL syntax error is matched against cve-registry.js and mapped to CWE-89."),
        
        ("Day 4: Secret Detection, Luhn Algorithm & CSP Mitigation Engine",
         "Topics: Mathematical Luhn mod 10 checksum; AWS key context validation; Content Security Policy mitigation.\n"
         "Code to Read: content/sensitive-data-security.js and content/security-auditor.js.\n"
         "Goal: Explain step-by-step how the Luhn algorithm eliminates false credit card alerts and how CSP reduces risk."),
        
        ("Day 5: Enterprise SOC, MITRE ATT&CK & SIEM Exporters",
         "Topics: siem-engine.js; MITRE tactics/techniques (T1190, T1059); CEF, JSONL, and Syslog schemas.\n"
         "Code to Read: content/siem-engine.js and dashboard/dashboard.js export functions.\n"
         "Goal: Explain how browser security findings translate into enterprise SOC alert pipelines in Splunk."),
        
        ("Day 6: AI Integration, Pre-Flight Sanitizer & Privacy Governance",
         "Topics: Google Gemini REST API; ai-sanitizer.js token redaction; Privacy-by-Default architecture; offline fallback.\n"
         "Code to Read: content/ai-sanitizer.js and background/service-worker.js lines 1350-1680.\n"
         "Goal: Prove that user passwords and tokens are never leaked to external AI models."),
        
        ("Day 7: Mock Interview, Scenarios & Final Polish",
         "Topics: Review Part 6 (Question Bank A-J) and Part 9 (30 Scenarios); execute live DevTools labs (Part 8).\n"
         "Practice: Have a peer cross-examine you using the 'Possible Cross-Questions' in Part 6.\n"
         "Goal: Answer technical edge cases confidently with structured 6-step reasoning.")
    ]
    
    for day, desc in schedule:
        add_heading_3(doc, day)
        add_paragraph(doc, desc)
        
    add_heading_2(doc, "11.2 Topic Priority Matrix (High / Medium / Low)")
    
    p_headers = ["Priority Level", "Topics & Modules", "Must-Explain Code Files", "Interview Weight"]
    p_data = [
        ["HIGH PRIORITY (Must Master)", "Elevator Pitches, MV3 Architecture, Isolated Worlds, Form Security, Luhn Algorithm, CSP Mitigation, Privacy Sanitizer", "service-worker.js, ai-sanitizer.js, content.js, sensitive-data-security.js", "60% of Interview"],
        ["MEDIUM PRIORITY (Core Technical)", "CVE Registry, MITRE ATT&CK Mapping, SIEM CEF/Syslog Exporters, Extension Privilege Auditing, Prompt Injection", "cve-registry.js, siem-engine.js, security-auditor.js, prompt-injection.js", "30% of Interview"],
        ["LOW PRIORITY (Edge Cases)", "CSS animations, fixed popup widths, legacy Manifest V2 background page bugs, minified jQuery parsing edge cases", "popup.css, dashboard.css, scratch/ scripts", "10% of Interview"]
    ]
    create_styled_table(doc, p_headers, p_data, [1.5, 2.3, 1.8, 1.2])
    
    add_heading_2(doc, "11.3 Self-Assessment Readiness Checklist")
    add_paragraph(doc, "Before entering your technical interview, verify you can answer YES to every item:")
    
    checklist = [
        "[ ] Can you explain the 3-tier architecture (Content Scripts -> Service Worker -> Dashboard) in under 2 minutes?",
        "[ ] Can you explain why Manifest V3 replaced persistent background pages with Service Workers?",
        "[ ] Can you trace how the Luhn algorithm validates a credit card mathematically?",
        "[ ] Can you explain how active Content Security Policies dynamically downgrade false-positive findings?",
        "[ ] Can you describe how ai-sanitizer.js strips passwords and session tokens before Gemini API calls?",
        "[ ] Can you explain how background/service-worker.js captures HTTP response headers using webRequest?",
        "[ ] Can you explain the difference between Direct and Indirect Prompt Injection in web content?",
        "[ ] Can you explain how findings map to the MITRE ATT&CK framework and export to Splunk CEF?",
        "[ ] Can you explain what happens when the Gemini API is down or when Wi-Fi is disconnected?",
        "[ ] Can you honestly explain project limitations (passive scanning trade-offs, obfuscation bypasses)?"
    ]
    for chk in checklist:
        add_bullet(doc, chk)
        
    add_heading_2(doc, "11.4 Comprehensive Glossary of Terms")
    
    glossary = [
        ("Manifest V3 (MV3)", "Google Chrome's extension platform standard mandating service workers, declarative network rules, and isolated worlds."),
        ("Isolated World", "A private execution environment where content scripts run; shares DOM with the webpage but has an isolated JS heap."),
        ("Service Worker", "An event-driven background script that spins up on network or message events and terminates when idle."),
        ("Content Security Policy (CSP)", "An HTTP response header restricting where scripts, styles, and iframes can load from, preventing XSS and injection."),
        ("Subresource Integrity (SRI)", "A security feature allowing browsers to verify that resources fetched from CDNs have not been tampered with (integrity hash)."),
        ("Luhn Algorithm", "A modulus 10 checksum formula used to validate identification numbers, specifically credit card numbers (ISO/IEC 7812)."),
        ("MITRE ATT&CK", "A globally accessible knowledge base of adversary tactics and techniques based on real-world cyber attack observations."),
        ("Common Event Format (CEF)", "An industry-standard log management format developed by ArcSight for SIEM event ingestion."),
        ("Data Loss Prevention (DLP)", "A cybersecurity strategy for ensuring that sensitive data is not lost, misused, or accessed by unauthorized users."),
        ("Prompt Injection", "An adversarial attack against Large Language Models where untrusted inputs alter the model's instructions or behavior."),
        ("Same-Origin Policy (SOP)", "A foundational browser security control restricting how scripts on one origin can interact with resources on another."),
        ("Reverse Tabnabbing", "An attack where an untrusted link with target='_blank' manipulates window.opener to replace the parent page with a phishing portal.")
    ]
    
    for term, defn in glossary:
        add_paragraph(doc, defn, bold_prefix=f"{term}: ")
        
    add_heading_2(doc, "11.5 Authoritative Sources & Industry References")
    
    refs = [
        "Google Chrome Extensions Developer Documentation: https://developer.chrome.com/docs/extensions/mv3/",
        "OWASP Top 10 (2021) Web Application Security Risks: https://owasp.org/Top10/",
        "Common Weakness Enumeration (CWE) Database: https://cwe.mitre.org/",
        "MITRE ATT&CK Enterprise Matrix v14: https://attack.mitre.org/matrices/enterprise/",
        "NIST SP 800-115 Technical Guide to Information Security Testing and Assessment: https://csrc.nist.gov/",
        "NIST Common Vulnerability Scoring System (CVSS) v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document",
        "W3C Content Security Policy Level 3 Specification: https://www.w3.org/TR/CSP3/",
        "RFC 5424 The Syslog Protocol: https://datatracker.ietf.org/doc/html/rfc5424",
        "Google Generative AI REST API Reference: https://ai.google.dev/api/rest"
    ]
    for r in refs:
        add_bullet(doc, r)


/**
 * Standard MITRE ATT&CK® Enterprise Matrix Mapping for Web Application Security
 */
const MITRE_ATTACK_MAP = {
    // Injections & Exploits
    "SQL_INJECTION": {
        tactic: "Initial Access",
        tacticId: "TA0001",
        techniqueId: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        subtechnique: null
    },
    "BLIND_SQL_INJECTION": {
        tactic: "Initial Access",
        tacticId: "TA0001",
        techniqueId: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        subtechnique: null
    },
    "COMMAND_INJECTION": {
        tactic: "Execution",
        tacticId: "TA0002",
        techniqueId: "T1059.004",
        techniqueName: "Command and Scripting Interpreter: Unix Shell",
        subtechnique: "T1059.004"
    },
    "PHP_CGI_ARG_INJECTION": {
        tactic: "Execution",
        tacticId: "TA0002",
        techniqueId: "T1190",
        techniqueName: "Exploit Public-Facing Application (CVE-2024-4577)",
        subtechnique: null
    },
    // Cross-Site Scripting (XSS)
    "XSS_REFLECTED": {
        tactic: "Execution",
        tacticId: "TA0002",
        techniqueId: "T1059.007",
        techniqueName: "Command and Scripting Interpreter: JavaScript",
        subtechnique: "T1059.007"
    },
    "XSS_STORED": {
        tactic: "Persistence",
        tacticId: "TA0003",
        techniqueId: "T1189",
        techniqueName: "Drive-by Compromise",
        subtechnique: null
    },
    "XSS_DOM": {
        tactic: "Execution",
        tacticId: "TA0002",
        techniqueId: "T1059.007",
        techniqueName: "Command and Scripting Interpreter: JavaScript",
        subtechnique: "T1059.007"
    },
    "JQUERY_XSS": {
        tactic: "Execution",
        tacticId: "TA0002",
        techniqueId: "T1059.007",
        techniqueName: "Command and Scripting Interpreter: JavaScript (CVE-2020-11022)",
        subtechnique: "T1059.007"
    },
    // File & Server Software
    "FILE_INCLUSION": {
        tactic: "Initial Access",
        tacticId: "TA0001",
        techniqueId: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        subtechnique: null
    },
    "FILE_UPLOAD": {
        tactic: "Persistence",
        tacticId: "TA0003",
        techniqueId: "T1505.003",
        techniqueName: "Server Software Component: Web Shell",
        subtechnique: "T1505.003"
    },
    // Authentication & Credential Access
    "CSRF": {
        tactic: "Initial Access",
        tacticId: "TA0001",
        techniqueId: "T1204.001",
        techniqueName: "User Execution: Malicious Link",
        subtechnique: "T1204.001"
    },
    "BRUTE_FORCE": {
        tactic: "Credential Access",
        tacticId: "TA0006",
        techniqueId: "T1110.001",
        techniqueName: "Brute Force: Password Guessing",
        subtechnique: "T1110.001"
    },
    "WEAK_SESSION_ID": {
        tactic: "Credential Access",
        tacticId: "TA0006",
        techniqueId: "T1539",
        techniqueName: "Steal Web Session Cookie",
        subtechnique: null
    },
    "INSECURE_COOKIE": {
        tactic: "Credential Access",
        tacticId: "TA0006",
        techniqueId: "T1539",
        techniqueName: "Steal Web Session Cookie",
        subtechnique: null
    },
    // Defense Evasion & Bypasses
    "INSECURE_CAPTCHA": {
        tactic: "Defense Evasion",
        tacticId: "TA0005",
        techniqueId: "T1562",
        techniqueName: "Impair Defenses",
        subtechnique: null
    },
    "CSP_BYPASS": {
        tactic: "Defense Evasion",
        tacticId: "TA0005",
        techniqueId: "T1562.001",
        techniqueName: "Impair Defenses: Disable or Modify Tools",
        subtechnique: "T1562.001"
    },
    "OPEN_REDIRECT": {
        tactic: "Initial Access",
        tacticId: "TA0001",
        techniqueId: "T1204.001",
        techniqueName: "User Execution: Malicious Link",
        subtechnique: "T1204.001"
    },
    // Extension & Client Environment
    "HIGH_PRIVILEGE_EXTENSION": {
        tactic: "Persistence",
        tacticId: "TA0003",
        techniqueId: "T1176",
        techniqueName: "Browser Extensions",
        subtechnique: null
    },
    "PROMPT_INJECTION": {
        tactic: "Defense Evasion",
        tacticId: "TA0005",
        techniqueId: "T1055",
        techniqueName: "Process Injection: LLM Prompt Injection",
        subtechnique: null
    },
    "SENSITIVE_DATA_EXPOSURE": {
        tactic: "Credential Access",
        tacticId: "TA0006",
        techniqueId: "T1552",
        techniqueName: "Unsecured Credentials",
        subtechnique: null
    },
    "RECON_ATTACK_SURFACE": {
        tactic: "Reconnaissance",
        tacticId: "TA0043",
        techniqueId: "T1592",
        techniqueName: "Gather Victim Host Information",
        subtechnique: null
    }
};

/**
 * Resolves MITRE ATT&CK technique by finding type
 */
function resolveMitreAttack(vulnType) {
    const norm = String(vulnType || "").toUpperCase();
    if (norm.includes("SQL")) return MITRE_ATTACK_MAP["SQL_INJECTION"];
    if (norm.includes("COMMAND") || norm.includes("EXEC")) return MITRE_ATTACK_MAP["COMMAND_INJECTION"];
    if (norm.includes("PHP_CGI")) return MITRE_ATTACK_MAP["PHP_CGI_ARG_INJECTION"];
    if (norm.includes("STORED")) return MITRE_ATTACK_MAP["XSS_STORED"];
    if (norm.includes("DOM")) return MITRE_ATTACK_MAP["XSS_DOM"];
    if (norm.includes("XSS")) return MITRE_ATTACK_MAP["XSS_REFLECTED"];
    if (norm.includes("INCLUSION") || norm.includes("PATH_TRAVERSAL")) return MITRE_ATTACK_MAP["FILE_INCLUSION"];
    if (norm.includes("UPLOAD")) return MITRE_ATTACK_MAP["FILE_UPLOAD"];
    if (norm.includes("CSRF")) return MITRE_ATTACK_MAP["CSRF"];
    if (norm.includes("BRUTE")) return MITRE_ATTACK_MAP["BRUTE_FORCE"];
    if (norm.includes("SESSION")) return MITRE_ATTACK_MAP["WEAK_SESSION_ID"];
    if (norm.includes("COOKIE")) return MITRE_ATTACK_MAP["INSECURE_COOKIE"];
    if (norm.includes("CAPTCHA")) return MITRE_ATTACK_MAP["INSECURE_CAPTCHA"];
    if (norm.includes("CSP")) return MITRE_ATTACK_MAP["CSP_BYPASS"];
    if (norm.includes("REDIRECT")) return MITRE_ATTACK_MAP["OPEN_REDIRECT"];
    if (norm.includes("EXTENSION")) return MITRE_ATTACK_MAP["HIGH_PRIVILEGE_EXTENSION"];
    if (norm.includes("PROMPT")) return MITRE_ATTACK_MAP["PROMPT_INJECTION"];
    if (norm.includes("CREDENTIAL") || norm.includes("SECRET") || norm.includes("KEY")) return MITRE_ATTACK_MAP["SENSITIVE_DATA_EXPOSURE"];
    if (norm.includes("RECON") || norm.includes("COMMENT") || norm.includes("ENDPOINT")) return MITRE_ATTACK_MAP["RECON_ATTACK_SURFACE"];

    return {
        tactic: "Discovery",
        tacticId: "TA0007",
        techniqueId: "T1082",
        techniqueName: "System Information Discovery",
        subtechnique: null
    };
}

/**
 * Returns numeric severity score for SIEM standard scoring (1 to 10)
 */
function getSeverityScore(severity) {
    switch (String(severity || "").toUpperCase()) {
        case "CRITICAL": return 10;
        case "HIGH": return 8;
        case "MEDIUM": return 5;
        case "LOW": return 2;
        default: return 1;
    }
}

/**
 * Converts raw scan findings into standardized SIEM event log records
 * @param {Object} scan Complete scan result from page
 * @returns {Array<Object>} Standardized SIEM event objects
 */
function generateSiemEventsFromScan(scan) {
    if (!scan) return [];
    const events = [];
    const now = new Date();
    const timestamp = now.toISOString();
    const epoch = now.getTime();

    let hostname = "unknown";
    let port = "80";
    let pathname = "/";
    try {
        if (scan.url && scan.url.startsWith("http")) {
            const u = new URL(scan.url);
            hostname = u.hostname;
            port = u.port || (u.protocol === "https:" ? "443" : "80");
            pathname = u.pathname;
        }
    } catch (e) {}

    const allFindings = [
        ...(Array.isArray(scan.webVulnerabilityFindings) ? scan.webVulnerabilityFindings : []),
        ...(Array.isArray(scan.urlFindings) ? scan.urlFindings : []),
        ...(Array.isArray(scan.domFindings) ? scan.domFindings : []),
        ...(Array.isArray(scan.formFindings) ? scan.formFindings : []),
        ...(Array.isArray(scan.scriptIframeFindings) ? scan.scriptIframeFindings : []),
        ...(Array.isArray(scan.sensitiveDataFindings) ? scan.sensitiveDataFindings : []),
        ...(Array.isArray(scan.promptInjectionFindings) ? scan.promptInjectionFindings : [])
    ];

    allFindings.forEach((f, idx) => {
        if (!f || !f.type || f.type.startsWith("NO_")) return;

        const mitre = resolveMitreAttack(f.type || f.category);
        const sev = String(f.severity || "LOW").toUpperCase();
        let targetComponent = pathname;
        if (f.details?.items && f.details.items.length > 0) {
            targetComponent = f.details.items[0].location || f.details.items[0].domPath || pathname;
        }

        events.push({
            id: `TL-EVT-${epoch}-${idx}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
            timestamp,
            epoch,
            eventType: f.type || "SECURITY_FINDING",
            category: f.category || "WEB_APPLICATION",
            severity: sev,
            severityScore: getSeverityScore(sev),
            target: {
                url: (scan.url || "").split("?")[0], // Redacted URL base
                hostname,
                port,
                pathname,
                component: String(targetComponent).slice(0, 100)
            },
            mitre,
            message: f.reason || `${f.type} detected on ${hostname}`,
            ruleId: f.details?.ruleId || f.type,
            occurrences: f.count || 1
        });
    });

    // Check extension risks and generate SIEM events
    if (Array.isArray(scan.extensionScan)) {
        scan.extensionScan.forEach((ext, idx) => {
            if (ext.risk === "HIGH" || ext.risk === "CRITICAL") {
                events.push({
                    id: `TL-EXT-${epoch}-${idx}`,
                    timestamp,
                    epoch,
                    eventType: "HIGH_PRIVILEGE_EXTENSION",
                    category: "BROWSER_SECURITY",
                    severity: ext.risk,
                    severityScore: getSeverityScore(ext.risk),
                    target: {
                        url: "chrome://extensions",
                        hostname: "browser-client",
                        port: "local",
                        pathname: ext.name || "Unknown Extension",
                        component: (ext.permissions || []).join(", ").slice(0, 80)
                    },
                    mitre: MITRE_ATTACK_MAP["HIGH_PRIVILEGE_EXTENSION"],
                    message: `Extension '${ext.name}' possesses high-risk host/DOM permissions`,
                    ruleId: "BROWSER_EXT_AUDIT",
                    occurrences: 1
                });
            }
        });
    }

    return events;
}

/**
 * Correlates individual SIEM events into actionable Multi-Stage Security Incidents
 * @param {Array<Object>} events All active SIEM events
 * @returns {Array<Object>} Correlated security incidents
 */
function correlateSiemEvents(events) {
    if (!Array.isArray(events) || events.length === 0) return [];

    const incidents = [];
    const hostMap = new Map();

    events.forEach(ev => {
        const host = ev.target?.hostname || "unknown";
        if (!hostMap.has(host)) hostMap.set(host, []);
        hostMap.get(host).push(ev);
    });

    hostMap.forEach((hostEvents, host) => {
        const types = new Set(hostEvents.map(e => e.eventType));
        const hasSqli = Array.from(types).some(t => t.includes("SQL"));
        const hasCmdInj = Array.from(types).some(t => t.includes("COMMAND") || t.includes("EXEC") || t.includes("PHP_CGI"));
        const hasXss = Array.from(types).some(t => t.includes("XSS"));
        const hasCookieExposure = Array.from(types).some(t => t.includes("COOKIE") || t.includes("SESSION"));
        const hasFileUpload = Array.from(types).some(t => t.includes("UPLOAD"));
        const hasFileInclusion = Array.from(types).some(t => t.includes("INCLUSION") || t.includes("TRAVERSAL"));
        const hasHighPrivExt = hostEvents.some(e => e.eventType === "HIGH_PRIVILEGE_EXTENSION");

        // Incident 1: Critical Web Exploitation Chain
        if ((hasSqli || hasCmdInj) && (hasFileInclusion || hasFileUpload || hasCookieExposure)) {
            incidents.push({
                incidentId: `INC-CHAIN-${Math.floor(hostEvents[0].epoch / 1000).toString(16).toUpperCase()}`,
                title: `Multi-Stage Web Exploitation Chain on ${host}`,
                severity: "CRITICAL",
                severityScore: 10,
                targetHost: host,
                eventCount: hostEvents.length,
                mitreTactics: ["Initial Access (TA0001)", "Execution (TA0002)", "Persistence (TA0003)"],
                summary: `Correlated attack chain combining Injection flaws with File Inclusion/Upload capabilities. High probability of complete host or database compromise.`,
                socAction: "Isolate web application endpoint, enforce strict database parameterized queries, and restrict server script execution permissions."
            });
        }
        // Incident 2: Session Hijacking Threat
        else if (hasCookieExposure && (hasXss || hasHighPrivExt)) {
            incidents.push({
                incidentId: `INC-SESSION-${Math.floor(hostEvents[0].epoch / 1000).toString(16).toUpperCase()}`,
                title: `Session Hijacking & Token Theft Risk on ${host}`,
                severity: "HIGH",
                severityScore: 8,
                targetHost: host,
                eventCount: hostEvents.length,
                mitreTactics: ["Execution (TA0002)", "Credential Access (TA0006)"],
                summary: `Insecure session tokens detected without HttpOnly flags while active XSS or high-privilege browser extensions can read client cookies.`,
                socAction: "Enforce HttpOnly and Secure cookie attributes immediately. Rotate user session identifiers upon permission state change."
            });
        }
        // Incident 3: Active Input Manipulation & Injection Surface
        else if (hasSqli || hasCmdInj || hasXss) {
            incidents.push({
                incidentId: `INC-INJECT-${Math.floor(hostEvents[0].epoch / 1000).toString(16).toUpperCase()}`,
                title: `Active Application Vulnerability Probes on ${host}`,
                severity: hasCmdInj ? "CRITICAL" : "HIGH",
                severityScore: hasCmdInj ? 10 : 8,
                targetHost: host,
                eventCount: hostEvents.length,
                mitreTactics: ["Initial Access (TA0001)", "Execution (TA0002)"],
                summary: `Multiple input parameter vulnerabilities identified on active routes. Potential for unauthorized database access or arbitrary client script execution.`,
                socAction: "Validate and sanitize all form/query inputs. Implement contextual output encoding and prepared statements."
            });
        }
    });

    return incidents;
}

/**
 * Generates ArcSight Common Event Format (CEF) log output
 * Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
 * @param {Array<Object>} events 
 * @returns {string} CEF formatted string
 */
function exportToCef(events) {
    if (!Array.isArray(events)) return "";
    const lines = [];

    events.forEach(e => {
        const ext = [
            `src=127.0.0.1`,
            `dst=${e.target?.hostname || "unknown"}`,
            `dpt=${e.target?.port || "80"}`,
            `request=${encodeURIComponent(e.target?.pathname || "/")}`,
            `cs1=${e.mitre?.techniqueId || "T1190"}`,
            `cs1Label=MitreTechniqueId`,
            `cs2=${e.mitre?.tactic || "Initial Access"}`,
            `cs2Label=MitreTactic`,
            `cs3=${encodeURIComponent(e.target?.component || "")}`,
            `cs3Label=TargetComponent`,
            `msg=${encodeURIComponent(e.message || "")}`
        ].join(" ");

        lines.push(`CEF:0|ThreatLens|OcularWebSecurity|1.0.7|${e.eventType}|${e.message.replace(/\|/g, "-")}|${e.severityScore}|${ext}`);
    });

    return lines.join("\r\n");
}

/**
 * Generates Elastic / Splunk compatible JSON Lines (JSONL) log output
 * @param {Array<Object>} events 
 * @returns {string} JSONL formatted string
 */
function exportToJsonl(events) {
    if (!Array.isArray(events)) return "";
    return events.map(e => JSON.stringify({
        "@timestamp": e.timestamp,
        "event": {
            "id": e.id,
            "category": e.category,
            "type": e.eventType,
            "severity": e.severityScore,
            "severity_label": e.severity,
            "rule_id": e.ruleId
        },
        "host": {
            "name": e.target?.hostname,
            "port": e.target?.port
        },
        "url": {
            "path": e.target?.pathname,
            "component": e.target?.component
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": e.mitre?.tacticId,
                "name": e.mitre?.tactic
            },
            "technique": {
                "id": e.mitre?.techniqueId,
                "name": e.mitre?.techniqueName,
                "subtechnique": e.mitre?.subtechnique
            }
        },
        "message": e.message
    })).join("\r\n");
}

/**
 * Generates RFC-5424 Syslog formatted output
 * Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
 * @param {Array<Object>} events 
 * @returns {string} Syslog formatted string
 */
function exportToSyslog(events) {
    if (!Array.isArray(events)) return "";
    const lines = [];

    events.forEach(e => {
        // Priority: Facility 16 (local0) * 8 + Severity (CRITICAL=2, HIGH=3, MEDIUM=4, LOW=6)
        let priVal = 134; // local0.info
        if (e.severity === "CRITICAL") priVal = 130; // local0.crit
        else if (e.severity === "HIGH") priVal = 131; // local0.err
        else if (e.severity === "MEDIUM") priVal = 132; // local0.warn

        const msg = `[ThreatLens@4280 eventType="${e.eventType}" mitre="${e.mitre?.techniqueId}" target="${e.target?.hostname}:${e.target?.port}${e.target?.pathname}"] ${e.message}`;
        lines.push(`<${priVal}>1 ${e.timestamp} client-browser ThreatLens SIEM ${e.id} - ${msg}`);
    });

    return lines.join("\r\n");
}

// Make accessible to all browser extension scopes (window or global worker)
if (typeof self !== "undefined") {
    self.MITRE_ATTACK_MAP = MITRE_ATTACK_MAP;
    self.resolveMitreAttack = resolveMitreAttack;
    self.generateSiemEventsFromScan = generateSiemEventsFromScan;
    self.correlateSiemEvents = correlateSiemEvents;
    self.exportToCef = exportToCef;
    self.exportToJsonl = exportToJsonl;
    self.exportToSyslog = exportToSyslog;
}

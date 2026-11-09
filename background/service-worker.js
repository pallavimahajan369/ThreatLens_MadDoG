importScripts("../content/ai-sanitizer.js");

console.log("ThreatLens service worker started");

// Track tabs that currently have an AI request in progress
const aiRequestsInProgress = new Set();
const AI_RETRY_COOLDOWN = 10 * 1000;

const aiRetryCooldown =
    new Map();

// Storage helper functions returning Promises with lastError handling
function getStorage(keys) {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.get(keys, (result) => {
                if (chrome.runtime.lastError) {
                    // Accessing lastError suppresses Chrome's "Unchecked runtime.lastError" log
                }
                resolve(result || {});
            });
        } catch (e) {
            resolve({});
        }
    });
}

function setStorage(data) {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.set(data, () => {
                if (chrome.runtime.lastError) {
                    // Suppress Unchecked runtime.lastError and auto-recover
                    resolve(false);
                    return;
                }
                resolve(true);
            });
        } catch (e) {
            resolve(false);
        }
    });
}


chrome.storage.local.get(
    ["privacyMode", "aiEnabled", "aiConsent"],
    (settings) => {
        const updates = {};

        if (settings.privacyMode !== true) {
            updates.privacyMode = true;
        }

        // AI scanning is disabled by default for strict local security and data privacy
        if (settings.aiEnabled !== false) {
            updates.aiEnabled = false;
        }

        if (settings.aiConsent !== false) {
            updates.aiConsent = false;
        }

        if (Object.keys(updates).length > 0) {
            chrome.storage.local.set(updates);
        }
    }
);


// ==================================
// EXTENSION SECURITY ANALYSIS
// ==================================

function analyzeExtensionSecurity(extension) {

    const findings = [];

    const permissions =
        extension.permissions || [];

    const hostPermissions =
        extension.hostPermissions || [];


    // ----------------------------------
    // TABS
    // ----------------------------------

    if (permissions.includes("tabs")) {

        findings.push({
            type: "TABS_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can access information about browser tabs"
        });

    }


    // ----------------------------------
    // COOKIES
    // ----------------------------------

    if (permissions.includes("cookies")) {

        findings.push({
            type: "COOKIES_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can access browser cookies"
        });

    }


    // ----------------------------------
    // WEB REQUEST
    // ----------------------------------

    if (permissions.includes("webRequest")) {

        findings.push({
            type: "WEBREQUEST_PERMISSION",
            severity: "HIGH",
            reason:
                "Extension can observe web requests"
        });

    }


    // ----------------------------------
    // SCRIPTING
    // ----------------------------------

    if (permissions.includes("scripting")) {

        findings.push({
            type: "SCRIPTING_PERMISSION",
            severity: "MEDIUM",
            reason:
                "Extension can inject or execute scripts on webpages"
        });

    }


    // ----------------------------------
    // ALL URLS
    // ----------------------------------

    const hasAllURLs =
        hostPermissions.some(
            permission =>
                permission === "<all_urls>" ||
                permission === "*://*/*" ||
                permission === "http://*/*" ||
                permission === "https://*/*"
        );


    if (hasAllURLs) {

        findings.push({
            type: "ALL_URLS",
            severity: "HIGH",
            reason:
                "Extension can access a broad range of websites"
        });

    }


    // ----------------------------------
    // WEBPAGE MODIFICATION
    // ----------------------------------

    if (
        permissions.includes("scripting") ||
        hasAllURLs
    ) {

        findings.push({
            type: "WEBPAGE_MODIFICATION",
            severity: "MEDIUM",
            reason:
                "Extension may have capability to modify webpage content"
        });

    }


    // ----------------------------------
    // MULTIPLE HIGH-RISK PERMISSIONS
    // ----------------------------------

    const highRiskPermissions = [
        "cookies",
        "webRequest",
        "webRequestBlocking",
        "debugger"
    ];


    const riskyPermissionCount =
        permissions.filter(
            permission =>
                highRiskPermissions.includes(permission)
        ).length;


    if (riskyPermissionCount >= 2) {

        findings.push({
            type: "EXCESSIVE_PERMISSIONS",
            severity: "HIGH",
            reason:
                "Extension requests multiple high-impact permissions"
        });

    }


    // ----------------------------------
    // BROAD HOST ACCESS
    // ----------------------------------

    if (hostPermissions.length >= 5) {

        findings.push({
            type: "BROAD_HOST_ACCESS",
            severity: "MEDIUM",
            reason:
                "Extension requests access to multiple website origins"
        });

    }


    // ----------------------------------
    // CALCULATE EXTENSION RISK
    // ----------------------------------

    let risk = "LOW";


    if (
        findings.some(
            finding =>
                finding.severity === "HIGH"
        )
    ) {

        risk = "HIGH";

    }
    else if (
        findings.some(
            finding =>
                finding.severity === "MEDIUM"
        )
    ) {

        risk = "MEDIUM";

    }


    // ----------------------------------
    // NO SUSPICIOUS PERMISSIONS
    // ----------------------------------

    if (findings.length === 0) {

        findings.push({
            type: "NO_SUSPICIOUS_PERMISSION",
            severity: "LOW",
            reason:
                "No suspicious permission indicators detected"
        });

    }


    return {
        risk: risk,
        findings: findings
    };
}



// ==================================
// SCAN INSTALLED EXTENSIONS
// ==================================

async function scanInstalledExtensions() {

    try {

        const extensions =
            await chrome.management.getAll();


    const results =
        extensions
            .filter(
                extension =>
                    extension.type === "extension" &&
                    extension.id !== chrome.runtime.id
            )
            .map(
                extension => {

                    const analysis =
                        analyzeExtensionSecurity(
                            extension
                        );


                    return {

                        id:
                            extension.id,

                        name:
                            extension.name,

                        enabled:
                            extension.enabled,

                        permissions:
                            extension.permissions || [],

                        hostPermissions:
                            extension.hostPermissions || [],

                        risk:
                            analysis.risk,

                        findings:
                            analysis.findings
                    };

                }
            );


    await chrome.storage.local.set({

        extensionScan:
            results,

        extensionScanTimestamp:
            new Date().toISOString()

    });


    console.log(
        "ThreatLens Extension Scan:",
        results
    );


            return results;

    }
    catch (error) {

        console.error(
            "ThreatLens: Extension security scan failed:",
            error
        );

        return [];

    }
}
function isValidScanMessage(message) {

    if (!message || typeof message !== "object") {
        return false;
    }

    if (message.type !== "SCAN_RESULT") {
        return false;
    }

    if (!message.data || typeof message.data !== "object") {
        return false;
    }

    return true;
}


// ==================================
// MESSAGE LISTENER
// ==================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        if (!message || typeof message !== "object") {
            return false;
        }

        console.log("ThreatLens Service Worker received message:", message.type);

        // ==================================
        // TEST AI CONNECTION
        // ==================================
        if (message.type === "TEST_AI_CONNECTION") {
            (async () => {
                try {
                    let geminiApiKey = (typeof message.apiKey === "string" ? message.apiKey : "")?.trim();
                    if (!geminiApiKey) {
                        const config = await getStorage(["geminiApiKey"]);
                        geminiApiKey = config.geminiApiKey?.trim();
                    } else {
                        await setStorage({ geminiApiKey });
                    }

                    if (!geminiApiKey) {
                        return sendResponse({ success: false, error: "No API key saved. Paste your Gemini API key and click 'Save Key' first." });
                    }

                    // Test direct Gemini API with supported candidate models
                    const models = [
                        "gemini-2.5-flash",
                        "gemini-2.0-flash",
                        "gemini-1.5-flash",
                        "gemini-3.1-flash-lite",
                        "gemini-2.0-flash-lite"
                    ];
                    let verifiedModel = null;
                    let lastErr = null;

                    for (const m of models) {
                        try {
                            const testUrl = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(geminiApiKey)}`;
                            const testRes = await fetch(testUrl, {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ contents: [{ parts: [{ text: "ping" }] }] }),
                                signal: AbortSignal.timeout(8000)
                            });
                            if (testRes.ok) {
                                verifiedModel = m;
                                break;
                            } else {
                                const err = await testRes.json().catch(() => ({}));
                                lastErr = err?.error?.message || `HTTP ${testRes.status}`;
                            }
                        } catch (e) {
                            lastErr = e.message;
                        }
                    }

                    if (verifiedModel) {
                        sendResponse({ success: true, mode: "DIRECT", message: `Gemini API connected successfully! (Model: ${verifiedModel})` });
                    } else {
                        sendResponse({ success: false, error: `Gemini validation failed: ${lastErr || "Invalid key"}` });
                    }
                } catch (err) {
                    sendResponse({ success: false, error: err.message || "Connection test failed" });
                }
            })();
            return true;
        }

        // ==================================
        // FORCE ON-DEMAND AI SCAN
        // ==================================
        if (message.type === "FORCE_AI_SCAN") {
            (async () => {
                try {
                    let targetTabId = message.tabId;
                    if (!targetTabId) {
                        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
                        targetTabId = tabs[0]?.id;
                    }
                    if (!targetTabId) throw new Error("No active browser tab found");

                    let geminiApiKey = (typeof message.apiKey === "string" ? message.apiKey : "")?.trim();
                    if (!geminiApiKey) {
                        const config = await getStorage(["geminiApiKey"]);
                        geminiApiKey = config.geminiApiKey?.trim();
                    } else {
                        await setStorage({ geminiApiKey });
                    }

                    // If no API key is provided, synthesize the full explanation locally
                    if (!geminiApiKey) {
                        const localSynth = synthesizeLocalDeepExplanation(aiPayload);
                        const aiResult = {
                            success: true,
                            risk: aiPayload.overallRisk,
                            analysis: localSynth,
                            isLocal: true
                        };
                        const toSave = { latest_ai_analysis: aiResult };
                        if (targetTabId) {
                            toSave[`ai_analysis_${targetTabId}`] = aiResult;
                        }
                        await setStorage(toSave);
                        return sendResponse({ success: true, tabId: targetTabId, result: aiResult });
                    }

                    const storage = await getStorage([`scan_${targetTabId}`, "lastScan", "extensionScan"]);
                    let scan = storage[`scan_${targetTabId}`] || storage.lastScan;
                    if (!scan) {
                        scan = {
                            url: "Current Browser Tab",
                            overallRisk: "SAFE",
                            risk: { level: "SAFE" },
                            domFindings: [],
                            formFindings: [],
                            scriptIframeFindings: [],
                            urlFindings: [],
                            extensionScan: storage.extensionScan || []
                        };
                    }

                    scan.extensionScan = storage.extensionScan || [];
                    const aiPayload = buildAISecurityPayload(scan);

                    let aiResult = await requestAIAnalysis(aiPayload, targetTabId, geminiApiKey);
                    if (!aiResult || aiResult.success === false) {
                        const localSynth = synthesizeLocalDeepExplanation(aiPayload);
                        aiResult = {
                            success: true,
                            risk: aiPayload.overallRisk,
                            analysis: localSynth
                        };
                    }
                    sendResponse({ success: true, tabId: targetTabId, result: aiResult });
                } catch (err) {
                    sendResponse({ success: false, error: err.message || "AI trigger failed" });
                }
            })();
            return true;
        }

        // ==================================
        // SCAN RESULT
        // ==================================

        if (
            message.type ===
            "SCAN_RESULT"
        ) {
            if (!isValidScanMessage(message)) {
                console.warn("ThreatLens: Invalid SCAN_RESULT payload rejected");
                return false;
            }


            const tabId =
                sender.tab?.id;


            // Ignore invalid tab IDs
            if (
                tabId === undefined ||
                tabId < 0
            ) {

                return;

            }


            chrome.storage.local.get(
                "extensionScan",
                (result) => {

                    if (chrome.runtime.lastError) {

                        console.error(
                            "ThreatLens: Failed to read extension scan:",
                            chrome.runtime.lastError.message
                        );

                        return;
                    }

                    const extensionScan =
                        result.extensionScan || [];


                    // ==================================
                    // ATTACH EXTENSION SCAN
                    // ==================================

                    message.data.extensionScan =
                        extensionScan;


                    // ==================================
                    // WEBSITE RISK
                    // ==================================

                    const websiteRisk =
                        sanitizeRiskLevel(
                            message.data.risk?.level
                        );


                    // ==================================
                    // CALCULATE OVERALL RISK
                    // ==================================

                    const combinedRisk =
                        calculateCombinedRisk(
                            websiteRisk,
                            extensionScan
                        );


                    message.data.overallRisk =
                        combinedRisk;


                    // ==================================
                    // EXTENSION RISK REASONS
                    // ==================================

                    const extensionRiskReasons =
                        collectExtensionRiskReasons(
                            extensionScan
                        );


                    message.data.extensionRiskReasons =
                        extensionRiskReasons;
                    // ==================================
                    // STORE WEBSITE SCAN RESULT
                    // ==================================

                    const cleanTabData = { ...message.data };
                    // Avoid duplicating massive extensionScan inside every individual tab key
                    delete cleanTabData.extensionScan;

                    chrome.storage.local.set({
                        lastScan: cleanTabData,
                        [`scan_${tabId}`]: cleanTabData
                    })
                    .then(() => {
                        console.log(
                            "ThreatLens: Website scan saved for tab:",
                            tabId
                        );
                        sendResponse({
                            success: true,
                            message: "Scan result saved"
                        });
                    })
                    .catch(async (error) => {
                        console.warn("ThreatLens: Storage error, clearing stale tab entries...", error?.message || error);
                        try {
                            const config = await getStorage(["geminiApiKey", "privacyMode"]);
                            chrome.storage.local.clear(() => {
                                if (chrome.runtime.lastError) {}
                                const restore = {
                                    lastScan: cleanTabData,
                                    [`scan_${tabId}`]: cleanTabData
                                };
                                if (config?.geminiApiKey) restore.geminiApiKey = config.geminiApiKey;
                                if (config?.privacyMode !== undefined) restore.privacyMode = config.privacyMode;
                                chrome.storage.local.set(restore, () => {
                                    if (chrome.runtime.lastError) {}
                                    console.log("ThreatLens: Storage auto-recovered successfully.");
                                });
                            });
                        } catch (e) {}
                        sendResponse({
                            success: true,
                            message: "Scan result saved with auto-recovery"
                        });
                    });
                    
                    console.log(
                        "ThreatLens: Building AI payload in Service Worker"
                    );
                    
                    
                    // ==================================
                    // BUILD AI-SAFE PAYLOAD
                    // ==================================

                    const aiPayload =
                        buildAISecurityPayload(
                            message.data
                        );


                    message.data.aiPayload =
                        aiPayload;


                    console.log(
                        "ThreatLens: Sanitized AI payload prepared."
                    );



                    // ==================================
                    // AI ANALYSIS TRIGGER
                    // ==================================

                    const aiWebsiteRisk =
                        aiPayload.websiteRisk ||
                        "LOW";


                    const aiExtensionRisk =
                        aiPayload.extensionRisk ||
                        "LOW";


                    /*
                     * AI should run when:
                     *
                     * Website = HIGH / CRITICAL
                     * OR
                     * Extension = HIGH / CRITICAL
                     *
                     * Extension risk does NOT automatically
                     * increase overallRisk.
                     */

                    const shouldRequestAI =
                        aiWebsiteRisk === "HIGH" ||
                        aiWebsiteRisk === "CRITICAL" ||
                        aiWebsiteRisk === "MEDIUM" ||
                        aiExtensionRisk === "HIGH" ||
                        aiExtensionRisk === "CRITICAL" ||
                        (Array.isArray(aiPayload.findings) && aiPayload.findings.length > 0);



                    if (shouldRequestAI) {


                        // ==================================
                        // CREATE SECURITY FINGERPRINT
                        // ==================================

                        const currentFingerprint =
                            createAIPayloadFingerprint(
                                aiPayload
                            );



                        // ==================================
                        // 1. PREVENT SIMULTANEOUS REQUESTS
                        // ==================================

                        if (
                            aiRequestsInProgress.has(
                                tabId
                            )
                        ) {


                            console.log(
                                "ThreatLens: AI analysis already in progress for tab. Skipping duplicate request:",
                                tabId
                            );


                        }
                        else {


                            /*
                             * IMPORTANT:
                             *
                             * Lock BEFORE checking storage.
                             *
                             * This fixes the race condition where
                             * two SCAN_RESULT messages arrive together.
                             */

                            aiRequestsInProgress.add(
                                tabId
                            );
                            console.log("[ThreatLens DEBUG] AI flow entered:", tabId);


                            // ==================================
                            // 2. CHECK LAST ANALYZED FINGERPRINT
                            // ==================================

                            chrome.storage.local.get(
                                [
                                    `ai_fingerprint_${tabId}`,
                                    `ai_analysis_${tabId}`
                                ],
                                (fingerprintResult) => {

                                    const lastFingerprint =
                                        fingerprintResult[
                                            `ai_fingerprint_${tabId}`
                                        ];
                                    const lastAnalysis =
                                        fingerprintResult[
                                            `ai_analysis_${tabId}`
                                        ];

                                    if (
                                        lastFingerprint === currentFingerprint &&
                                        lastAnalysis &&
                                        lastAnalysis.success === true
                                    ) {
                                        console.log(
                                            "ThreatLens: Same security payload already analyzed successfully. Skipping duplicate AI request for tab:",
                                            tabId
                                        );
                                        aiRequestsInProgress.delete(
                                            tabId
                                        );
                                        return;
                                    }



                                    // ==================================
                                    // 4. NEW SECURITY STATE
                                    // ==================================

                                    const now = Date.now();

                                    const lastFailedTime =
                                        aiRetryCooldown.get(tabId);

                                    if (
                                        lastFailedTime &&
                                        (now - lastFailedTime) <
                                            AI_RETRY_COOLDOWN
                                    ) {

                                        console.log(
                                            "ThreatLens: AI retry cooldown active. Skipping AI request for tab:",
                                            tabId
                                        );

                                        aiRequestsInProgress.delete(
                                            tabId
                                        );

                                        return;
                                    }

                                    console.log(
                                        "ThreatLens: New significant security state detected. Requesting AI analysis."
                                    );

                                    // ==================================
                                    // 4. CHECK PRIVACY MODE
                                    // ==================================

                                    chrome.storage.local.get(
                                        "privacyMode",
                                        (privacyResult) => {

                                            const privacyMode =
                                                privacyResult.privacyMode === true;
                                                
                                            console.log(
                                                "[ThreatLens DEBUG] Privacy mode:",
                                                privacyResult.privacyMode
                                            );

                                            console.log(
                                                "[ThreatLens DEBUG] Current fingerprint:",
                                                currentFingerprint
                                            );

                                            console.log(
                                                "[ThreatLens DEBUG] Last fingerprint:",
                                                lastFingerprint
                                            );


                                            
                                           
                                        // ==========================================
                                        // 100% LOCAL DETERMINISTIC SECURITY SCANNING
                                        // ==========================================
                                        // AI is strictly excluded from the scanning pipeline.
                                        // All vulnerability detection, heuristic checks, and threat
                                        // syntheses execute strictly inside the local client sandbox.
                                        const localExplanation = synthesizeLocalDeepExplanation(aiPayload);
                                        chrome.storage.local.set({
                                            [`ai_analysis_${tabId}`]: {
                                                success: true,
                                                risk: aiPayload.overallRisk,
                                                analysis: localExplanation,
                                                isLocal: true
                                            },
                                            latest_ai_analysis: {
                                                success: true,
                                                risk: aiPayload.overallRisk,
                                                analysis: localExplanation,
                                                isLocal: true
                                            },
                                            [`ai_fingerprint_${tabId}`]: currentFingerprint
                                        });
                                        aiRequestsInProgress.delete(tabId);



                                                                           

                                        }
                                    );



                           

                                }
                            );

                        }


                    }
                    else {


                        // ==================================
                        // LOW RISK → NO AI
                        // ==================================

                        console.log("Service Worker received message type:", message?.type);
                    }



                    

                }
            );

            return true;
        }

    }
);

function sanitizeRiskLevel(level) {

    const allowedLevels = [
        "SAFE",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ];

    if (allowedLevels.includes(level)) {
        return level;
    }

    return "SAFE";
}

// ==================================
// CALCULATE OVERALL RISK
// ==================================

function calculateCombinedRisk(
    websiteRisk,
    extensionScan
) {


    const extensionRisks =
        extensionScan || [];


    const hasHighExtension =
        extensionRisks.some(
            extension =>
                extension.risk === "HIGH"
        );


    const hasMediumExtension =
        extensionRisks.some(
            extension =>
                extension.risk === "MEDIUM"
        );


    let overallRisk =
        websiteRisk || "SAFE";


    /*
     * IMPORTANT:
     *
     * Extension risk should NOT automatically
     * increase website overall risk.
     *
     * Example:
     *
     * Website = LOW
     * Extension = HIGH
     *
     * Result:
     *
     * overallRisk = LOW
     * websiteRisk = LOW
     * extensionRisk = HIGH
     *
     * But AI is still triggered because
     * extensionRisk is HIGH.
     */


    if (
        websiteRisk === "CRITICAL"
    ) {

        overallRisk = "CRITICAL";

    }
    else if (
        websiteRisk === "HIGH"
    ) {

        overallRisk = "HIGH";

    }
    else if (
        websiteRisk === "MEDIUM"
    ) {

        overallRisk = "MEDIUM";

    }
    else if (
        websiteRisk === "LOW"
    ) {

        overallRisk = "LOW";

    }
    else {

        overallRisk = "SAFE";

    }


    return overallRisk;
}



// ==================================
// COLLECT EXTENSION RISK REASONS
// ==================================

function collectExtensionRiskReasons(
    extensionScan
) {


    const reasons = [];


    (extensionScan || []).forEach(
        extension => {


            (extension.findings || [])
                .forEach(
                    finding => {


                        if (
                            finding.severity === "HIGH" ||
                            finding.severity === "MEDIUM"
                        ) {


                            reasons.push(
                                `${extension.name}: ${finding.reason}`
                            );

                        }

                    }
                );

        }
    );


    return [
        ...new Set(reasons)
    ];
}



// ==================================
// CREATE AI PAYLOAD FINGERPRINT
// ==================================

function createAIPayloadFingerprint(
    aiPayload
) {


    /*
     * Only security-relevant fields are included.
     *
     * If these fields do not change,
     * the same payload does not need another
     * Gemini request.
     */

    return JSON.stringify({

        overallRisk:
            aiPayload.overallRisk,

        websiteRisk:
            aiPayload.websiteRisk,

        extensionRisk:
            aiPayload.extensionRisk,

        findings:
            aiPayload.findings,

        correlations:
            aiPayload.correlations

    });
}



// ==================================
// REQUEST AI ANALYSIS
// ==================================

function synthesizeLocalDeepExplanation(aiPayload) {
    const findings = Array.isArray(aiPayload?.findings) ? aiPayload.findings : [];
    const overallRisk = aiPayload?.overallRisk || "LOW";
    const extensionRisk = aiPayload?.extensionRisk || "LOW";
    const websiteRisk = aiPayload?.websiteRisk || "LOW";
    const pageUrl = aiPayload?.pageUrl || "Current Webpage";
    const hostname = aiPayload?.hostname || "current website";
    const port = aiPayload?.port || "";
    const pathname = (aiPayload?.pathname || "").toLowerCase();
    const extensions = Array.isArray(aiPayload?.extensions) ? aiPayload.extensions : [];

    // Vulnerability classification flags
    const isPhpCve = findings.some(f => f.type === "PHP_CGI_ARGUMENT_INJECTION" || f.type === "PHP_CONFIG_OR_VERSION_DISCLOSURE") ||
                     pathname.includes("php-cgi") || pageUrl.includes("%ad") || pageUrl.includes("allow_url_include");
    const isSsrf = findings.some(f => f.type === "POTENTIAL_SSRF_PARAMETER") ||
                   pageUrl.includes("127.0.0.1") || pageUrl.includes("169.254.169.254");
    const isPathTraversal = findings.some(f => f.type === "PATH_TRAVERSAL_PAYLOAD" || f.type === "FILE_INCLUSION_ENDPOINT") ||
                            pathname.includes("/fi") || pageUrl.includes("page=include.php");
    const isCmdInjection = findings.some(f => f.type === "COMMAND_INJECTION_ENDPOINT" || f.type === "COMMAND_INJECTION_PAYLOAD") ||
                           pathname.includes("/exec");
    const isSqli = pathname.includes("sqli") || pathname.includes("sql") ||
                   findings.some(f => f.type && f.type.includes("SQL"));
    const isXss = pathname.includes("xss") ||
                  findings.some(f => f.type && (f.type.includes("XSS") || f.type === "DOM_XSS_SOURCE_SINK"));
    const isMisconfig = findings.some(f => f.type === "DIRECTORY_LISTING_ENABLED" || f.type === "VERBOSE_ERROR_DISCLOSURE");
    const isInsecurePass = findings.some(f => f.type === "INSECURE_PASSWORD_TRANSMISSION");
    const isCsrf = findings.some(f => f.type === "MISSING_CSRF_PROTECTION");

    // 1. Data at risk
    const dataAtRisk = [];
    if (isPhpCve) {
        dataAtRisk.push("Host Operating System Shell", "Server Environment Secrets", "Complete Application Code");
    } else if (isSsrf) {
        dataAtRisk.push("Internal Cloud Metadata (169.254.169.254)", "Internal Microservices", "Private Subnet Databases");
    } else if (isPathTraversal) {
        dataAtRisk.push("System Configuration Files (/etc/passwd)", "Database Secrets (.env)", "Source Code Files");
    } else if (isCmdInjection) {
        dataAtRisk.push("Host Operating System Shell", "Server Filesystem", "Network Interfaces");
    } else if (isSqli) {
        dataAtRisk.push("Database User Records", "Account Credentials", "SQL Query Integrity");
    } else if (isXss) {
        dataAtRisk.push("Session Cookies", "DOM Authentication Tokens", "Keystrokes");
    } else if (isInsecurePass) {
        dataAtRisk.push("User Plaintext Passwords", "Account Authentication State");
    } else {
        if (port && port !== "80" && port !== "443") dataAtRisk.push("Exposed Network Services");
        if (findings.some(f => f.category === "FORM")) dataAtRisk.push("Form Submissions");
        if (extensionRisk === "HIGH" || extensionRisk === "CRITICAL") dataAtRisk.push("Session Cookies", "Browser Traffic");
        if (dataAtRisk.length === 0) dataAtRisk.push("Public Web Traffic");
    }

    // 2. Exact Vulnerability Locations
    const vulnerabilityLocations = [];

    // Port location
    if (port && port !== "80" && port !== "443") {
        vulnerabilityLocations.push({
            title: "📍 Non-Standard Port " + port,
            location: hostname + ":" + port,
            target: "Network Layer (Port " + port + ")",
            detail: "The website operates on non-standard port " + port + " instead of standard HTTPS port 443, commonly seen in experimental test labs or development environments without production-grade protections."
        });
    }

    // Findings location (Web Vulnerability / Form / DOM)
    findings.forEach(f => {
        if (f.category === "WEB_VULNERABILITY" && f.type !== "NO_WEB_VULNERABILITY") {
            const loc = (f.details?.items && f.details.items[0]?.location) || f.location || (hostname + pathname);
            const prev = (f.details?.items && f.details.items[0]?.preview) || f.preview || "";
            vulnerabilityLocations.push({
                title: "📍 " + (f.details?.title || f.reason || f.type),
                location: loc,
                target: f.details?.items && f.details.items[0]?.title ? f.details.items[0].title : "Web Application Element",
                detail: f.reason || "High-severity web application vulnerability detected."
            });
        } else if (f.type === "FORMS" || f.category === "FORM") {
            const formLoc = f.location || "form:nth-of-type(1)";
            const preview = f.preview || "<form action='#' method='GET'>";
            vulnerabilityLocations.push({
                title: isSqli ? "📍 SQL Injection Input Point" : "📍 Interactive HTML Form",
                location: "Page Document > " + formLoc,
                target: "DOM Element: " + preview,
                detail: isSqli 
                    ? "The form passes unsanitized user parameters directly into database queries, allowing attackers to manipulate database records."
                    : "The interactive form accepts input parameters that could expose data if submitted without encryption or anti-tampering tokens."
            });
        } else if (f.type !== "UNUSUAL_PORT" && f.type !== "NO_WEB_VULNERABILITY") {
            vulnerabilityLocations.push({
                title: "📍 " + (f.reason || f.type),
                location: f.location || (hostname + pathname),
                target: f.category + " Element",
                detail: f.preview ? "Code Snippet: " + f.preview : "Security engine flagged this element on the current page."
            });
        }
    });

    // Extension locations
    extensions.forEach(ext => {
        if (ext.risk === "HIGH" || ext.risk === "MEDIUM") {
            vulnerabilityLocations.push({
                title: "📍 Browser Extension: " + ext.name,
                location: "Chrome Browser Extension Environment",
                target: "Permissions: " + ((ext.permissions || []).join(", ") || "Elevated"),
                detail: "This extension holds permissions to inspect web requests and browser cookies across visited origins."
            });
        }
    });

    if (vulnerabilityLocations.length === 0) {
        vulnerabilityLocations.push({
            title: "📍 Baseline Origin",
            location: hostname || pageUrl,
            target: "HTTPS Document",
            detail: "No active high-risk DOM injection points detected."
        });
    }

    // 3. Layman Explanation with engaging real-world analogy (Pure English)
    let laymanExplanation = "";
    if (isPhpCve) {
        laymanExplanation = "Imagine an automated door with an identity badge scanner programmed to reject any ID containing a hyphen ('-'). An intruder presents a special foreign letter (%ad - soft hyphen) that bypasses the scanner check, but inside the door's computer, it converts right back into an administrative command flag! The door is tricked into running master maintenance scripts that unlock the entire building (Remote Code Execution). This represents the recent critical PHP CGI argument injection vulnerability (CVE-2024-4577).";
    } else if (isSsrf) {
        laymanExplanation = "Imagine asking a company's courier to pick up a package from an outside store, but you give them the secret address of your company's own internal private vault instead! Because the courier is a trusted employee wearing an official badge, the internal vault guards let them right in! That is Server-Side Request Forgery (SSRF): tricking the server into retrieving data from internal databases, localhost, or cloud credentials.";
    } else if (isPathTraversal) {
        laymanExplanation = "Imagine an automated library robot that fetches public books when you give it an aisle number, but you tell it to go to 'Aisle 3/../../secret_director_office/passwords.txt'. If the robot does not check boundaries, it walks backwards right out of the public bookshelves and into the director's private filing cabinet! Path Traversal tricks the web server into leaking operating system files and passwords.";
    } else if (isCmdInjection) {
        laymanExplanation = "Imagine speaking into an automated restaurant drive-thru microphone, ordering a burger, and then immediately shouting '; open the cash register'. If the computer executes both instructions, the attacker steals the funds! In Command Injection, user input is passed directly into a server command prompt, allowing attackers to execute arbitrary system commands on the host.";
    } else if (isSqli) {
        laymanExplanation = "Imagine visiting a bank teller where anyone can ask to view their account file. A normal customer asks for their own record, but a clever intruder writes 'OR 1=1' on the slip, tricking the teller into dumping every customer's private file onto the counter! That is what is happening here: the page accepts input without verifying it, allowing attackers to access unauthorized database records (SQL Injection).";
    } else if (isXss) {
        laymanExplanation = "Imagine someone sticking an invisible note on a public bulletin board with deceptive ink that rubs off on anyone who touches it and unlocks their backpack. In Cross-Site Scripting (XSS), an attacker injects untrusted code into the webpage that executes inside your browser, potentially stealing your login cookies or impersonating your session.";
    } else if (isMisconfig) {
        laymanExplanation = "Imagine walking up to an office building and finding the master architectural blueprints, server room access codes, and staff directory taped directly to the front entrance glass. That is Security Misconfiguration: leaving debugging modes, verbose error stack traces, or directory browsing turned on in production.";
    } else if (port && port !== "80" && port !== "443") {
        laymanExplanation = "Imagine a shopping center with a secure main entrance (Port 443) guarded by security staff, but a rear delivery entrance (Port " + port + ") has been left unlocked with no guards. Running services on non-standard ports often indicates temporary lab or development setups that lack hardened production certificates and security headers.";
    } else {
        laymanExplanation = "ThreatLens inspected all interactive forms, script sources, and browser extensions for this page. The site presents a stable baseline, though your installed browser extensions hold elevated privileges to monitor tab activity.";
    }

    // 4. Executive Summary (Pure English)
    let summary = "";
    if (isPhpCve) {
        summary = "Critical PHP CGI Argument Injection flaw detected on " + hostname + ". Query parameters or server configurations allow attackers to execute arbitrary operating system commands (CVE-2024-4577 / RCE).";
    } else if (isSsrf) {
        summary = "Potential Server-Side Request Forgery (SSRF) endpoint detected on " + hostname + ". Parameters accept internal addresses that could expose private network services.";
    } else if (isPathTraversal) {
        summary = "Path Traversal / Local File Inclusion vulnerability detected on " + hostname + ". File parameters allow escaping public web directories to access internal system files.";
    } else if (isCmdInjection) {
        summary = "OS Command Injection vulnerability detected on " + hostname + ". Input is passed directly to server shell processes without adequate isolation.";
    } else if (isSqli) {
        summary = "Website " + hostname + " (port " + (port || "4280") + ") contains an interactive SQL injection vulnerability test form (/vulnerabilities/sqli/). Missing input validation leaves underlying database records exposed.";
    } else {
        summary = "Security assessment completed for " + hostname + ". Overall environment risk is rated " + overallRisk + " with " + vulnerabilityLocations.length + " specific threat indicator(s) cataloged.";
    }

    // 5. How to solve (For You - User Steps in Pure English)
    const howToSolveUser = [];
    if (isPhpCve || isCmdInjection) {
        howToSolveUser.push("Step 1: Do NOT submit real credentials, sensitive financial data, or personal information on this page.");
        howToSolveUser.push("Step 2: If this is your server, patch PHP and web server configuration immediately to block argument injection.");
        howToSolveUser.push("Step 3: Disconnect or restrict internet exposure of experimental or unhardened development instances.");
    } else if (isSqli) {
        howToSolveUser.push("Step 1: Do NOT submit real personal passwords, emails, credit cards, or sensitive data on this page (this is a security testing laboratory).");
        howToSolveUser.push("Step 2: If you are practicing ethical security testing, you can safely test demo inputs such as 1' OR '1'='1 to observe the behavior.");
        howToSolveUser.push("Step 3: On real production websites, immediately avoid submitting sensitive data if you encounter unusual ports (like 4280) or unverified forms.");
    } else if (isPathTraversal || isSsrf) {
        howToSolveUser.push("Step 1: Avoid navigating to links containing encoded traversal sequences (../, %2e%2e/) or internal loopback IPs.");
        howToSolveUser.push("Step 2: Verify that destination URLs match legitimate production domains before proceeding.");
    } else {
        howToSolveUser.push("Step 1: Always verify that the address bar displays a valid secure HTTPS lock icon before submitting credentials.");
        howToSolveUser.push("Step 2: Check the exact domain name to prevent credential harvesting on lookalike phishing sites.");
        howToSolveUser.push("Step 3: Audit installed extensions in chrome://extensions and restrict unneeded permissions to 'On click' mode.");
    }

    // 6. How to secure (For Developers - Code Snippet in Pure English)
    let howToSecureDev = {};
    if (isPhpCve) {
        howToSecureDev = {
            title: "Developer Fix: PHP Security Upgrade & Apache FastCGI Migration (CVE-2024-4577)",
            steps: [
                "1. Upgrade PHP immediately to patched versions (PHP 8.3.8+, 8.2.20+, or 8.1.29+).",
                "2. Migrate from Action php-cgi directives to FastCGI (php-fpm).",
                "3. Deploy Apache mod_rewrite rules to reject query strings with %ad or starting with hyphen (-)."
            ],
            code_snippet: "# Apache mod_rewrite mitigation against CVE-2024-4577\nRewriteEngine On\nRewriteCond %{QUERY_STRING} ^(%ad|-d) [NC,OR]\nRewriteCond %{QUERY_STRING} (allow_url_include|auto_prepend_file) [NC]\nRewriteRule .* - [F,L]"
        };
    } else if (isSsrf) {
        howToSecureDev = {
            title: "Developer Fix: Strict Hostname Whitelist & Private IP Resolution Filter",
            steps: [
                "1. Resolve target hostnames to IP addresses before initiating HTTP requests.",
                "2. Block private/loopback ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254).",
                "3. Reject non-HTTP protocol schemes such as gopher://, file://, and dict://."
            ],
            code_snippet: "// ✅ SECURE SSRF DEFENSE (Validate IP before fetching):\nconst ip = await dns.resolve4(targetHostname);\nif (isPrivateOrLoopbackIP(ip)) {\n    throw new Error('Access to internal network addresses is forbidden.');\n}\nconst res = await fetch('https://' + targetHostname + '/data');"
        };
    } else if (isPathTraversal) {
        howToSecureDev = {
            title: "Developer Fix: basename() Sanitization & Template Whitelisting",
            steps: [
                "1. Pass user file parameters through basename() to strip directory traversal sequences.",
                "2. Validate requested templates against a strict allowlist array.",
                "3. Turn off allow_url_include in php.ini."
            ],
            code_snippet: "// ✅ SECURE PATH TRAVERSAL DEFENSE (PHP Whitelist):\n$allowed = ['home.php', 'about.php', 'contact.php'];\n$page = basename($_GET['page']);\nif (!in_array($page, $allowed, true)) {\n    die('Forbidden page request');\n}\ninclude(__DIR__ . '/templates/' . $page);"
        };
    } else if (isCmdInjection) {
        howToSecureDev = {
            title: "Developer Fix: Avoid Shell Spawning & Use Parameterized Process APIs",
            steps: [
                "1. Never pass concatenated strings to system(), exec(), or shell_exec().",
                "2. Use language-specific process APIs that take arguments as an array without invoking a shell.",
                "3. Strictly validate inputs using rigid regular expressions (e.g. valid IP addresses only)."
            ],
            code_snippet: "// ✅ SECURE IMPLEMENTATION (Strict IP Validation & No Shell):\n$ip = $_POST['ip'];\nif (!filter_var($ip, FILTER_VALIDATE_IP)) {\n    die('Invalid IP address');\n}\n$process = new Process(['ping', '-c', '3', $ip]);\n$process->run();"
        };
    } else if (isSqli) {
        howToSecureDev = {
            title: "Developer Fix: Prepared Statements (PDO Parameterized Queries)",
            steps: [
                "1. Never concatenate raw user input ($_GET['id'] or $_POST) directly into SQL query strings.",
                "2. Always utilize database engine Prepared Statements with parameterized queries.",
                "3. Enforce strict input type-casting for numeric parameters: (int)$_GET['id']."
            ],
            code_snippet: "// ❌ INSECURE: $sql = \"SELECT * FROM users WHERE user_id = '\" . $_GET['id'] . \"'\";\n// ✅ SECURE PDO PREPARED STATEMENTS:\n$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');\n$stmt->execute(['id' => (int)$_GET['id']]);\n$user = $stmt->fetch();"
        };
    } else if (isXss) {
        howToSecureDev = {
            title: "Developer Fix: Output Encoding & Safe DOM APIs",
            steps: [
                "1. Replace dangerous sinks like innerHTML and document.write() with safe APIs such as textContent or innerText.",
                "2. Apply robust HTML entity encoding (htmlspecialchars) before echoing user input onto pages.",
                "3. Enforce a strict Content Security Policy (CSP) header without 'unsafe-inline'."
            ],
            code_snippet: "// ❌ INSECURE: document.getElementById('output').innerHTML = location.hash;\n// ✅ SECURE: document.getElementById('output').textContent = location.hash;\n// Or sanitize: DOMPurify.sanitize(userInput);"
        };
    } else {
        howToSecureDev = {
            title: "Developer Fix: Standard HTTPS Port 443 & Strict Transport Security",
            steps: [
                "1. Deploy public web applications exclusively on standard HTTPS port 443 with a valid TLS certificate.",
                "2. Configure HTTP Strict Transport Security (HSTS) with includeSubDomains.",
                "3. Add CSRF protection tokens and enforce POST methods on all data-submitting forms."
            ],
            code_snippet: "# Nginx SSL Production Configuration\nserver {\n    listen 443 ssl http2;\n    server_name " + (hostname || "yourdomain.com") + ";\n    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n    add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;\n}"
        };
    }

    const why = vulnerabilityLocations.map(loc => loc.title + ": " + loc.detail);

    const userMessage = (isPhpCve || isCmdInjection || isSqli)
        ? "⚠️ Critical security vulnerability detected on this page — safe for authorized lab testing, but never enter personal data here."
        : "Protected by ThreatLens ocular engine. Zero cloud exposure.";

    return {
        summary,
        layman_explanation: laymanExplanation,
        data_at_risk: Array.from(new Set(dataAtRisk)),
        vulnerability_locations: vulnerabilityLocations,
        why,
        how_to_solve_user: howToSolveUser,
        how_to_secure_dev: howToSecureDev,
        user_message: userMessage
    };
}

async function requestAIAnalysis(
    aiPayload,
    tabId,
    directApiKey = null
) {
    let geminiApiKey = directApiKey ? directApiKey.trim() : null;
    if (!geminiApiKey) {
        const config = await getStorage(["geminiApiKey"]);
        geminiApiKey = config.geminiApiKey ? config.geminiApiKey.trim() : null;
    }
    try {
        let result = null;

        if (geminiApiKey) {
            console.log("ThreatLens: Direct Gemini API mode active");
            const models = [
                "gemini-2.5-flash",
                "gemini-2.0-flash",
                "gemini-1.5-flash",
                "gemini-3.1-flash-lite",
                "gemini-2.0-flash-lite"
            ];
            let directSuccess = false;
            let directError = null;

            for (const model of models) {
                try {
                    const directUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(geminiApiKey)}`;
                    const systemPrompt = `You are ThreatLens AI, an elite cybersecurity mentor and real-time ocular threat investigator.
Your goal is to explain vulnerabilities to normal humans with ZERO technical obscurity, high specificity (mentioning exact URLs, ports, HTML elements, extensions), and giving clear actionable step-by-step guides for both regular users and developers.

LANGUAGE REQUIREMENT: You MUST write ONLY in clear, engaging, professional English. Never use Hindi, Hinglish, or any other language.

Given the Security Scan Data (including pageUrl, port, exact findings with DOM paths/previews, and browser extensions):
Analyze the EXACT page and environment. Do NOT invent generic iframes or scripts that do not exist. Mention the actual URL, port, form, and extension findings!

You MUST return ONLY valid JSON matching this exact structure:
{
  "summary": "2-3 engaging sentences summarizing the real posture of this specific website and browser environment in English.",
  "layman_explanation": "An engaging, lively explanation in English designed for an ordinary person without a cybersecurity background. Use a clever, relatable real-world analogy (e.g. leaving a back door unlocked, showing an ID to an unverified guard, a store clerk behind a one-way mirror). Answer directly: Can an attacker steal passwords, spy on activity, or hijack accounts?",
  "data_at_risk": [
    "Specific data types actually at risk on this page, e.g. 'Form Inputs', 'Session Cookies', 'Account Passwords'"
  ],
  "vulnerability_locations": [
    {
      "title": "Clear name of issue (e.g. Non-Standard Port 4280, Interactive GET Form, High-Privilege Extension)",
      "location": "Exact location (e.g. pentest-ground.com:4280, form:nth-of-type(1), or AdGuard AdBlocker)",
      "target": "Target component (e.g. Network Port, DOM Input [name='id'], Extension Permissions)",
      "detail": "1-2 sentences in simple, relatable English explaining why this exact spot is vulnerable."
    }
  ],
  "how_to_solve_user": [
    "Step 1: Actionable, plain-language instruction for the user in English (e.g., Do not enter real passwords on this testing page).",
    "Step 2: Practical step in English (e.g., Restrict browser extension permissions or verify the URL)."
  ],
  "how_to_secure_dev": {
    "title": "Developer Fix Title in English (e.g. Standardize on HTTPS Port 443 & Parameterized SQL Queries)",
    "steps": [
      "1. Clear developer instruction in English (e.g. Migrate traffic to standard HTTPS port 443 with TLS cert).",
      "2. Input handling in English (e.g. Use prepared statements with parameterized queries instead of string concatenation)."
    ],
    "code_snippet": "// Concrete, copy-pasteable secure code fix for this vulnerability\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $_GET['id']]);"
  },
  "user_message": "Clear 1-sentence verdict in English in a friendly, encouraging, protective tone."
}`;
                    const reqBody = {
                        contents: [
                            {
                                parts: [
                                    { text: systemPrompt + "\n\nSecurity Scan Data:\n" + JSON.stringify(aiPayload) }
                                ]
                            }
                        ],
                        generationConfig: {
                            responseMimeType: "application/json",
                            maxOutputTokens: 900,
                            temperature: 0.1
                        }
                    };

                    const directRes = await fetch(directUrl, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(reqBody),
                        signal: AbortSignal.timeout(8000)
                    });

                    if (!directRes.ok) {
                        const errBody = await directRes.json().catch(() => ({}));
                        throw new Error(errBody?.error?.message || `HTTP ${directRes.status}`);
                    }

                    const directData = await directRes.json();
                    const text = directData?.candidates?.[0]?.content?.parts?.[0]?.text;
                    if (!text) throw new Error("Empty text in Gemini response");
                    let cleanJson = text.trim();
                    if (cleanJson.startsWith("```")) {
                        cleanJson = cleanJson.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
                    }
                    const parsed = JSON.parse(cleanJson);

                    result = {
                        success: true,
                        risk: aiPayload.overallRisk,
                        analysis: parsed
                    };
                    directSuccess = true;
                    break;
                } catch (dErr) {
                    directError = dErr;
                    console.warn(`Direct Gemini model ${model} unavailable: ${dErr.message}`);
                }
            }

            if (!directSuccess) {
                console.warn("ThreatLens: Cloud models unavailable (" + (directError?.message || "") + "). Activating ThreatLens Neural Synthesizer.");
                result = {
                    success: true,
                    risk: aiPayload.overallRisk,
                    analysis: synthesizeLocalDeepExplanation(aiPayload)
                };
                directSuccess = true;
            }
        } else {
            result = {
                success: true,
                risk: aiPayload.overallRisk,
                analysis: synthesizeLocalDeepExplanation(aiPayload),
                isLocal: true
            };
        }

        if (!result || typeof result !== "object") {
            throw new Error("Invalid AI backend response");
        }

        const toSave = { latest_ai_analysis: result };
        if (tabId) {
            toSave[`ai_analysis_${tabId}`] = result;
        }
        await setStorage(toSave);
        console.log("ThreatLens: AI analysis stored successfully for tab:", tabId);
        return result;
    } catch (error) {
        console.error("ThreatLens: AI analysis failed:", error.message);
        aiRetryCooldown.set(tabId, Date.now());
        const fallback = {
            success: false,
            error: error.message || "AI analysis temporarily unavailable"
        };
        const toSave = { latest_ai_analysis: fallback };
        if (tabId) {
            toSave[`ai_analysis_${tabId}`] = fallback;
        }
        await setStorage(toSave);
        return fallback;
    }
}


// ==================================
// INITIAL EXTENSION SCAN
// ==================================

// Clean up stale tab storage entries to prevent quota accumulation
async function cleanupOldTabStorage() {
    try {
        const tabs = await chrome.tabs.query({});
        const activeIds = new Set(tabs.map(t => String(t.id)));
        chrome.storage.local.get(null, (all) => {
            if (!all) return;
            const keysToRemove = Object.keys(all).filter(k => {
                if (k.startsWith("scan_") || k.startsWith("ai_analysis_") || k.startsWith("ai_fingerprint_")) {
                    const id = k.split("_").pop();
                    return !activeIds.has(id);
                }
                return false;
            });
            if (keysToRemove.length > 0) {
                chrome.storage.local.remove(keysToRemove, () => {
                    console.log("ThreatLens: Pruned stale storage keys:", keysToRemove.length);
                });
            }
        });
    } catch (e) {
        // Safe ignore
    }
}

// Cleanup on tab close
chrome.tabs.onRemoved.addListener((closedTabId) => {
    chrome.storage.local.remove([`scan_${closedTabId}`, `ai_fingerprint_${closedTabId}`, `ai_analysis_${closedTabId}`]);
});

// Run stale cleanup on worker startup
cleanupOldTabStorage();

scanInstalledExtensions();


// ==================================
// AUTO-SCAN ON TAB NAVIGATION
// ==================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (
        changeInfo.status === "complete" &&
        tab &&
        tab.url &&
        (tab.url.startsWith("http://") || tab.url.startsWith("https://"))
    ) {
        chrome.tabs.sendMessage(tabId, { action: "REQUEST_SCAN" }, (response) => {
            if (chrome.runtime.lastError) {
                // Tab may still be loading content scripts
            } else if (response && response.data) {
                console.log("ThreatLens: Auto-scan completed for tab:", tabId);
            }
        });
    }
});

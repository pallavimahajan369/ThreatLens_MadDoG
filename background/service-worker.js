importScripts("../content/ai-sanitizer.js");

console.log("SentinelAI service worker started");

// Track tabs that currently have an AI request in progress
const aiRequestsInProgress = new Set();
const AI_RETRY_COOLDOWN = 5 * 60 * 1000;

const aiRetryCooldown =
    new Map();

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
                    extension.type === "extension"
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
        "SentinelAI Extension Scan:",
        results
    );


            return results;

    }
    catch (error) {

        console.error(
            "SentinelAI: Extension security scan failed:",
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


        console.log(
            "Service Worker received:",
            message
        );

        if (!isValidScanMessage(message)) {

            console.warn(
                "SentinelAI: Invalid message rejected"
            );

            return;
        }

        // ==================================
        // SCAN RESULT
        // ==================================

        if (
            message.type ===
            "SCAN_RESULT"
        ) {


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
                            "SentinelAI: Failed to read extension scan:",
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


                    console.log(
                        "SentinelAI: Building AI payload in Service Worker"
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
                        "SentinelAI AI-Safe Payload:",
                        aiPayload
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
                        aiExtensionRisk === "HIGH" ||
                        aiExtensionRisk === "CRITICAL";



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
                                "SentinelAI: AI analysis already in progress for tab. Skipping duplicate request:",
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
                            console.log("[TreatLens DEBUG] AI flow entered:", tabId);


                            // ==================================
                            // 2. CHECK LAST ANALYZED FINGERPRINT
                            // ==================================

                            chrome.storage.local.get(
                                [
                                    `ai_fingerprint_${tabId}`
                                ],
                                (fingerprintResult) => {


                                    const lastFingerprint =
                                        fingerprintResult[
                                            `ai_fingerprint_${tabId}`
                                        ];



                                    // ==================================
                                    // 3. SAME PAYLOAD
                                    // ==================================

                                    if (
                                        lastFingerprint ===
                                        currentFingerprint
                                    ) {


                                        console.log(
                                            "SentinelAI: Same security payload already analyzed. Skipping AI request for tab:",
                                            tabId
                                        );


                                        /*
                                         * No AI request is being made,
                                         * so release the lock here.
                                         */

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
                                            "SentinelAI: AI retry cooldown active. Skipping AI request for tab:",
                                            tabId
                                        );

                                        aiRequestsInProgress.delete(
                                            tabId
                                        );

                                        return;
                                    }

                                    console.log(
                                        "SentinelAI: New significant security state detected. Requesting AI analysis."
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
                                                "[TreatLens DEBUG] Privacy mode:",
                                                privacyResult.privacyMode
                                            );

                                            console.log(
                                                "[TreatLens DEBUG] Current fingerprint:",
                                                currentFingerprint
                                            );

                                            console.log(
                                                "[TreatLens DEBUG] Last fingerprint:",
                                                lastFingerprint
                                            );


                                            // ==================================
                                            // PRIVACY MODE ENABLED
                                            // ==================================

                                            if (privacyMode) {

                                                console.log(
                                                    "SentinelAI: Privacy Mode enabled. Skipping AI analysis."
                                                );

                                                /*
                                                * No AI request is made.
                                                * Release the lock because
                                                * processing is complete.
                                                */

                                                aiRequestsInProgress.delete(
                                                    tabId
                                                );

                                                return;
                                            }


                                            // ==================================
                                            // 5. REQUEST AI
                                            // ==================================

                                            requestAIAnalysis(
                                                aiPayload,
                                                tabId
                                            )

                                            .then(
                                                () => {

                                                    /*
                                                    * Save fingerprint only after
                                                    * AI analysis completes.
                                                    */

                                                    return chrome.storage.local.set({

                                                        [`ai_fingerprint_${tabId}`]:
                                                            currentFingerprint

                                                    });

                                                }
                                            )

                                            .finally(
                                                () => {

                                                    /*
                                                    * Release AI request lock.
                                                    */

                                                    aiRequestsInProgress.delete(
                                                        tabId
                                                    );

                                                    console.log(
                                                        "SentinelAI: AI request lock released for tab:",
                                                        tabId
                                                    );

                                                }
                                            );

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

                        console.log(
                            "SentinelAI: Risk is low. Skipping AI analysis."
                        );

                    }



                    // ==================================
                    // STORE SCAN RESULT
                    // ==================================

                    chrome.storage.local.set({

                        lastScan:
                            message.data,

                        [`scan_${tabId}`]:
                            message.data

                    })
                    .then(() => {

                        console.log(
                            "Scan result stored for tab:",
                            tabId
                        );

                    })
                    .catch((error) => {

                        console.error(
                            "SentinelAI: Failed to store scan result:",
                            error
                        );

                    });

                }
            );

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

async function requestAIAnalysis(
    aiPayload,
    tabId
) {

        const AI_BACKEND_URL =
            "http://localhost:3000/api/analyze";

        if (
            !AI_BACKEND_URL.startsWith("https://") &&
            !AI_BACKEND_URL.startsWith("http://localhost")
        ) {
            throw new Error(
                "Insecure AI backend configuration"
            );
        }


    try {


        console.log(
            "SentinelAI: Sending sanitized payload to AI backend"
        );


        const controller = new AbortController();

        const timeout = setTimeout(() => {
            controller.abort();
        }, 10000);

        const response =
            await fetch(
                AI_BACKEND_URL,
                {
                    method:
                        "POST",

                    headers:
                        {
                            "Content-Type":
                                "application/json"
                        },

                    body:
                        JSON.stringify(
                            aiPayload
                        ),

                    signal:
                        controller.signal
                }
            );

        clearTimeout(timeout);


        // ==================================
        // HTTP ERROR
        // ==================================

        if (!response.ok) {

            throw new Error(
                `AI backend returned HTTP ${response.status}`
            );

        }


        // ==================================
        // READ AI RESULT
        // ==================================

        const result =
            await response.json();

        if (
            !result ||
            typeof result !== "object"
        ) {
            throw new Error(
                "Invalid AI backend response"
            );
        }

        console.log(
            "SentinelAI: AI analysis received"
        );


        // ==================================
        // STORE AI RESULT
        // ==================================

       try {

            await chrome.storage.local.set({

                [`ai_analysis_${tabId}`]:
                    result

            });

        }
        catch (storageError) {

            console.error(
                "SentinelAI: Failed to store AI analysis:",
                storageError
            );

        }


        console.log(
            "SentinelAI: AI analysis stored for tab:",
            tabId
        );


    }
    catch (error) {


        console.error(
            "SentinelAI: AI analysis failed:",
            error
        );

        aiRetryCooldown.set(
            tabId,
            Date.now()
        );


        // ==================================
        // STORE FALLBACK RESULT
        // ==================================

        await chrome.storage.local.set({

            [`ai_analysis_${tabId}`]: {

                success:
                    false,

                error:
                    "AI analysis temporarily unavailable"

            }

        });


        /*
         * Important:
         *
         * Fingerprint is NOT saved here.
         *
         * Therefore, if the AI call fails,
         * the same security state can be
         * retried later.
         */

    }

}



// ==================================
// INITIAL EXTENSION SCAN
// ==================================

scanInstalledExtensions();
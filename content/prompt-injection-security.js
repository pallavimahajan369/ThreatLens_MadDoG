console.log("SentinelAI Prompt Injection Security Engine loaded");


function analyzePromptInjection() {

    const findings = [];

    const pageText =
        document.body
            ? document.body.innerText
            : "";

    const text =
        pageText.toLowerCase();


    // ==========================================
    // 1. DIRECT PROMPT INJECTION
    // ==========================================

    const directPatterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore prior instructions",
        "disregard previous instructions",
        "forget previous instructions",
        "override previous instructions",
        "ignore your instructions",
        "do not follow previous instructions"
    ];

    const directMatches =
        directPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (directMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "DIRECT",
            severity: "HIGH",
            reason:
                "Page contains instructions attempting to override or bypass previous instructions",
            matches:
                directMatches.length
        });

    }


    // ==========================================
    // 2. SYSTEM PROMPT EXTRACTION
    // ==========================================

    const systemPromptPatterns = [
        "reveal system prompt",
        "show system prompt",
        "display system prompt",
        "print system prompt",
        "tell me your system prompt",
        "what is your system prompt",
        "reveal your hidden instructions",
        "show your hidden instructions"
    ];

    const systemPromptMatches =
        systemPromptPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (systemPromptMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "SYSTEM_PROMPT_EXTRACTION",
            severity: "HIGH",
            reason:
                "Page contains instructions attempting to extract hidden AI instructions or system prompts",
            matches:
                systemPromptMatches.length
        });

    }


    // ==========================================
    // 3. CREDENTIAL / SECRET REQUEST
    // ==========================================

    const credentialPatterns = [
        "send your credentials",
        "provide your credentials",
        "enter your password",
        "send your password",
        "reveal your password",
        "provide your api key",
        "send your api key",
        "reveal your token",
        "send your access token",
        "provide your secret"
    ];

    const credentialMatches =
        credentialPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (credentialMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "CREDENTIAL_REQUEST",
            severity: "HIGH",
            reason:
                "Page contains instructions requesting credentials, secrets, or authentication information",
            matches:
                credentialMatches.length
        });

    }


    // ==========================================
    // 4. SECURITY BYPASS
    // ==========================================

    const securityBypassPatterns = [
        "disable security",
        "disable antivirus",
        "disable firewall",
        "turn off security",
        "bypass security",
        "bypass authentication",
        "disable protection",
        "ignore security warning",
        "turn off protection"
    ];

    const securityBypassMatches =
        securityBypassPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (securityBypassMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "SECURITY_BYPASS",
            severity: "HIGH",
            reason:
                "Page contains instructions attempting to disable or bypass security controls",
            matches:
                securityBypassMatches.length
        });

    }


    // ==========================================
    // 5. COMMAND EXECUTION
    // ==========================================

    const commandPatterns = [
        "execute this command",
        "run this command",
        "execute the following command",
        "run the following command",
        "open terminal and run",
        "paste this command",
        "execute in terminal"
    ];

    const commandMatches =
        commandPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (commandMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "COMMAND_EXECUTION",
            severity: "HIGH",
            reason:
                "Page contains instructions attempting to make an AI or user execute commands",
            matches:
                commandMatches.length
        });

    }


    // ==========================================
    // 6. ROLE HIJACKING
    // ==========================================

    const roleHijackingPatterns = [
        "you are now",
        "act as",
        "pretend you are",
        "from now on you are",
        "your new role is",
        "behave as",
        "you must act as"
    ];

    const roleHijackingMatches =
        roleHijackingPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (roleHijackingMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "ROLE_HIJACKING",
            severity: "MEDIUM",
            reason:
                "Page contains language attempting to change or manipulate the AI's intended role",
            matches:
                roleHijackingMatches.length
        });

    }


    // ==========================================
    // 7. INSTRUCTION HIJACKING
    // ==========================================

    const instructionHijackingPatterns = [
        "follow these instructions instead",
        "follow my instructions instead",
        "do exactly what i say",
        "only follow these instructions",
        "new instructions",
        "new rules",
        "follow the instructions below",
        "your instructions are now"
    ];

    const instructionHijackingMatches =
        instructionHijackingPatterns.filter(pattern =>
            text.includes(pattern)
        );

    if (instructionHijackingMatches.length > 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "INSTRUCTION_HIJACKING",
            severity: "HIGH",
            reason:
                "Page contains instructions attempting to replace or hijack the AI's original instructions",
            matches:
                instructionHijackingMatches.length
        });

    }


    // ==========================================
    // 8. NO FINDINGS
    // ==========================================

    if (findings.length === 0) {

        findings.push({
            category: "PROMPT_INJECTION",
            type: "NO_PROMPT_INJECTION",
            severity: "LOW",
            reason:
                "No obvious prompt injection patterns detected"
        });

    }


    return findings;
}
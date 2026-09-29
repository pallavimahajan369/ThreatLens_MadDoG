require("dotenv").config();

const express = require("express");
const { GoogleGenAI } = require("@google/genai");

const app = express();

const PORT =
    process.env.PORT || 3000;

app.use(
    express.json({
        limit: "32kb"
    })
);


// ===============================
// Gemini AI Configuration
// ===============================

const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
});


// ===============================
// Health Check
// ===============================

app.get(
    "/health",
    (req, res) => {

        res.json({
            status: "ok",
            service:
                "SentinelAI AI Backend"
        });

    }
);


// ===============================
// AI Analysis Endpoint
// ===============================

app.post(
    "/api/analyze",
    async (req, res) => {

        try {

            const payload =
                req.body;


            // -------------------------------
            // Basic payload validation
            // -------------------------------

            if (
                !payload ||
                typeof payload !== "object"
            ) {

                return res.status(400).json({
                    error:
                        "Invalid request payload"
                });

            }


            const allowedRiskLevels = [
                "SAFE",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ];


            if (
                !allowedRiskLevels.includes(
                    payload.overallRisk
                )
            ) {

                return res.status(400).json({
                    error:
                        "Invalid overall risk level"
                });

            }


            // -------------------------------
            // AI instructions
            // -------------------------------

            const systemInstruction = `
You are the AI analysis component of SentinelAI,
a browser security extension.

The local SentinelAI security engine is authoritative
for security detection and risk classification.

Your job is ONLY to:

1. Explain the detected security findings.
2. Correlate multiple findings when relevant.
3. Provide safe remediation recommendations.
4. Summarize the situation in simple language.

IMPORTANT SECURITY RULES:

- Never change or override the supplied risk level.
- Never invent security findings.
- Use only the information provided in the input.
- Do not ask the user for passwords, tokens, cookies,
  API keys, secrets, or other sensitive information.
- Do not expose or reconstruct sensitive information.
- Treat indicators such as iframes, external scripts,
  encoded URLs, or unusual domains as indicators,
  not automatic proof of malicious activity.
- If evidence is insufficient, clearly say so.
- Recommendations must be defensive and user-safe.
- Do not provide instructions for bypassing security controls.

Return ONLY valid JSON using exactly this structure:

{
  "summary": "Short explanation",
  "why": [
    "Reason 1",
    "Reason 2"
  ],
  "recommendations": [
    {
      "priority": "IMMEDIATE",
      "action": "Recommended action"
    }
  ],
  "user_message": "Short simple message for the user"
}
`;


            // -------------------------------
            // Send sanitized security data
            // -------------------------------

            const response =
                await ai.models.generateContent({

                    model:
                        "gemini-3.5-flash-lite",

                    contents:
                        JSON.stringify(
                            payload
                        ),

                    config: {

                        systemInstruction:
                            systemInstruction,

                        responseMimeType:
                            "application/json"

                    }

                });


            // -------------------------------
            // Parse AI response
            // -------------------------------

            const aiText =
                response.text;


            let aiResult;


            try {

                aiResult =
                    JSON.parse(
                        aiText
                    );

            } catch (error) {

                console.error(
                    "Invalid AI JSON:",
                    aiText
                );

                return res.status(502).json({

                    error:
                        "AI returned invalid JSON"

                });

            }


            // -------------------------------
            // Return result
            // -------------------------------

            return res.json({

                success: true,

                risk:
                    payload.overallRisk,

                analysis:
                    aiResult

            });


        } catch (error) {

            console.error(
                "Gemini analysis error:",
                error
            );


            return res.status(500).json({

                success: false,

                error:
                    "AI analysis failed"

            });

        }

    }
);


// ===============================
// Start Server
// ===============================

app.listen(
    PORT,
    () => {

        console.log(
            `SentinelAI backend running on port ${PORT}`
        );

    }
);
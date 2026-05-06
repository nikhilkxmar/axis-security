const { z } = require("zod");
const { GoogleGenAI } = require("@google/genai");
const { config } = require("../config");
const { createLogger } = require("../logger");

const logger = createLogger();

const AiAnalysisSchema = z
  .object({
    classification: z.enum(["TRUE POSITIVE", "FALSE POSITIVE"]),
    reasoning: z.string().min(1),
    exploit: z.string().min(1),
    fix: z.string().min(1),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    confidence: z.coerce.number().int().min(0).max(100)
  })
  .strict();

function buildAiJsonSchema() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      classification: {
        type: "string",
        enum: ["TRUE POSITIVE", "FALSE POSITIVE"]
      },
      reasoning: { type: "string" },
      exploit: { type: "string" },
      fix: { type: "string" },
      severity: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
      confidence: { type: "integer", minimum: 0, maximum: 100 }
    },
    required: ["classification", "reasoning", "exploit", "fix", "severity", "confidence"]
  };
}

function toPromptText({ findings, contexts, diffMeta }) {
  const safeFindings = {
    semgrep: findings?.semgrep || null,
    gitleaks: findings?.gitleaks
      ? {
          ...findings.gitleaks,
          results: (findings.gitleaks.results || []).map((r) => ({
            ...r,
            secret: r?.secret ? "[REDACTED]" : r?.secret
          }))
        }
      : null,
    npmAudit: findings?.npmAudit || null
  };

  const contextForPrompt = contexts || [];

  return JSON.stringify(
    {
      instructions: {
        goal: "Classify findings as TRUE POSITIVE or FALSE POSITIVE with security risk and remediation.",
        enforce_schema: true
      },
      diffMeta: diffMeta || null,
      findings: safeFindings,
      codeContext: contextForPrompt
    },
    null,
    2
  );
}

async function analyzeWithAi({ scanId, findings, contexts, diffMeta }) {
  const client = new GoogleGenAI({ apiKey: config.GEMINI_API_KEY });

  const systemPrompt = [
    "You are a Senior Application Security Engineer.",
    "You will be given: (1) security scanner findings, and (2) surrounding code context for flagged locations.",
    "Your job is to determine whether each finding is a real exploitable security issue (TRUE POSITIVE) or a false positive (FALSE POSITIVE).",
    "Return ONLY valid JSON matching the schema.",
    "Safety: Do not include secrets or environment variable values. Do not hallucinate repository-specific facts not supported by the code context.",
    `Required JSON schema: ${JSON.stringify(buildAiJsonSchema())}`
  ].join("\n");

  const userPrompt = toPromptText({ findings, contexts, diffMeta });

  const requestPayloadBytes = Buffer.byteLength(userPrompt, "utf8");
  logger.info(
    { scanId, contextCount: (contexts || []).length, payloadBytes: requestPayloadBytes },
    "ai request"
  );

  for (let attempt = 1; attempt <= 2; attempt++) {
    const prompt = [
      `SYSTEM INSTRUCTIONS:\n${systemPrompt}`,
      "",
      "USER INPUT:",
      attempt === 1
        ? userPrompt
        : `${userPrompt}\n\nIMPORTANT: Your previous output did not match the required JSON schema. Re-evaluate and output valid JSON only.`
    ].join("\n");

    const resp = await client.models.generateContent({
      model: config.GEMINI_MODEL,
      contents: prompt,
      config: {
        temperature: 0,
        responseMimeType: "application/json"
      }
    });

    const content = resp?.text;
    if (!content) {
      logger.warn({ scanId, attempt }, "ai response missing content");
      continue;
    }

    try {
      const parsed = JSON.parse(content);
      const validated = AiAnalysisSchema.parse(parsed);
      logger.info(
        { scanId, classification: validated.classification, severity: validated.severity, confidence: validated.confidence },
        "ai output validated"
      );
      return validated;
    } catch (err) {
      logger.warn({ scanId, attempt, err, contentPreview: String(content).slice(0, 200) }, "invalid ai output json");
    }
  }

  throw new Error("AI analysis failed to produce valid structured JSON after retries");
}

module.exports = { analyzeWithAi };


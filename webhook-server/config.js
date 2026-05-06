const { z } = require("zod");

const ConfigSchema = z.object({
  NODE_ENV: z.string().optional().default("development"),
  PORT: z.coerce.number().int().positive().default(3000),

  REDIS_HOST: z.string().default("redis"),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().nonnegative().optional().default(0),

  QUEUE_NAME: z.string().default("axis-security-gate"),

  GITHUB_SECRET: z.string().min(1),
  GITHUB_TOKEN: z.string().min(1),
  GEMINI_API_KEY: z.string().min(1),

  GEMINI_MODEL: z.string().default("gemini-2.5-flash"),
  AI_MAX_CONTEXT_CHARS: z.coerce.number().int().positive().default(12000),

  SEMGREP_CONFIG: z.string().default("p/default"),
  SEMGREP_TIMEOUT_MS: z.coerce.number().int().positive().default(180000),
  GITLEAKS_TIMEOUT_MS: z.coerce.number().int().positive().default(180000),
  NPM_AUDIT_TIMEOUT_MS: z.coerce.number().int().positive().default(120000),

  CONTEXT_WINDOW_LINES: z.coerce.number().int().positive().default(10),
  MAX_SEMGREP_FINDINGS: z.coerce.number().int().positive().default(25),
  MAX_GITLEAKS_FINDINGS: z.coerce.number().int().positive().default(25),
  MAX_NPM_AUDIT_FINDINGS: z.coerce.number().int().positive().default(25),

  BLOCK_CONFIDENCE_THRESHOLD: z.coerce.number().int().min(0).max(100).default(80),

  GITHUB_CONTEXT: z.string().default("axis-security"),
  COMMENT_MARKER: z
    .string()
    .default("<!-- axis-security-gatekeeper-v2 -->")
});

const config = ConfigSchema.parse(process.env);

module.exports = { config };


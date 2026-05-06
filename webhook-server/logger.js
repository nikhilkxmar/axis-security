const pino = require("pino");

function createLogger() {
  const level = process.env.LOG_LEVEL || "info";

  return pino({
    level,
    redact: {
      paths: [
        "req.headers.authorization",
        "req.headers.Authorization",
        "req.headers['x-hub-signature-256']",
        "req.headers['X-Hub-Signature-256']",
        "err.stack",
        "err.cause",
        "env.GITHUB_SECRET",
        "env.GITHUB_TOKEN",
        "env.OPENAI_API_KEY",
        "env.GEMINI_API_KEY",
      ],
      remove: false
    },
    base: undefined
  });
}

module.exports = { createLogger };


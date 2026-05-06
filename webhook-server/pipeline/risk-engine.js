const { config } = require("../config");

function decideRisk(aiOutput) {
  const classification = aiOutput?.classification;
  const severity = aiOutput?.severity;
  const confidence = Number(aiOutput?.confidence ?? 0);

  const matchesPolicy =
    classification === "TRUE POSITIVE" &&
    (severity === "HIGH" || severity === "CRITICAL") &&
    confidence > config.BLOCK_CONFIDENCE_THRESHOLD;

  if (matchesPolicy) {
    return {
      state: "failure",
      decision: "BLOCK",
      description: `Blocked by Axis policy: ${severity} TRUE POSITIVE with ${confidence}% confidence (> ${config.BLOCK_CONFIDENCE_THRESHOLD}%).`
    };
  }

  return {
    state: "success",
    decision: "ALLOW",
    description:
      "Allowed by Axis policy: either FALSE POSITIVE, LOW severity, or confidence below threshold."
  };
}

module.exports = { decideRisk };


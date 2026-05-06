const { Octokit } = require("@octokit/rest");
const { config } = require("../config");
const { createLogger } = require("../logger");

const logger = createLogger();

function createOctokit() {
  return new Octokit({
    auth: config.GITHUB_TOKEN,
    userAgent: "axis-security-gatekeeper-v2"
  });
}

async function withRetry(fn, { retries = 4, scanId, operation }) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = err?.status || err?.response?.status;
      const retryAfterHeader =
        err?.response?.headers?.["retry-after"] || err?.response?.headers?.["Retry-After"];
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;

      const retryable =
        status === 403 ||
        status === 429 ||
        status === 500 ||
        status === 502 ||
        status === 503 ||
        status === 504;

      if (!retryable || attempt === retries) {
        logger.error(
          { scanId, operation, attempt, status, err },
          "github operation failed (non-retryable or last attempt)"
        );
        throw err;
      }

      const backoffMs = Math.min(60_000, 1000 * Math.pow(2, attempt - 1)) + (retryAfterSeconds ? retryAfterSeconds * 1000 : 0);
      logger.warn(
        { scanId, operation, attempt, status, backoffMs },
        "github request retrying"
      );
      await new Promise((r) => setTimeout(r, backoffMs));
    }
  }
  throw lastErr;
}

async function setCommitStatus({ octokit, owner, repo, sha, state, description, context }) {
  const statusContext = context || config.GITHUB_CONTEXT;

  return withRetry(
    () =>
      octokit.repos.createCommitStatus({
        owner,
        repo,
        sha,
        state,
        description: String(description || ""),
        context: statusContext
      }),
    { operation: "setCommitStatus" }
  );
}

async function findExistingAxisComment({ octokit, owner, repo, pull_number, scanId }) {
  const per_page = 20;

  const comments = await withRetry(
    () =>
      octokit.issues.listComments({
        owner,
        repo,
        issue_number: pull_number,
        per_page
      }),
    { operation: "listComments", scanId }
  );

  const markerPresent = (body) =>
    typeof body === "string" && body.includes(config.COMMENT_MARKER) && body.includes(`scanId: ${scanId}`);

  const existing = comments?.data?.find((c) => markerPresent(c.body));
  return existing || null;
}

function renderFindingsSummary({ summary, findings }) {
  const sem = summary?.semgrepCount ?? 0;
  const gl = summary?.gitleaksCount ?? 0;
  const npm = summary?.npmCount ?? 0;
  const semErr = findings?.semgrep?.error ? ` (error: ${findings.semgrep.error})` : "";
  const glErr = findings?.gitleaks?.error ? ` (error: ${findings.gitleaks.error})` : "";
  const npmErr = findings?.npmAudit?.error ? ` (error: ${findings.npmAudit.error})` : "";
  return [
    `- Semgrep: ${sem}${semErr}`,
    `- Gitleaks: ${gl}${glErr}`,
    `- npm audit: ${npm}${npmErr}`
  ].join("\n");
}

function renderAiCommentBody({ scanId, aiOutput, decision, findings, summary, error, diffMeta }) {
  const actionBlock = decision?.decision ? `Action: **${decision.decision}**` : "Action: **UNKNOWN**";
  const stateLine =
    decision?.state === "failure"
      ? "Commit Status will be set to `failure`."
      : "Commit Status will be set to `success`.";

  const diffBrief = diffMeta
    ? `\n\nDiff observability: ${diffMeta.fileCount ?? "?"} files (patch preview truncated).`
    : "";

  if (error) {
    return [
      config.COMMENT_MARKER,
      `## Axis Security`,
      `Scan ID: ${scanId}`,
      "",
      `Action: **BLOCK**`,
      "",
      `Reason: Pipeline error: ${error}`,
      "",
      stateLine
    ].join("\n");
  }

  return [
    config.COMMENT_MARKER,
    `## Axis Security`,
    `Scan ID: ${scanId}`,
    `scanId: ${scanId}`,
    "",
    actionBlock,
    stateLine,
    "",
    `### AI Classification`,
    aiOutput
      ? [
          `- classification: **${aiOutput.classification}**`,
          `- severity: **${aiOutput.severity}**`,
          `- confidence: **${aiOutput.confidence}%**`,
          "",
          "### Reasoning",
          aiOutput.reasoning
        ].join("\n")
      : "- (missing aiOutput)",
    "",
    "### Scanner Findings Summary",
    summary ? renderFindingsSummary({ summary, findings }) : "(no scanner summary)",
    diffBrief,
    "",
    "### Suggested Exploit (for verification)",
    aiOutput?.exploit ? `\`\`\`\n${aiOutput.exploit}\n\`\`\`` : "(n/a)",
    "",
    "### Suggested Fix",
    aiOutput?.fix ? `\`\`\`\n${aiOutput.fix}\n\`\`\`` : "(n/a)"
  ].join("\n");
}

async function postPrComment({
  octokit,
  owner,
  repo,
  pull_number,
  head_sha,
  scanId,
  aiOutput,
  decision,
  findings,
  summary,
  diffMeta,
  error
}) {
  const body = renderAiCommentBody({
    scanId,
    aiOutput,
    decision,
    findings,
    summary,
    error,
    diffMeta
  });

  const existing = await findExistingAxisComment({ octokit, owner, repo, pull_number, scanId });

  if (existing) {
    logger.info({ scanId, commentId: existing.id }, "updating existing axis comment");
    await withRetry(
      () =>
        octokit.issues.updateComment({
          owner,
          repo,
          comment_id: existing.id,
          body
        }),
      { operation: "updateComment", scanId }
    );
  } else {
    logger.info({ scanId }, "creating axis comment");
    await withRetry(
      () =>
        octokit.issues.createComment({
          owner,
          repo,
          issue_number: pull_number,
          body
        }),
      { operation: "createComment", scanId }
    );
  }
}

async function fetchPullDiffBestEffort({ octokit, owner, repo, pull_number }) {
  try {
    const allFiles = [];
    let page = 1;
    while (true) {
      const files = await withRetry(
        () =>
          octokit.pulls.listFiles({
            owner,
            repo,
            pull_number,
            per_page: 100,
            page
          }),
        { operation: "listFiles", scanId: pull_number }
      );
      const batch = files?.data || [];
      allFiles.push(...batch);
      if (batch.length < 100) break;
      page += 1;
    }

    const fileCount = allFiles.length;
    const maxPatchChars = 10_000;
    let used = 0;
    const filePreviews = [];
    const changedFiles = [];

    for (const f of allFiles) {
      changedFiles.push({
        filename: f.filename,
        previous_filename: f.previous_filename || null,
        status: f.status
      });

      const patch = typeof f.patch === "string" ? f.patch : "";
      const remaining = maxPatchChars - used;
      const take = remaining > 0 ? patch.slice(0, remaining) : "";
      used += take.length;
      if (take.length > 0) {
        filePreviews.push({
          filename: f.filename,
          patchPreview: take
        });
      }
      if (used >= maxPatchChars) break;
    }

    return {
      fileCount,
      changedFiles,
      patchPreviewChars: used,
      filePreviews,
      truncated: used >= maxPatchChars
    };
  } catch (err) {
    logger.warn({ pull_number, err }, "failed to fetch PR diff (best effort)");
    return null;
  }
}

module.exports = {
  createOctokit,
  postPrComment,
  setCommitStatus,
  fetchPullDiffBestEffort
};


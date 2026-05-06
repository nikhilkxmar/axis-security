const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");

const { config } = require("../config");
const { createLogger } = require("../logger");
const { clonePullRequestToTempDir } = require("./repo");
const { runSecurityScanners } = require("./scanner");
const { analyzeWithAi } = require("./ai-agent");
const { decideRisk } = require("./risk-engine");
const {
  createOctokit,
  postPrComment,
  setCommitStatus,
  fetchPullDiffBestEffort
} = require("./reporter");

const logger = createLogger();

function sanitizeForTempPath(value) {
  return String(value || "scan")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 80);
}

function isPermanentAiQuotaError(err) {
  const code = String(err?.code || "").toLowerCase();
  const status = Number(err?.status || 0);
  const apiCode = String(err?.error?.code || "").toLowerCase();
  const message = String(err?.message || "").toLowerCase();
  const details = String(err?.error?.message || "").toLowerCase();

  return (
    code === "insufficient_quota" ||
    code === "resource_exhausted" ||
    apiCode === "insufficient_quota" ||
    apiCode === "resource_exhausted" ||
    (status === 429 && (message.includes("quota") || details.includes("quota"))) ||
    message.includes("resource exhausted") ||
    details.includes("resource exhausted")
  );
}

function formatErrorForComment(err) {
  const status = err?.status ? `status=${err.status}` : null;
  const code = err?.code ? `code=${err.code}` : null;
  const apiCode = err?.error?.code ? `api_code=${err.error.code}` : null;
  const message = err?.message ? String(err.message) : "unknown error";
  return [status, code, apiCode].filter(Boolean).concat(message).join(" | ");
}

function clampLines(windowLines, min = 1, max = 50) {
  return Math.max(min, Math.min(max, windowLines));
}

async function readFileLines(repoPath, relativePath) {
  const safeRel = relativePath.replaceAll("\\", "/");
  const abs = path.join(repoPath, safeRel);
  const content = await fs.readFile(abs, "utf8");
  return content.split(/\r?\n/);
}

function extractContextFromLines(lines, centerLine, windowLines) {
  const idx = centerLine - 1; 
  const start = Math.max(0, idx - windowLines);
  const end = Math.min(lines.length - 1, idx + windowLines);
  return {
    line: centerLine,
    startLine: start + 1,
    endLine: end + 1,
    text: lines.slice(start, end + 1).join("\n")
  };
}

function dedupeByKey(items, getKey) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const k = getKey(item);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(item);
  }
  return out;
}

function truncateString(s, maxChars) {
  if (!s) return s;
  if (s.length <= maxChars) return s;
  return s.slice(0, maxChars) + "\n...[truncated]";
}

function buildAiInputContext({ repoPath, semgrep, gitleaks, npmAudit }) {
  const windowLines = clampLines(config.CONTEXT_WINDOW_LINES);
  const tasks = [];

  const semgrepPoints = (semgrep?.results || []).map((r) => ({
    source: "semgrep",
    file: r.path,
    line: r.startLine
  }));
  const gitleaksPoints = (gitleaks?.results || []).map((r) => ({
    source: "gitleaks",
    file: r.path,
    line: r.line
  }));
  const npmPoints = (npmAudit?.results || []).flatMap((r) => {
    const pkg = r.packageName;
    if (!pkg) return [];
    return [{ source: "npm-audit", packageName: pkg }];
  });

  const semgrepContextPoints = dedupeByKey(
    semgrepPoints.filter((p) => p.file && p.line),
    (p) => `semgrep:${p.file}:${p.line}`
  );
  const gitleaksContextPoints = dedupeByKey(
    gitleaksPoints.filter((p) => p.file && p.line),
    (p) => `gitleaks:${p.file}:${p.line}`
  );

  for (const p of semgrepContextPoints.slice(0, config.MAX_SEMGREP_FINDINGS)) {
    tasks.push(
      (async () => {
        const lines = await readFileLines(repoPath, p.file);
        return {
          source: p.source,
          path: p.file,
          context: extractContextFromLines(lines, p.line, windowLines)
        };
      })()
    );
  }

  for (const p of gitleaksContextPoints.slice(0, config.MAX_GITLEAKS_FINDINGS)) {
    tasks.push(
      (async () => {
        const lines = await readFileLines(repoPath, p.file);
        return {
          source: p.source,
          path: p.file,
          context: extractContextFromLines(lines, p.line, windowLines)
        };
      })()
    );
  }

  return Promise.all(tasks).then(async (fileContexts) => {
    const pkgJsonPath = "package.json";
    const contexts = fileContexts;
    if (npmPoints.length > 0) {
      try {
        const pkgJson = await fs.readFile(path.join(repoPath, pkgJsonPath), "utf8");
        const lines = pkgJson.split(/\r?\n/);
        const packageNames = dedupeByKey(
          npmPoints.map((x) => x.packageName).filter(Boolean),
          (x) => x
        ).slice(0, config.MAX_NPM_AUDIT_FINDINGS);

        for (const pkgName of packageNames) {
          const matchIdx = lines.findIndex((l) => l.includes(`"${pkgName}"`));
          const approxLine = matchIdx >= 0 ? matchIdx + 1 : 1;
          contexts.push({
            source: "npm-audit",
            path: pkgJsonPath,
            context: extractContextFromLines(lines, approxLine, windowLines)
          });
        }
      } catch (err) {
        logger.warn({ err }, "unable to extract npm audit context from package.json");
      }
    }

    const totalChars = contexts.reduce((acc, c) => acc + (c.context?.text?.length || 0), 0);
    if (totalChars > config.AI_MAX_CONTEXT_CHARS) {
      const perContextMax = Math.floor(config.AI_MAX_CONTEXT_CHARS / Math.max(1, contexts.length));
      for (const c of contexts) {
        if (c.context?.text) c.context.text = truncateString(c.context.text, perContextMax);
      }
    }

    return contexts;
  });
}

function summarizeFindingsForComment(scanResult) {
  const semgrepCount = (scanResult?.findings?.semgrep?.results || []).length;
  const gitleaksCount = (scanResult?.findings?.gitleaks?.results || []).length;
  const npmCount = (scanResult?.findings?.npmAudit?.results || []).length;
  return { semgrepCount, gitleaksCount, npmCount };
}

async function orchestratePrScan({
  scanId,
  job,
  owner,
  repo,
  pull_number,
  head_sha
}) {
  const octokit = createOctokit();

  const safeScanId = sanitizeForTempPath(scanId);
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), `axis-${safeScanId}-`));
  const repoPath = path.join(tempDir, "repo");

  const commitSha = head_sha;
  const statusContext = config.GITHUB_CONTEXT;

  await setCommitStatus({
    octokit,
    owner,
    repo,
    sha: commitSha,
    state: "pending",
    description: "Axis security gate running"
  });

  try {
    logger.info(
      { scanId, owner, repo, pull_number, head_sha, bullAttempt: job?.attemptsMade + 1 },
      "orchestrator started"
    );

    await clonePullRequestToTempDir({
      octokit,
      owner,
      repo,
      pull_number,
      head_sha,
      destinationPath: repoPath
    });

    const diffMeta = await fetchPullDiffBestEffort({ octokit, owner, repo, pull_number });
    const changedFiles = diffMeta?.changedFiles || [];

    logger.info(
      { scanId, changedFilesCount: changedFiles.length },
      "fetched PR changed files for scoped scan"
    );

    const scanResult = await runSecurityScanners({
      repoPath,
      changedFiles
    });

    logger.info(
      { scanId, summary: summarizeFindingsForComment(scanResult) },
      "scanner completed"
    );

    const contexts = await buildAiInputContext({
      repoPath,
      semgrep: scanResult?.findings?.semgrep,
      gitleaks: scanResult?.findings?.gitleaks,
      npmAudit: scanResult?.findings?.npmAudit
    });
    logger.info(
      { scanId, contextCount: contexts.length, diffFiles: diffMeta?.fileCount || null },
      "context built"
    );

    const aiOutput = await analyzeWithAi({
      scanId,
      findings: scanResult.findings,
      contexts,
      diffMeta
    });

    logger.info(
      { scanId, aiClassification: aiOutput.classification, aiSeverity: aiOutput.severity, aiConfidence: aiOutput.confidence },
      "ai analysis completed"
    );

    const decision = decideRisk(aiOutput);
    logger.info({ scanId, decision }, "risk decision completed");

    await postPrComment({
      octokit,
      owner,
      repo,
      pull_number,
      head_sha: commitSha,
      scanId,
      aiOutput,
      decision,
      findings: scanResult.findings,
      summary: summarizeFindingsForComment(scanResult),
      diffMeta
    });

    await setCommitStatus({
      octokit,
      owner,
      repo,
      sha: commitSha,
      state: decision.state,
      description: decision.description,
      context: statusContext
    });

    return {
      scanId,
      decision,
      aiOutput,
      findings: scanResult.findings,
      diffMeta
    };
  } catch (err) {
    const errorMessage = formatErrorForComment(err);
    logger.error({ scanId, err }, "orchestrator failed");
    const permanentQuotaError = isPermanentAiQuotaError(err);

    try {
      await postPrComment({
        octokit,
        owner,
        repo,
        pull_number,
        head_sha: commitSha,
        scanId,
        aiOutput: null,
        decision: { state: "failure", description: "Security gate error" },
        findings: null,
        summary: null,
        diffMeta: null,
        error: errorMessage
      });

      await setCommitStatus({
        octokit,
        owner,
        repo,
        sha: commitSha,
        state: "failure",
        description: "Axis security gate error (check logs)",
        context: statusContext
      });
    } catch (reportErr) {
      logger.error({ scanId, reportErr }, "failed to report error to GitHub");
    }

    if (permanentQuotaError) {
      logger.warn({ scanId }, "non-retryable AI quota error; marking job handled");
      return {
        scanId,
        decision: {
          state: "failure",
          decision: "BLOCK",
          description: "AI quota exceeded; security gate could not complete analysis"
        },
        aiOutput: null,
        findings: null,
        diffMeta: null,
        error: errorMessage
      };
    }

    throw err;
  } finally {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch (_) {
    }
  }
}

module.exports = { orchestratePrScan };


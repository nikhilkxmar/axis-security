const path = require("node:path");
const fs = require("node:fs/promises");
const { execa } = require("execa");
const { config } = require("../config");
const { createLogger } = require("../logger");

const logger = createLogger();

async function fileExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function readJsonFile(p) {
  const txt = await fs.readFile(p, "utf8");
  return JSON.parse(txt);
}

function normalizePath(p) {
  if (!p) return p;
  return String(p).replaceAll("\\", "/");
}

function truncateOutput(output, maxChars = 6000) {
  const text = String(output || "").trim();
  if (!text) return "";
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n...[truncated]`;
}

function logToolOutput(tool, res) {
  logger.info(
    {
      tool,
      exitCode: res?.exitCode ?? null,
      stdout: truncateOutput(res?.stdout),
      stderr: truncateOutput(res?.stderr)
    },
    `${tool} finished`
  );
}

function normalizeSeverity(raw) {
  const s = String(raw || "").toUpperCase();
  if (!s) return undefined;
  const map = {
    INFO: "LOW",
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    MODERATE: "MEDIUM",
    HIGH: "HIGH",
    CRITICAL: "CRITICAL",
    ERROR: "HIGH",
    WARNING: "MEDIUM",
    "": undefined
  };
  return map[s] || s;
}

function toPosixRelPath(p) {
  return String(p || "").replaceAll("\\", "/").replace(/^\/+/, "");
}

async function pathIsRegularFile(p) {
  try {
    const st = await fs.stat(p);
    return st.isFile();
  } catch {
    return false;
  }
}

async function buildScopedScanDirectory({ repoPath, outDir, changedFiles }) {
  const scopedRoot = path.join(outDir, "pr-files");
  await fs.rm(scopedRoot, { recursive: true, force: true });
  await fs.mkdir(scopedRoot, { recursive: true });

  const included = [];
  const seen = new Set();
  for (const f of changedFiles || []) {
    const rel = toPosixRelPath(f.filename);
    if (!rel || seen.has(rel)) continue;
    seen.add(rel);

    if (f.status === "removed") continue;

    const src = path.join(repoPath, rel);
    if (!(await pathIsRegularFile(src))) continue;

    const dst = path.join(scopedRoot, rel);
    await fs.mkdir(path.dirname(dst), { recursive: true });
    await fs.copyFile(src, dst);
    included.push(rel);
  }

  return { scopedRoot, includedFiles: included };
}

function shouldRunNpmAudit(changedFilePaths) {
  if (!Array.isArray(changedFilePaths) || changedFilePaths.length === 0) return false;
  const depManifests = new Set([
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json"
  ]);
  return changedFilePaths.some((p) => depManifests.has(toPosixRelPath(p)));
}

async function runSemgrep({ scanPath, outDir }) {
  const semgrepJsonPath = path.join(outDir, "semgrep.json");

  const args = [
    "scan",
    "--config",
    config.SEMGREP_CONFIG,
    "--json",
    `--json-output=${semgrepJsonPath}`,
    "."
  ];

  logger.info(
    { semgrepConfig: config.SEMGREP_CONFIG, timeoutMs: config.SEMGREP_TIMEOUT_MS },
    "running semgrep"
  );

  const res = await execa("semgrep", args, {
    cwd: scanPath,
    timeout: Math.ceil(config.SEMGREP_TIMEOUT_MS / 1000) * 1000,
    reject: false
  });
  logToolOutput("semgrep", res);

  if (!(await fileExists(semgrepJsonPath))) {
    throw new Error(`Semgrep did not produce JSON output. exitCode=${res.exitCode}`);
  }

  const semgrepJson = await readJsonFile(semgrepJsonPath);
  const resultsRaw = Array.isArray(semgrepJson?.results) ? semgrepJson.results : [];

  const results = resultsRaw.map((r) => ({
    check_id: r.check_id,
    message: r.extra?.message || r.extra?.taint_source?.message || r.extra?.metadata?.message,
    severity: normalizeSeverity(r.extra?.severity),
    path: normalizePath(r.path || r.path?.path),
    startLine: r.start?.line || r.start_line || r.start_line_number,
    endLine: r.end?.line || r.end_line
  }));

  return {
    semgrepExitCode: res.exitCode,
    results,
    rawErrors: semgrepJson?.errors || []
  };
}

async function runGitleaks({ scanPath, outDir }) {
  const gitleaksJsonPath = path.join(outDir, "gitleaks.json");

  logger.info({ timeoutMs: config.GITLEAKS_TIMEOUT_MS }, "running gitleaks");

  const args = [
    "detect",
    "--no-git",
    "--source",
    ".",
    "--report-format",
    "json",
    `--report-path=${gitleaksJsonPath}`
  ];

  const res = await execa("gitleaks", args, {
    cwd: scanPath,
    timeout: Math.ceil(config.GITLEAKS_TIMEOUT_MS / 1000) * 1000,
    reject: false
  });
  logToolOutput("gitleaks", res);

  if (!(await fileExists(gitleaksJsonPath))) {
    throw new Error(`Gitleaks did not produce JSON output. exitCode=${res.exitCode}`);
  }

  const gitleaksJson = await readJsonFile(gitleaksJsonPath);

  const findingsRaw = Array.isArray(gitleaksJson?.findings)
    ? gitleaksJson.findings
    : Array.isArray(gitleaksJson)
      ? gitleaksJson
      : [];

  const results = findingsRaw.map((f) => {
    const pathVal = f.path || f.File || f.file || f.Filename;
    const lineVal = f.line || f.Line || f.StartLine || f.startLine || f.start_line;
    const startLine = Number(lineVal) || undefined;

    const ruleId = f.ruleId || f.RuleID || f.rule_id || f.rule || f.RuleID;
    const secret = f.secret || f.Secret || f.match || f.Match;
    const severity =
      normalizeSeverity(f.severity || f.Severity || f.tags?.[0]) ||
      normalizeSeverity(f.Tags?.[0]) ||
      undefined;

    return {
      ruleId,
      secret,
      severity,
      path: normalizePath(pathVal),
      line: startLine
    };
  });

  return { gitleaksExitCode: res.exitCode, results };
}

async function runNpmAudit({ repoPath, outDir }) {
  const npmJsonPath = path.join(outDir, "npm-audit.json");

  logger.info({ timeoutMs: config.NPM_AUDIT_TIMEOUT_MS }, "running npm audit");

  const res = await execa("npm", ["audit", "--json"], {
    cwd: repoPath,
    timeout: Math.ceil(config.NPM_AUDIT_TIMEOUT_MS / 1000) * 1000,
    reject: false
  });
  logToolOutput("npm-audit", res);

  await fs.writeFile(npmJsonPath, res.stdout || "", "utf8");

  let npmJson = {};
  if (res.stdout) {
    try {
      npmJson = JSON.parse(res.stdout);
    } catch (err) {
      throw new Error(`npm audit returned non-JSON output: ${String(err.message || err)}`);
    }
  }

  const results = [];

  if (npmJson?.advisories && typeof npmJson.advisories === "object") {
    for (const adv of Object.values(npmJson.advisories)) {
      results.push({
        packageName: adv.module_name,
        severity: normalizeSeverity(adv.severity),
        title: adv.title,
        url: adv.url,
        vulnerable_versions: adv.vulnerable_versions,
        patched_versions: adv.patched_versions
      });
    }
  } else if (npmJson?.vulnerabilities && typeof npmJson.vulnerabilities === "object") {
    for (const [pkg, v] of Object.entries(npmJson.vulnerabilities)) {
      results.push({
        packageName: pkg,
        severity: normalizeSeverity(v && v.severity),
        title: v.title,
        url: v.url,
        range: v.range,
        patched_versions: v.range
      });
    }
  }

  return { npmAuditExitCode: res.exitCode, results };
}

async function runSecurityScanners({ repoPath, changedFiles }) {
  const outDir = path.join(repoPath, "__axis_scan_tmp");
  await fs.rm(outDir, { recursive: true, force: true });
  await fs.mkdir(outDir, { recursive: true });

  try {
    const { scopedRoot, includedFiles } = await buildScopedScanDirectory({
      repoPath,
      outDir,
      changedFiles
    });
    const changedFilePaths = includedFiles;

    logger.info(
      { changedFiles: (changedFiles || []).length, includedFiles: includedFiles.length },
      "built PR-only scan scope"
    );

    if (includedFiles.length === 0) {
      return {
        findings: {
          semgrep: { results: [], error: null, rawErrors: [] },
          gitleaks: { results: [], error: null },
          npmAudit: { results: [], error: "Skipped: no supported changed files" }
        },
        scanMeta: {
          semgrepExitCode: 0,
          gitleaksExitCode: 0,
          npmAuditExitCode: null
        }
      };
    }

    const runNpm = shouldRunNpmAudit(changedFilePaths);

    const [semgrep, gitleaks, npmAudit] = await Promise.all([
      runSemgrep({ scanPath: scopedRoot, outDir }).catch((err) => {
        logger.error({ err }, "semgrep failed");
        return { error: String(err.message || err), results: [], rawErrors: [] };
      }),
      runGitleaks({ scanPath: scopedRoot, outDir }).catch((err) => {
        logger.error({ err }, "gitleaks failed");
        return { error: String(err.message || err), results: [] };
      }),
      runNpm
        ? runNpmAudit({ repoPath, outDir }).catch((err) => {
            logger.error({ err }, "npm audit failed");
            return { error: String(err.message || err), results: [] };
          })
        : Promise.resolve({
            npmAuditExitCode: null,
            results: [],
            error: "Skipped: dependency manifests unchanged in PR"
          })
    ]);

    const semgrepCapped = semgrep?.results?.slice(0, config.MAX_SEMGREP_FINDINGS) || [];
    const gitleaksCapped = gitleaks?.results?.slice(0, config.MAX_GITLEAKS_FINDINGS) || [];
    const npmAuditCapped = npmAudit?.results?.slice(0, config.MAX_NPM_AUDIT_FINDINGS) || [];

    return {
      findings: {
        semgrep: {
          results: semgrepCapped,
          error: semgrep?.error || null,
          rawErrors: semgrep?.rawErrors || []
        },
        gitleaks: {
          results: gitleaksCapped,
          error: gitleaks?.error || null
        },
        npmAudit: {
          results: npmAuditCapped,
          error: npmAudit?.error || null
        }
      },
      scanMeta: {
        semgrepExitCode: semgrep?.semgrepExitCode ?? null,
        gitleaksExitCode: gitleaks?.gitleaksExitCode ?? null,
        npmAuditExitCode: npmAudit?.npmAuditExitCode ?? null
      }
    };
  } finally {
    await fs.rm(outDir, { recursive: true, force: true });
  }
}

module.exports = { runSecurityScanners };


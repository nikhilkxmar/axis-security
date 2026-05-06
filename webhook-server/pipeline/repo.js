const fs = require("node:fs/promises");
const path = require("node:path");
const { execa } = require("execa");
const { config } = require("../config");
const { createLogger } = require("../logger");

const logger = createLogger();

async function ensureEmptyDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

function withTokenInHttpsUrl(cloneUrl, token) {
  const u = new URL(cloneUrl);
  if (u.protocol !== "https:") return cloneUrl;
  u.username = "x-access-token";
  u.password = token;
  return u.toString();
}

async function runGit(args, { cwd }) {
  const res = await execa("git", args, { cwd });
  return res;
}

async function clonePullRequestToTempDir({
  octokit,
  owner,
  repo,
  pull_number,
  head_sha,
  destinationPath
}) {
  const pr = await octokit.pulls.get({ owner, repo, pull_number });
  const head = pr.data.head;
  const headRepo = head.repo;

  if (!headRepo || !headRepo.clone_url) {
    throw new Error("Unable to determine PR head clone URL");
  }

  await ensureEmptyDir(destinationPath);

  const cloneUrl = withTokenInHttpsUrl(headRepo.clone_url, config.GITHUB_TOKEN);

  await fs.rm(destinationPath, { recursive: true, force: true });

  await execa(
    "git",
    ["clone", "--depth", "1", "--filter=blob:none", cloneUrl, destinationPath],
    { stdio: "ignore" }
  );

  await runGit(["fetch", "--depth", "1", "origin", head_sha], { cwd: destinationPath });
  await runGit(["checkout", "-q", head_sha], { cwd: destinationPath });

  const current = await execa("git", ["rev-parse", "HEAD"], { cwd: destinationPath });
  if (String(current.stdout).trim() !== String(head_sha).trim()) {
    logger.warn(
      { expected: head_sha, got: String(current.stdout).trim() },
      "checked out SHA mismatch"
    );
  }

  return { repoPath: destinationPath };
}

module.exports = { clonePullRequestToTempDir };


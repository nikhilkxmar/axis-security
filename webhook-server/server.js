require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const { z } = require("zod");
const { createLogger } = require("./logger");
const { config } = require("./config");
const { createRedisConnection, createQueue } = require("./queue");

const logger = createLogger();

const WebhookEventSchema = z
  .object({
    action: z.string(),
    pull_request: z.object({
      number: z.number().int(),
      head: z.object({ sha: z.string().min(1) })
    }),
    repository: z.object({
      owner: z.object({ login: z.string().min(1) }),
      name: z.string().min(1)
    })
  })
  .passthrough();

function verifyGitHubSignature({ rawBody, signatureHeader }) {
  if (!signatureHeader) return false;
  const match = signatureHeader.match(/^sha256=([a-f0-9]{64})$/i);
  if (!match) return false;

  const provided = match[1];
  const expected = crypto
    .createHmac("sha256", config.GITHUB_SECRET)
    .update(rawBody)
    .digest("hex");

  const a = Buffer.from(provided, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function main() {
  const redisConnection = createRedisConnection();
  const queue = createQueue(redisConnection);

  const app = express();

  app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    const requestId = crypto.randomUUID();
    logger.info(
      {
        requestId,
        path: req.path,
        event: req.headers["x-github-event"],
        delivery: req.headers["x-github-delivery"]
      },
      "webhook request received"
    );

    try {
      const signatureHeader = req.headers["x-hub-signature-256"];
      const rawBody = req.body;

      if (!verifyGitHubSignature({ rawBody, signatureHeader })) {
        logger.warn({ requestId }, "invalid signature");
        return res.status(401).send("Invalid signature");
      }

      const githubEvent = String(req.headers["x-github-event"] || "");
      if (githubEvent !== "pull_request") {
        return res.status(200).send("Ignored: not pull_request event");
      }

      const payload = JSON.parse(rawBody.toString("utf8"));
      const event = WebhookEventSchema.parse(payload);

      const allowedActions = new Set(["opened", "synchronize", "reopened"]);
      if (!allowedActions.has(event.action)) {
        return res.status(200).send(`Ignored: action=${event.action}`);
      }

      const owner = event.repository.owner.login;
      const repo = event.repository.name;
      const pull_number = event.pull_request.number;
      const head_sha = event.pull_request.head.sha;

      const jobId = `${owner}/${repo}#${pull_number}@${head_sha}`;

      const job = await queue.add(
        "pr-security-scan",
        { owner, repo, pull_number, head_sha, jobId },
        { jobId }
      );

      logger.info(
        { requestId, jobId: job.id, owner, repo, pull_number, head_sha },
        "job enqueued"
      );
      return res.status(202).send("Accepted");
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      if (msg.toLowerCase().includes("already exists")) {
        return res.status(202).send("Accepted (duplicate job)");
      }

      logger.error({ requestId, err }, "webhook handler error");
      return res.status(400).send("Bad webhook payload");
    }
  });

  app.get("/healthz", (_req, res) => res.status(200).json({ ok: true }));

  const server = app.listen(config.PORT, () => {
    logger.info({ port: config.PORT }, "server listening");
  });

  const shutdown = async () => {
    logger.info("shutting down server");
    server.close();
    try {
      await redisConnection.close();
    } catch (_) {
    }
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  logger.error({ err }, "fatal startup error");
  process.exit(1);
});


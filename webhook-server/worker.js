require("dotenv").config();

const crypto = require("crypto");
const { Worker } = require("bullmq");
const { createRedisConnection } = require("./queue");
const { config } = require("./config");
const { createLogger } = require("./logger");
const { orchestratePrScan } = require("./pipeline/orchestrator");

const logger = createLogger();

async function main() {
  const redisConnection = createRedisConnection();

  const concurrency = Number(process.env.WORKER_CONCURRENCY || 2);

  const worker = new Worker(
    config.QUEUE_NAME,
    async (job) => {
      const { owner, repo, pull_number, head_sha, jobId } = job.data || {};
      const scanId = jobId || `${owner}/${repo}#${pull_number}`;

      logger.info(
        { scanId, bullJobId: job.id, attempt: job.attemptsMade + 1 },
        "starting PR scan job"
      );

      const result = await orchestratePrScan({
        scanId,
        job,
        owner,
        repo,
        pull_number,
        head_sha
      });

      logger.info({ scanId }, "PR scan job finished");
      return result;
    },
    {
      connection: redisConnection,
      concurrency,
      settings: {
        lockDuration: 60_000,
        stalledInterval: 30_000,
        maxStalledCount: 3
      }
    }
  );

  worker.on("completed", (job) => {
    logger.info({ scanId: job.data && job.data.jobId, bullJobId: job.id }, "job completed");
  });

  worker.on("failed", (job, err) => {
    logger.error(
      { scanId: job && job.data && job.data.jobId, err },
      "job failed"
    );
  });

  worker.on("stalled", (jobId) => {
    logger.warn({ bullJobId: jobId }, "job stalled");
  });

  const shutdown = async () => {
    const scanId = crypto.randomUUID();
    logger.info({ shutdownId: scanId }, "worker shutting down");
    try {
      await worker.close();
    } catch (_) {
    }
    try {
      await redisConnection.close();
    } catch (_) {
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  logger.error({ err }, "worker fatal error");
  process.exit(1);
});


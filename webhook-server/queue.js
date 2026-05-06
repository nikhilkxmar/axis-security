const { Queue } = require("bullmq");
const IORedis = require("ioredis");
const { config } = require("./config");

function createRedisConnection() {
  return new IORedis({
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    password: config.REDIS_PASSWORD,
    db: config.REDIS_DB,
    maxRetriesPerRequest: null,
    enableReadyCheck: true
  });
}

function createQueue(redisConnection) {
  return new Queue(config.QUEUE_NAME, {
    connection: redisConnection,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: "exponential", delay: 30_000 },
      removeOnComplete: 200,
      removeOnFail: false
    }
  });
}

module.exports = { createRedisConnection, createQueue };


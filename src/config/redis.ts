import Redis from "ioredis";
import { env } from "./env";

export const redis = new Redis({
  host: env.REDIS_HOST,
  port: env.REDIS_PORT,
  password: env.REDIS_PASSWORD,
  retryStrategy: (times) => {
    if (times > 5) return null;
    return Math.min(times * 200, 2000);
  },
});

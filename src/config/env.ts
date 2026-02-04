import { config } from "dotenv";

config();

const required = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required env var: ${key}`);
  }
  return value;
};

export const env = {
  NODE_ENV: process.env.NODE_ENV ?? "development",
  PORT: Number(process.env.PORT ?? 4000),
  DATABASE_URL: required("DATABASE_URL"),
  JWT_ACCESS_SECRET: required("JWT_ACCESS_SECRET"),
  JWT_REFRESH_SECRET: required("JWT_REFRESH_SECRET"),
  JWT_REFRESH_TOKEN_EXPIRY_TIME: required("JWT_REFRESH_TOKEN_EXPIRY_TIME"),
  JWT_ACCESS_TOKEN_EXPIRY_TIME: required("JWT_ACCESS_TOKEN_EXPIRY_TIME"),
  REDIS_HOST: required("REDIS_HOST"),
  REDIS_PORT: Number(process.env.REDIS_PORT ?? 6379),
  REDIS_PASSWORD: process.env.REDIS_PASSWORD,
  COOKIE_SECURE: process.env.COOKIE_SECURE === "true",
};

export const auth = {
  JWT_REFRESH_TOKEN_EXPIRY_TIME: 60 * 60 * 24 * 7,
  JWT_ACCESS_TOKEN_EXPIRY_TIME: 60 * 60 * 24 * 1,
};

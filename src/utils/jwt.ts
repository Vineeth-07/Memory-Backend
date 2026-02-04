import jwt from "jsonwebtoken";
import { env, auth } from "../config/env";

export const signAccessToken = (payload: object) =>
  jwt.sign(payload, env.JWT_ACCESS_SECRET!, {
    expiresIn: auth.JWT_ACCESS_TOKEN_EXPIRY_TIME,
  });

export const signRefreshToken = (payload: object) =>
  jwt.sign(payload, env.JWT_REFRESH_SECRET!, {
    expiresIn: auth.JWT_REFRESH_TOKEN_EXPIRY_TIME,
  });

export const verifyAccessToken = (token: string) =>
  jwt.verify(token, env.JWT_ACCESS_SECRET!);

export const verifyRefreshToken = (token: string) =>
  jwt.verify(token, env.JWT_REFRESH_SECRET!);

import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";
import { redis } from "../config/redis";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt";
import { prisma } from "../config/prisma";
import { USERSTATUS } from "../enums";
import { auth, env } from "../config/env";

export const signup = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required",
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      message: "Password must be at least 8 characters long",
    });
  }

  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    return res.status(409).json({
      message: "User already exists",
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      email,
      password_hash: passwordHash,
      is_verified: false,
      status: USERSTATUS.ACTIVE,
    },
  });

  const sessionId = uuid();

  const accessToken = signAccessToken({
    userId: user.id,
    sessionId,
  });

  const refreshToken = signRefreshToken({
    userId: user.id,
    sessionId,
  });

  await redis.set(
    `refresh:${user.id}:${sessionId}`,
    refreshToken,
    "EX",
    auth.JWT_REFRESH_TOKEN_EXPIRY_TIME,
  );

  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: "strict",
      path: "/api/v1/auth",
    })
    .status(201)
    .json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        is_verified: user.is_verified,
        status: user.status,
      },
    });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  const sessionId = uuid();

  const accessToken = signAccessToken({
    userId: user.id,
    sessionId,
  });

  const refreshToken = signRefreshToken({
    userId: user.id,
    sessionId,
  });

  await redis.set(
    `refresh:${user.id}:${sessionId}`,
    refreshToken,
    "EX",
    auth.JWT_REFRESH_TOKEN_EXPIRY_TIME,
  );

  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/v1/auth",
    })
    .json({ accessToken });
};

export const refresh = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  let payload: any;
  try {
    payload = verifyRefreshToken(token);
  } catch {
    return res.sendStatus(401);
  }

  const key = `refresh:${payload.userId}:${payload.sessionId}`;
  const stored = await redis.get(key);

  if (!stored || stored !== token) return res.sendStatus(401);

  // rotate
  await redis.del(key);

  const newSessionId = payload.sessionId;

  const newAccessToken = signAccessToken({
    userId: payload.userId,
    sessionId: newSessionId,
  });

  const newRefreshToken = signRefreshToken({
    userId: payload.userId,
    sessionId: newSessionId,
  });

  await redis.set(
    `refresh:${payload.userId}:${newSessionId}`,
    newRefreshToken,
    "EX",
    auth.JWT_REFRESH_TOKEN_EXPIRY_TIME,
  );

  res
    .cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/v1/auth",
    })
    .json({ accessToken: newAccessToken });
};

export const logout = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(202);

  try {
    const payload: any = verifyRefreshToken(token);
    await redis.del(`refresh:${payload.userId}:${payload.sessionId}`);
  } catch {}

  res.clearCookie("refreshToken", { path: "/api/v1/auth" });
  res.sendStatus(204);
};

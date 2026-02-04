import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env";

export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.sendStatus(401);

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, env.JWT_ACCESS_SECRET!);
    next();
  } catch {
    res.sendStatus(401);
  }
};

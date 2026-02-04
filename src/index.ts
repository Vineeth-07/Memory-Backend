import express from "express";
import cors from "cors";
import helmet from "helmet";
import { env } from "./config/env";
import cookieParser from "cookie-parser";
import routes from "./routes";

const app = express();

app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

app.use("/api/v1", routes);

app.get("/health", (_, res) => {
  res.json({ status: "ok" });
});

const PORT = env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

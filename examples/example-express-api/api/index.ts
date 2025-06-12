import express from "express";
import cors from "cors";
import type { Request, Response } from "express";

import PublicRoutes from "./routes/public.js";
import PrivateRoutes from "./routes/private.js";

const app = express();

app.set('trust proxy', true);

app.use(
  cors({
    exposedHeaders: ["DPoP-Nonce", "WWW-Authenticate"],
  }),
);

app.use("/private", PrivateRoutes);
app.use("/public", PublicRoutes);

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: "not_found",
    error_description: "The requested resource was not found",
  });
});

export default app;

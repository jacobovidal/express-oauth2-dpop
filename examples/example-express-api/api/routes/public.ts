import express from "express";

const router = express.Router();

router.get("/hello", (_req, res) => {
  res.json({
    message: "Hello from a public endpoint!",
  });
});

export default router;

import type { Response } from "express";
import {
  InsufficientScope,
  InvalidDpopProof,
  InvalidRequest,
  InvalidToken,
  Unauthorized,
  UseDpopNonce,
} from "../errors/errors.js";

export function handleError(error: unknown, res: Response) {
  if (error instanceof Unauthorized) {
    return res
      .status(error.statusCode)
      .header("WWW-Authenticate", error.wwwAuthenticate)
      .end();
  }

  if (error instanceof UseDpopNonce) {
    return res
      .status(error.statusCode)
      .header("WWW-Authenticate", error.wwwAuthenticate)
      .json({
        error: error.code,
        error_description: error.description,
      });
  }

  if (
    error instanceof InvalidToken ||
    error instanceof InsufficientScope ||
    error instanceof InvalidDpopProof ||
    error instanceof InvalidRequest
  ) {
    return res
      .status(error.statusCode)
      .header("WWW-Authenticate", error.wwwAuthenticate)
      .json({
        error: error.code,
        error_description: error.description,
      });
  }

  return res.status(500).json({
    error: "server_error",
    error_description: "There was an unknown error",
  });
}

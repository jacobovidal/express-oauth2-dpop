import { Request, Response, NextFunction } from "express";
import { ProtectRouteOptions } from "../types/types.js";

export function protectRoute(
  protectRouteOptions: ProtectRouteOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const { enforceDPoP = false, scope: requiredScopes } = protectRouteOptions;

  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).header("WWW-Authenticate", "Bearer").end();
    }

    if (enforceDPoP && !req.auth?.payload?.cnf?.jkt) {
      return res.status(401).header("WWW-Authenticate", "DPoP").json({
        error: "invalid_token",
        error_description: "The access token needs to be DPoP-bound",
      });
    }

    if (requiredScopes?.length) {
      const tokenScope = req.auth?.payload?.scope;

      if (!tokenScope || typeof tokenScope !== "string") {
        return res.status(403).json({
          error: "insufficient_scope",
          error_description: "The access token has no scopes",
        });
      }

      const tokenScopes = (tokenScope as string).split(" ");

      const hasAllScopes = requiredScopes.every((scope) =>
        tokenScopes.includes(scope),
      );

      if (!hasAllScopes) {
        return res.status(403).json({
          error: "insufficient_scope",
          error_description: `Required scopes are: '${requiredScopes.join(" ")}'`,
        });
      }
    }

    next();
  };
}

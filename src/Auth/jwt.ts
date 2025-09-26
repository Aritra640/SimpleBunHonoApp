import type { Context, Next } from "hono";
import jwt from "jsonwebtoken";
import JWTsecret from "./secret";

export default async function AuthMiddleware(c: Context, next: Next) {
  console.log("JWt middleware called!");

  const authHeader = c.req.header("Authorization") || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : null;

  if (!token) {
    return c.text("Unauthorized", 401);
  }

  try {
    const decoded = jwt.verify(token, JWTsecret) as
      | { username: string }
      | object;
    const username = (decoded as { username?: string }).username;

    if (!username) {
      return c.text("Invalid token payload", 401);
    }

    c.header("username", username);
    await next();
  } catch (err) {
    return c.text("Token verification failed ", 404);
  }
}

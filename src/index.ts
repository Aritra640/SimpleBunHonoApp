import { Hono } from "hono";
import { cors } from "hono/cors";
import store from "./store/store";
import type { user } from "./store/user";
import jwt from "jsonwebtoken";
import JWTsecret from "./Auth/secret";
import AuthMiddleware from "./Auth/jwt";
import { upgradeWebSocket } from "hono/bun";

const app = new Hono();
app.use(cors());
app.use("/auth/*", AuthMiddleware);

app.get("/hello", async (c) => {
  return c.text("Hello From Hono!");
});

app.post("/add", async (c) => {
  const username = c.req.header("username");
  const password = c.req.header("password");

  if (!password || !username) {
    return c.text(
      "Error: cannot read password or password void or invalid username",
    );
  }

  const hash = await Bun.password.hash(password);
  const newUser: user = {
    hpwd: hash,
    name: username,
  };
  store[username] = newUser;
});

app.post("/lognin", async (c) => {
  const username = c.req.header("username");
  const password = c.req.header("password");

  if (!password || !username) {
    return c.text(
      "Error: cannot read password or password void or invalid username",
    );
  }

  if (!store[username]) {
    return c.text("Error: user not found!");
  }

  const userData = store[username];
  const isMatch = await Bun.password.verify(password, userData.hpwd);
  if (!isMatch) {
    return c.text("Error: username or password invalid");
  }

  const token = jwt.sign({ username: username }, JWTsecret, {
    expiresIn: "2h",
  });

  c.header("Authorization", `Bearer ${token}`);
  return c.text("JWT token sent in Authorization header");
});

app.get("/auth/userinfo", async (c) => {
  const username = c.req.header("username");
  if (!username) {
    return c.text("Error: username null");
  }

  const userinfo = store[username];

  return c.json({
    username: username,
    password: userinfo?.hpwd,
  });
});


app.get("/ping", upgradeWebSocket((c) => {
  return {
    open(ws) {
      console.log("Websocket connection established!");
      ws.send("Welcome send 'ping' or 'pong'");
    }
  }
}))

export default app;

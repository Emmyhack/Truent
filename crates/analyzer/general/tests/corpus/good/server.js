// Express configured correctly: scoped CORS with credentials, hardened
// session cookie, helmet, rate limiting, guarded outbound fetch.
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");

const app = express();
app.use(helmet());
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));

const ALLOWED_HOSTS = new Set(["api.partner.example"]);
app.get("/proxy", async (req, res) => {
  const url = new URL(req.query.url);
  if (!ALLOWED_HOSTS.has(url.hostname)) return res.status(400).end();
  const r = await fetch(url);
  res.send(await r.text());
});

app.get("/files/:name", (req, res) => {
  res.sendFile(path.join(UPLOADS, path.basename(req.params.name)));
});

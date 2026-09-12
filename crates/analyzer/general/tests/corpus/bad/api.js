// EXPECT: gen_web_jwt_unverified
// EXPECT: gen_web_ssrf
// EXPECT: gen_web_path_traversal
const jwt = require("jsonwebtoken");
app.get("/me", (req, res) => {
  const claims = jwt.verify(req.headers.token, key, { algorithms: ["none"] });
  res.json(claims);
});
app.get("/fetch", async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});
app.get("/file", (req, res) => {
  res.sendFile(path.join(UPLOADS, req.query.name));
});

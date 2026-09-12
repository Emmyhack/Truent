// Correct Node code: parameterised queries, execFile with an argument array,
// textContent for untrusted data, crypto for tokens, config from env.
const { execFile } = require("child_process");
const crypto = require("crypto");
const apiKey = process.env.API_KEY;
const dbUrl = `postgres://${process.env.DB_USER}@${process.env.DB_HOST}/app`;

async function findUser(db, id) {
  return db.query("SELECT id, name FROM users WHERE id = $1", [id]);
}

function list(dir, cb) {
  execFile("ls", ["-la", dir], cb);
}

function render(el, text) {
  el.textContent = text;
  el.innerHTML = "<span class=\"ok\">saved</span>";
}

function token() {
  return crypto.randomBytes(32).toString("hex");
}

function jitter() {
  return Math.random() * 100;
}

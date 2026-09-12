// EXPECT: gen_xss_sink
// EXPECT: gen_command_injection
// EXPECT: gen_sql_injection
// EXPECT: gen_insecure_randomness
const { exec } = require("child_process");

function show(el, req) {
  el.innerHTML = req.query.name;
}
function ping(req) {
  exec(`ping -c 1 ${req.query.host}`);
}
function find(db, req) {
  return db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
}
function resetToken() {
  return Math.random().toString(36).slice(2);
}

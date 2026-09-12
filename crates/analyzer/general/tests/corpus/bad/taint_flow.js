// EXPECT: gen_sql_injection
// EXPECT: gen_xss_sink
// Injection reached across several lines — no sink line contains a source.
function lookup(req, res) {
  const name = req.body.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(sql);
}

function render(req) {
  let msg = req.query.msg;
  let html = "<b>" + msg + "</b>";
  el.innerHTML = html;
}

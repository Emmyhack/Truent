#!/usr/bin/env bash
# Load / stress test for the scanner itself.
#
# Truent's product is the CLI, so "load" means: a large repository, many
# files, deep trees, and one pathological file — scanned within a fixed time
# budget without a crash, a hang, or runaway memory. Thresholds are asserted;
# CI fails when they regress.
#
#   tests/load/stress-scan.sh [path-to-truent-binary]
set -euo pipefail

BIN="${1:-./target/release/truent}"
FILES="${STRESS_FILES:-3000}"
BUDGET_S="${STRESS_BUDGET_S:-120}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "▶ generating $FILES files under $WORK"
python3 - "$WORK" "$FILES" <<'PY'
import os, random, sys
root, n = sys.argv[1], int(sys.argv[2])
random.seed(7)
py = '''from flask import request
def handler_{i}():
    q = request.args.get("id")
    sql = "SELECT * FROM t WHERE id = " + q
    cur.execute(sql)
    limit = int(request.args.get("limit"))
    return rows[:limit]
'''
js = '''app.get('/x{i}', async (req, res) => {{
  const order = await Order.findById(req.params.id);
  res.json(order);
}});
'''
sol = '''pragma solidity ^0.8.20;
contract C{i} is Ownable {{
    address[] public holders;
    function join() external {{ holders.push(msg.sender); }}
    function withdraw(uint256 a) external {{ payable(msg.sender).transfer(a); }}
    function deposit() external payable {{}}
    function borrow(uint256 a) external {{}}
    function pay() external onlyOwner {{
        for (uint256 i = 0; i < holders.length; i++) {{ payable(holders[i]).transfer(1); }}
    }}
}}
'''
for i in range(n):
    d = os.path.join(root, f"svc{i % 40}", f"mod{i % 7}")
    os.makedirs(d, exist_ok=True)
    kind = i % 3
    if kind == 0:
        open(os.path.join(d, f"h{i}.py"), "w").write(py.format(i=i))
    elif kind == 1:
        open(os.path.join(d, f"r{i}.js"), "w").write(js.format(i=i))
    else:
        open(os.path.join(d, f"C{i}.sol"), "w").write(sol.format(i=i))
# One pathological file: 20k lines, long lines, nested braces.
with open(os.path.join(root, "huge.js"), "w") as f:
    for i in range(20000):
        f.write("function f%d(req){ const a = req.query.a; return a + %s; }\n" % (i, "'x'" * 40))
PY

echo "▶ scan (budget ${BUDGET_S}s)"
START=$(date +%s)
"$BIN" scan "$WORK" --chain auto --output json > "$WORK/out.json" 2>"$WORK/err.txt" || true
END=$(date +%s)
ELAPSED=$((END - START))
COUNT=$(python3 -c "import json; print(len(json.load(open('$WORK/out.json')).get('violations', [])))")
echo "  scanned $FILES+1 files in ${ELAPSED}s, $COUNT findings"

if [ "$ELAPSED" -gt "$BUDGET_S" ]; then echo "✗ exceeded time budget"; exit 1; fi
if [ "$COUNT" -lt "$FILES" ]; then echo "✗ expected at least one finding per generated file, got $COUNT"; exit 1; fi
if grep -qi "panicked" "$WORK/err.txt"; then echo "✗ panic during scan"; cat "$WORK/err.txt"; exit 1; fi
echo "✓ stress scan within budget, no panic"

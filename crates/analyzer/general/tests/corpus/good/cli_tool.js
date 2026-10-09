// A developer tool: reads its own config from a path it derived itself,
// walks a file with a RegExp, and shells out with an argument array.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function loadConfig(projectRoot) {
  const cfg = path.join(projectRoot, 'foundry.toml');
  if (!fs.existsSync(cfg)) return { src: 'src' };
  const text = fs.readFileSync(cfg, 'utf8');
  return { src: /src\s*=\s*"([^"]+)"/.exec(text)?.[1] ?? 'src' };
}

function contractNames(source) {
  const names = [];
  const re = /\bcontract\s+(\w+)/g;
  let m;
  while ((m = re.exec(source)) !== null) names.push(m[1]);
  return names;
}

function openInBrowser(url) {
  execFileSync('open', [url], { stdio: 'ignore' });
}

module.exports = { loadConfig, contractNames, openInBrowser };

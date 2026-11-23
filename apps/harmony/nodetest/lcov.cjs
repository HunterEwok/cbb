// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Keeps the app's own code of Node's LCOV (run.sh):
//   node lcov.cjs NODE.info ROOT DIR >APP.info
// the records of DIR (entry/src/main/ets, the phone's, or
// wearable/src/main/ets, the watch's), named from the repository's root, and
// in each only the lines of code: Node counts every line of a file it
// loaded, blank lines and comments too. A line of code holds more than a
// comment or closing brackets, as apps/desktop/jscover_test.go counts.
'use strict';
const fs = require('fs');
const path = require('path');
const [file, root, dir] = process.argv.slice(2);
const app = path.join(root, 'apps/harmony', dir) + path.sep;
let out = '';
let records = 0;
for (const rec of fs.readFileSync(file, 'utf8').split('end_of_record')) {
  const sf = /^SF:(.*)$/m.exec(rec);
  if (!sf) continue;
  const src = path.resolve(__dirname, sf[1]);
  if (!src.startsWith(app)) continue;
  const lines = fs.readFileSync(src, 'utf8').split('\n');
  const code = (n) => {
    const t = (lines[n - 1] || '').trim();
    return t !== '' && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*') && t.replace(/[}\]);, ]/g, '') !== '';
  };
  let lf = 0, lh = 0, da = '';
  for (const m of rec.matchAll(/^DA:(\d+),(\d+)/gm)) {
    const n = Number(m[1]);
    if (!code(n)) continue;
    lf++;
    if (Number(m[2]) > 0) lh++;
    da += `DA:${n},${m[2]}\n`;
  }
  out += `TN:\nSF:${path.relative(root, src).split(path.sep).join('/')}\n${da}LF:${lf}\nLH:${lh}\nend_of_record\n`;
  records++;
}
if (records === 0) {
  console.error(`lcov.cjs: ${file} has no record of ${dir}`);
  process.exit(1);
}
process.stdout.write(out);

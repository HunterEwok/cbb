// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Turns the app's ArkTS into JavaScript for the tests under Node (run.sh):
//   node build.cjs TYPESCRIPT OUT
// with TypeScript's transpiler, file by file and without type checks, each
// with its source map, so that coverage names the .ets lines. The pages and
// components, which ArkTS's UI syntax keeps from TypeScript, are left out:
// the tests here reach only the model, core and common code.
'use strict';
const fs = require('fs');
const path = require('path');
const ts = require(process.argv[2]);
const out = process.argv[3];
const app = path.resolve(__dirname, '..');
let failed = false;

function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!['pages', 'components', 'widget', 'entryability', 'entrybackupability', 'entryformability', 'wearability'].includes(e.name)) walk(p);
      continue;
    }
    if (!p.endsWith('.ets')) continue;
    const r = ts.transpileModule(fs.readFileSync(p, 'utf8'), {
      fileName: p.replace(/\.ets$/, '.ts'),
      reportDiagnostics: true,
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, experimentalDecorators: true, sourceMap: true },
    });
    for (const d of r.diagnostics || []) {
      console.error(`${path.relative(app, p)}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`);
      failed = true;
    }
    const dst = path.join(out, path.relative(app, p)).replace(/\.ets$/, '.js');
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    const map = JSON.parse(r.sourceMapText);
    map.sources = [p];
    fs.writeFileSync(dst, r.outputText.replace(/\/\/# sourceMappingURL=.*$/m, '') +
      '//# sourceMappingURL=data:application/json;base64,' + Buffer.from(JSON.stringify(map)).toString('base64') + '\n');
  }
}

walk(path.join(app, 'entry/src/main/ets'));
walk(path.join(app, 'wearable/src/main/ets'));
walk(path.join(app, 'entry/src/ohosTest/ets'));
process.exit(failed ? 1 : 0);

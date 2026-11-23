// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Runs the app's ohosTest suite (entry/src/ohosTest/ets/test/List.test.ets)
// under Node's test runner, with shim.cjs standing in for the phone (run.sh).
'use strict';
const path = require('node:path');
require('./shim.cjs');
const fs = require('node:fs');

const suite = require(path.join(process.env.CBB_TEST_OUT, 'entry/src/ohosTest/ets/test/List.test.js'));
(suite.default || suite)();

// Every module of the model, core and common code, the watch's too, is loaded, so that
// coverage counts the ones no test reaches too.
(function loadAll(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) loadAll(p);
    else if (p.endsWith('.js') && !p.includes(`${path.sep}ohosTest${path.sep}`)) require(p);
  }
})(process.env.CBB_TEST_OUT);

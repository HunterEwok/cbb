// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import labTest from './Lab.test';
import modelTest from './Model.test';
import watchTest from './Watch.test';

export default function testsuite() {
  modelTest();
  labTest();
  watchTest();
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Rust core's one entry point (docs/core-api.md), the group's rules every
// member shares, through the C functions of lite/ffi (cbb_core.h): the app
// asks the core instead of writing the rules again in C++.
#pragma once

#include "errors.h"

#include <QJsonObject>
#include <QJsonValue>

namespace Core {

// The version of the request and answer shapes the app speaks; call refuses
// a core of another.
const int abi = 1;

// Sends the operation op with args (left out when null) and returns the
// answer's ok. A refusal of the core, a core of another ABI or an answer that
// does not read comes back in failure, and ok is then null.
QJsonValue call(const QString &op, const QJsonValue &args, Failure *failure);

// The linked core as `cbb version` names it: "core X, abi N, source S".
QString versionLine(Failure *failure);

} // namespace Core

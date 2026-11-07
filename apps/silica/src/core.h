// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Rust core's one entry point (docs/core-api.md), the group's rules every
// member shares, through the C functions of ffi/ (cbb_core.h): the app
// asks the core instead of writing the rules again in C++.
#pragma once

#include "errors.h"

#include <QJsonObject>
#include <QJsonValue>

#include <cstddef>
#include <cstdint>

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

// An answer of ffi's join and member functions, which it frees: its ok,
// or its error in failure, the details under what.
QJsonObject take(uint8_t *answer, size_t len, const QString &what, Failure *failure);

// The core's signing callback (cbb_sign_fn): the key store signs the digest.
int32_t signDigest(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sigLen);
// The same with the admin key, for a phone that joins as an admin.
int32_t signAdminDigest(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sigLen);

} // namespace Core

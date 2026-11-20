// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The bytes between HUKS and the core: keys.cpp's, tested on the host
// (src/test/cpp/der_test.cpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace keys {

// ECDSA's raw r||s (64 bytes) in DER, for a keystore that gives it raw.
std::vector<uint8_t> derSignature(const uint8_t *raw);

// The uncompressed point of a P-256 SubjectPublicKeyInfo, as HUKS exports a
// public key, or of a bare point; empty when it is neither.
std::vector<uint8_t> pointOf(const uint8_t *spki, size_t len);

} // namespace keys

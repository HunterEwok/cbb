// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's keys in HUKS, HarmonyOS's keystore, P-256 keys that never
// leave its TEE (the level "hardware" of docs/apps.md, "Key levels"): the
// member key, the phone's device key in its group, which signs without
// asking, and the admin key (the root's key in a group the phone made, or
// the admin key the root certified), which signs only after the user's face,
// fingerprint or PIN, once for each action, as the iPhone's Secure Enclave
// key does: the consent lasts half a minute, so that an action that signs
// several times asks once.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace keys {

enum class Which { Member, Admin };

// What a failed call says: message is for the user, details for the log
// and, in debug mode, under the message.
struct Failure {
    std::string message;
    std::string details;
    bool failed() const { return !message.empty() || !details.empty(); }
};

struct Key {
    std::vector<uint8_t> point; // the public key, uncompressed (65 bytes)
    bool created = false;       // made by this call
};

// Finds the key, making it the first time. Blocks; call it off the main thread.
bool ensure(Which which, Key *key, Failure *failure);

// Deletes both keys when the phone leaves its group (D-83); a missing key is
// no failure.
bool forget(Failure *failure);

// Asks the user for the admin key: given a challenge (empty for the admin
// key, whose consent is by time), it answers the auth token that User
// Authentication Kit gave, or an empty token when the user declined. It is
// called on the signing thread and blocks until the app answers.
using AuthFn = std::function<std::vector<uint8_t>(const std::vector<uint8_t> &challenge, std::string *why)>;
void setAuth(AuthFn auth);

// Signs a SHA-256 digest (32 bytes) with the key: ECDSA P-256 in DER, at
// most 72 bytes. Blocks, for the admin key until the user answered.
bool sign(Which which, const uint8_t *digest, std::vector<uint8_t> *der, Failure *failure);

// The cbb_sign_fn of each key for the core (ffi/include/cbb_core.h); ctx is
// ignored.
int32_t signMember(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sigLen);
int32_t signAdmin(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sigLen);

} // namespace keys

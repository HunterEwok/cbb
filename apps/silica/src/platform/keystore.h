// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Where the phone keeps its member key, the one part of the key that differs
// between the systems: keystore_tee.cpp on Aurora, a P-256 key in the app's
// own OP-TEE token that never leaves it (docs/roadmap.md, item 60; the level
// "hardware" of "Key levels"); keystore_file.cpp on Sailfish OS and Aurora 4,
// a P-256 key in a file only the app reads (level 3, "file").
#pragma once

#include "errors.h"

#include <QByteArray>
#include <QString>

namespace KeyStore {

// Where the key lives, as the phone's hello says: "hardware" or "file".
QString store();

// Which key: the member key, the phone's device key in its group, or the
// admin key, which a phone that joins as an admin offers and the group's
// root certifies (docs/protocol.md, section 6, "A phone joins a computer's
// group"). The admin key is made only when the user asks to join as an
// admin.
enum class Which { Member, Admin };

// Why the phone has no hardware key: no OP-TEE at all (Sailfish OS, the
// emulator, a phone without a TEE), or the TEE failed.
enum class State { Ready, NoTee, Failed };

struct Key
{
    State state = State::Failed;
    QByteArray publicKey; // uncompressed point, 65 bytes
    bool created = false; // made by this call
    Failure failure;      // set unless Ready
};

// Finds the app's key, making it the first time. On Aurora it initializes
// the token through QCA the first time, and checks that the key is
// OP-TEE's: /dev/tee0 is there, the token is the initialized "Aurora TA" one
// and the key reads back never extractable and always sensitive. Blocks;
// call it off the GUI thread.
Key ensure(Which which = Which::Member);

// Signs digest (SHA-256, 32 bytes) with the key: ECDSA P-256 in DER, as the
// member protocol's signatures are. Empty on failure.
QByteArray sign(const QByteArray &digest, Failure *failure, Which which = Which::Member);

// ECDSA's raw r||s, as PKCS#11 gives it, in DER.
QByteArray derSignature(const QByteArray &raw);

} // namespace KeyStore

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
    bool pinNeeded = false; // the admin key waits for the user's PIN
    Failure failure;      // set unless Ready
};

// Finds the app's key, making it the first time. On Aurora it initializes
// the token through QCA the first time, and checks that the key is
// OP-TEE's: /dev/tee0 is there, the token is the initialized "Aurora TA" one
// and the key reads back never extractable and always sensitive. On Aurora
// the admin key lives in a token of its own behind the user's PIN (see
// below): it is found without the PIN, but made only while the PIN's
// login lasts, and pinNeeded says so otherwise. Blocks; call it off the GUI thread.
Key ensure(Which which = Which::Member);

// Signs digest (SHA-256, 32 bytes) with the key: ECDSA P-256 in DER, as the
// member protocol's signatures are. Empty on failure; the admin key signs
// only while its PIN's login lasts, and pinNeeded is set when it was not.
QByteArray sign(const QByteArray &digest, Failure *failure, Which which = Which::Member, bool *pinNeeded = nullptr);

// The admin key's PIN. Aurora 5.1.5 lets no regular app ask the system to
// confirm the user (docs/parity.md), so the admin and root key sits in a
// second OP-TEE token of the app, whose user PIN the user chooses and the
// TEE checks and counts: seven wrong PINs lock the token for good, and its
// SO PIN, random and kept nowhere, cannot unlock it (docs/protocol.md,
// section 3). The file store (Sailfish OS, Aurora 4) needs no PIN.
enum class PinState {
    None,   // the store needs no PIN
    NotSet, // no PIN yet: the first admin key sets it
    Set,    // asked before the admin key signs
    Locked, // seven wrong PINs: the admin key signs no more
    Failed, // the TEE did not answer
};

struct PinStatus
{
    PinState state = PinState::Failed;
    bool fewLeft = false;  // a wrong PIN was tried since the last right one
    bool lastTry = false;  // one more wrong PIN locks the token
    int triesLeft = 0;     // as far as the app counted, of seven
    Failure failure;       // set when Failed
};

// The PIN's state, from the token's flags. Blocks.
PinStatus adminPin();

enum class PinResult { Right, Wrong, Locked, Failed };

// Checks pin against the token, setting it first when none is set, and on
// Right keeps the token logged in, the PIN itself not kept: the admin key
// then signs without asking until it has not been used for two minutes, or
// dropAdminPin logs it out. A wrong PIN spends one of
// the seven tries; after says how many are left. Blocks.
PinResult enterAdminPin(const QByteArray &pin, PinStatus *after, Failure *failure);

// Changes the PIN, which the TEE checks first. Blocks.
PinResult changeAdminPin(const QByteArray &old, const QByteArray &pin, PinStatus *after, Failure *failure);

// Whether the login lasts (ending it once it does not), and logging out, as
// when the app leaves the screen. Both are cheap.
bool adminPinHeld();
void dropAdminPin();

// Deletes both keys, the member key and the admin key, when the phone
// leaves its group (D-83): the next ensure makes a new member key, so the
// phone joins again as a new device. An admin key whose PIN's login ended
// stays in its token, unusable without the PIN, and the next admin key
// replaces it. Its old key stays in the group's
// records until an admin removes it, and removing it then revokes only that
// key. Missing keys are no failure. Blocks; call it off the GUI thread.
bool forget(Failure *failure);

// ECDSA's raw r||s, as PKCS#11 gives it, in DER.
QByteArray derSignature(const QByteArray &raw);

} // namespace KeyStore

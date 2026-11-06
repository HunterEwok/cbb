// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Initializes the app's own OP-TEE token through Aurora's QCA keystore, the
// only way a regular app gets one (docs/roadmap.md, item 60). Called only
// while the token is uninitialized: QCA's plugin handles RSA and GOST keys
// alone and aborts the process when the keystore holds an EC key.
#pragma once

#include "errors.h"

namespace QcaInit {

// The token's label, and the name QCA gives the keystore.
extern const char tokenLabel[];
// The PIN QCA sets on the token; the token is the app's own, so a PIN known
// to every app protects nothing that the sandbox does not.
extern const char pin[];

// Asks QCA's provider qca-aurora-pkcs11 to initialize the keystore USERAPP.
// Blocks; call it off the GUI thread. Returns a null Failure when QCA says
// it did; the caller checks the token itself.
Failure initUserAppKeystore();

} // namespace QcaInit

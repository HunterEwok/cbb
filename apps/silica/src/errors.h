// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the app shows of an error, and the log every error goes to.
#pragma once

#include <QString>

// An error as the user sees it: a short message, and under it the causes
// (types, codes, the underlying messages), one per line.
struct Failure
{
    QString message;
    QString details;

    bool isNull() const { return message.isEmpty(); }
};

namespace Errors {

// Whether the app shows an error's details under its message. On in debug
// builds, off in release ones; the environment variable CBB_ERROR_DETAILS
// (1 or 0) or the setting errors/details overrides the build, the setting
// winning, so that a release build can show them when an error needs
// understanding.
bool showDetails();

// The text to show for f: the message, and the details under it when
// showDetails(). Logs f either way.
QString shown(const Failure &f);

// Writes a line to the app's log, ~/.local/share/tools.cbb/CBB/cbb.log, and
// to the system's journal.
void log(const QString &line);

} // namespace Errors

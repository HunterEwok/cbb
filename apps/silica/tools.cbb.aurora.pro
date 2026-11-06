# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# The CBB app for Aurora OS and Sailfish OS: one code, a package per system
# (packaging/<target>). build.sh writes core/ (the Rust core) and icons/ first
# and passes CBB_TARGET; only src/platform/ and packaging/ differ by target.
TARGET = tools.cbb.aurora
AURORAAPP_ICONS = 86x86 108x108 128x128 172x172

isEmpty(CBB_TARGET): CBB_TARGET = aurora5
!equals(CBB_TARGET, aurora5): error("CBB_TARGET $$CBB_TARGET is not built yet")

CONFIG += c++11
QT += network

# The spec passes VERSION=%{version} to qmake.
isEmpty(VERSION): VERSION = 0.0.0
DEFINES += CBB_VERSION=\\\"$$VERSION\\\"

INCLUDEPATH += $$PWD/src $$PWD/core/include
LIBS += $$PWD/core/$$QT_ARCH/libcbb_ffi.a -ldl -lpthread -lm

SOURCES += \
    src/main.cpp \
    src/app.cpp \
    src/core.cpp \
    src/errors.cpp \
    src/join.cpp \
    src/member.cpp \
    src/membership.cpp \
    src/platform/osinfo.cpp
HEADERS += \
    src/app.h \
    src/core.h \
    src/errors.h \
    src/join.h \
    src/member.h \
    src/membership.h \
    src/platform/keystore.h \
    src/platform/osinfo.h \
    src/platform/shell.h

# Aurora: libauroraapp, and the key in OP-TEE through QCA and libckteec.
equals(CBB_TARGET, aurora5) {
    SOURCES += \
        src/platform/keystore_tee.cpp \
        src/platform/qcainit.cpp \
        src/platform/shell_aurora.cpp
    HEADERS += \
        src/platform/pkcs11.h \
        src/platform/qcainit.h
    PKGCONFIG += qca2-qt5
    # Loaded here, not through CONFIG, so that the .desktop file comes from
    # packaging/ instead of the project's folder.
    load(auroraapp)
}

desktop.files = packaging/$$CBB_TARGET/$${TARGET}.desktop

DISTFILES += \
    qml/tools.cbb.aurora.qml \
    qml/pages/MainPage.qml \
    qml/pages/JoinPage.qml \
    qml/cover/CoverPage.qml \
    packaging/$$CBB_TARGET/tools.cbb.aurora.desktop \
    packaging/$$CBB_TARGET/tools.cbb.aurora.spec

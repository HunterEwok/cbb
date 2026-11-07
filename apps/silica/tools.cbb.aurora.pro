# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# The CBB app for Aurora OS and Sailfish OS: one code, a package per system
# (packaging/<target>). build.sh writes core/ (the Rust core) and icons/ first
# and passes CBB_TARGET; only src/platform/ and packaging/ differ by target.
TARGET = tools.cbb.aurora
AURORAAPP_ICONS = 86x86 108x108 128x128 172x172

isEmpty(CBB_TARGET): CBB_TARGET = aurora5
!contains(CBB_TARGET, ^(aurora5|aurora4|sailfish)$): error("CBB_TARGET $$CBB_TARGET is none of aurora5, aurora4, sailfish")
# Sailfish OS names a package for Jolla's store harbour-*; Aurora's are
# reverse domain names. The app's data folder follows the name the sandbox
# gives it (the .desktop file's OrganizationName and ApplicationName).
equals(CBB_TARGET, sailfish) {
    TARGET = harbour-cbb
    CBB_APP_NAME = cbb
} else {
    CBB_APP_NAME = aurora
}
DEFINES += CBB_APP_NAME=\\\"$$CBB_APP_NAME\\\"

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

# Aurora 5: libauroraapp, and the key in OP-TEE through QCA and libckteec.
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

# Aurora 4: libauroraapp too, the key in a file (level 3).
equals(CBB_TARGET, aurora4) {
    SOURCES += \
        src/platform/keystore_file.cpp \
        src/platform/shell_aurora.cpp
    load(auroraapp)
}

# Sailfish OS: libsailfishapp, the key in a file (level 3).
equals(CBB_TARGET, sailfish) {
    SOURCES += \
        src/platform/keystore_file.cpp \
        src/platform/shell_sailfish.cpp
    SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172
    load(sailfishapp)
}

desktop.files = packaging/$$CBB_TARGET/$${TARGET}.desktop

DISTFILES += \
    qml/tools.cbb.aurora.qml \
    qml/pages/MainPage.qml \
    qml/pages/JoinPage.qml \
    qml/cover/CoverPage.qml \
    packaging/$$CBB_TARGET/$${TARGET}.desktop \
    packaging/$$CBB_TARGET/$${TARGET}.spec

# The translations (translations/cbb-<language>.ts, English being the
# source), compiled by lrelease into the package's translations/ folder,
# where main.cpp loads the system language's.
TRANSLATIONS = $$files(translations/cbb-*.ts)
lrelease.input = TRANSLATIONS
lrelease.output = ${QMAKE_FILE_BASE}.qm
lrelease.commands = $$[QT_INSTALL_BINS]/lrelease -silent ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
lrelease.CONFIG += no_link target_predeps
QMAKE_EXTRA_COMPILERS += lrelease
qm.files = $$OUT_PWD/cbb-*.qm
qm.path = /usr/share/$$TARGET/translations
qm.CONFIG += no_check_exist
INSTALLS += qm
DISTFILES += $$TRANSLATIONS

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
Name:       tools.cbb.aurora
Summary:    One clipboard for your phones and computers
Version:    0.5.0
Release:    1
License:    AGPL-3.0-only
URL:        https://cbb.tools
Source0:    %{name}-%{version}.tar.bz2

# The Rust core comes in as a static library; nothing to strip apart.
%global debug_package %{nil}

# The camera page that reads a device's join code.
Requires: qt5-qtdeclarative-import-multimedia
BuildRequires: pkgconfig(auroraapp)
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(Qt5Network)
BuildRequires: pkgconfig(Qt5DBus)
BuildRequires: pkgconfig(qca2-qt5)

%description
CBB syncs the clipboard between your phones and computers on the home network.

%prep
%autosetup

%build
%qmake5 VERSION=%{version} CBB_TARGET=aurora5
%make_build

%install
%make_install

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png

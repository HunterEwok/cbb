# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
Name:       harbour-cbb
Summary:    One clipboard for your phones and computers
Version:    0.5.0
Release:    1
License:    AGPL-3.0-only
URL:        https://cbb.tools
Source0:    %{name}-%{version}.tar.bz2

# The Rust core comes in as a static library; nothing to strip apart.
%global debug_package %{nil}
# Jolla's store takes no package that requires its own libraries.
%define __provides_exclude_from ^%{_datadir}/.*$

Requires:   sailfishsilica-qt5 >= 0.10.9
Requires:   qt5-qtdeclarative-import-multimedia
BuildRequires: pkgconfig(sailfishapp) >= 1.0.2
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(Qt5Network)
BuildRequires: pkgconfig(Qt5DBus)

%description
CBB syncs the clipboard between your phones and computers on the home network.
Not yet tested on a phone.

%prep
%autosetup

%build
%qmake5 VERSION=%{version} CBB_TARGET=sailfish
%make_build

%install
%make_install

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png

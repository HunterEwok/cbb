#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds what the HarmonyOS app links before DevEco Studio or hvigor builds
# the app: the Rust core's static library in build/ffi (ffi/bind.sh
# harmony), with OpenHarmony's native SDK from OHOS_NDK_HOME, or else
# downloaded by ffi/ohos-sdk.sh into build/ohos-sdk.
#   build.sh          the core's library
#   build.sh hap      also the app's package, with hvigorw from the HarmonyOS
#                     command line tools on PATH (their download needs a
#                     Huawei developer account) and the developer's signing
#                     config in build-profile.json5
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
if [ -z "${OHOS_NDK_HOME:-}" ]; then
	OHOS_NDK_HOME=$(sh "$root/ffi/ohos-sdk.sh" "$here/build/ohos-sdk" | tail -n 1)
	export OHOS_NDK_HOME
fi
(cd "$root" && sh ffi/bind.sh harmony "$here/build/ffi")
if [ "${1:-}" = hap ]; then
	cd "$here"
	ohpm install
	hvigorw assembleHap --mode module -p product=default --no-daemon
fi

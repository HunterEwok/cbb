#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Compiles the app's ArkTS and runs the ArkTS linter with OpenHarmony's
# compiler (the ets-loader of the SDK's ArkTS part), without DevEco Studio or
# the HarmonyOS tools, which need a Huawei developer account; with Node.js
# and Python 3:
#   check.sh SDK   SDK as ffi/ohos-sdk.sh SDK ets left it
# It checks each module (the phone's entry and the watch's wearable), and
# fails on any error of the compiler or the linter, or when the files the
# two modules share differ. The HarmonyOS SDK's kits that OpenHarmony's
# lacks (Scan Kit, Share Kit, Wear Engine) come from check/,
# hvigor's BuildProfile is a stub in debug mode, and the native module's
# types are imported from where hvigor would resolve them.
set -eu
if [ $# -ne 1 ]; then
	echo "usage: check.sh SDK" >&2
	exit 2
fi
sdk=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
loader=$sdk/ets/build-tools/ets-loader
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for kit in ScanKit ShareKit WearEngine; do
	cp "$here/check/@kit.$kit.d.ts" "$sdk/ets/kits/"
	cp "$here/check/@kit.$kit.json" "$loader/kit_configs/"
done

# The files the phone's module and the watch's share.
for f in common/WatchState.ets common/Wear.ets core/Errors.ets core/Text.ets; do
	if ! cmp -s "$here/entry/src/main/ets/$f" "$here/wearable/src/main/ets/$f"; then
		echo "check.sh: entry and wearable differ in ets/$f" >&2
		exit 1
	fi
done

failed=0
for module in entry wearable; do
	w=$work/$module
	mkdir -p "$w"
	main=$w/main
	cp -R "$here/$module/src/main" "$main"
	sed -i "s#import BuildProfile from 'BuildProfile';#import BuildProfile from './BuildProfileStub';#" "$main/ets/core/Errors.ets"
	printf 'export default class BuildProfile {\n  static readonly DEBUG: boolean = true;\n}\n' >"$main/ets/core/BuildProfileStub.ets"
	if [ -d "$main/cpp" ]; then
		mkdir -p "$main/ets/napi"
		cp "$main/cpp/types/libcbb_napi/index.d.ts" "$main/ets/napi/index.d.ts"
		grep -rl "from 'libcbb_napi.so'" "$main/ets" | xargs sed -i "s#from 'libcbb_napi.so'#from '../napi/index'#"
	fi

	# module.json as hvigor makes it: the module's and the app's JSON5.
	node -e '
	const fs = require("fs");
	const JSON5 = require(process.argv[1]);
	const m = JSON5.parse(fs.readFileSync(process.argv[2], "utf8"));
	m.app = JSON5.parse(fs.readFileSync(process.argv[3], "utf8")).app;
	m.app.compileSdkVersion = "6.0";
	fs.writeFileSync(process.argv[4], JSON.stringify(m));
	' "$loader/node_modules/json5" "$main/module.json5" "$here/AppScope/app.json5" "$w/module.json"

	mkdir -p "$w/res" "$w/out"
	"$sdk/toolchains/restool" -i "$here/AppScope" -i "$main" -j "$w/module.json" -p tools.cbb.harmony \
		-o "$w/res" -r "$w/res/ResourceTable.txt" -f >"$w/restool.log" 2>&1 || {
		cat "$w/restool.log"
		exit 1
	}

	rm -rf "$loader/node_modules/.cache"
	mkdir -p "$loader/node_modules/.cache"
	(cd "$loader" && node node_modules/webpack/bin/webpack.js --config webpack.config.js --env buildMode=debug \
		--env aceModuleRoot="$main/ets" --env aceModuleBuild="$w/out" \
		--env aceProfilePath="$main/resources/base/profile" --env aceModuleJsonPath="$w/module.json" \
		--env appResource="$w/res/ResourceTable.txt") >"$w/log.txt" 2>&1 || true
	python3 "$here/check/report.py" "$w" "$loader" || failed=1
done
exit $failed

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build cbbcore && cgo

package core

/*
#cgo CFLAGS: -I${SRCDIR}/../../ffi/include
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libcbb_ffi.a -lm
#cgo linux LDFLAGS: -ldl -lpthread
#include "cbb_core.h"
*/
import "C"

import "unsafe"

const how = "cgo"

const linked = true

func abi() (int, error) { return int(C.cbb_abi()), nil }

func call(request []byte) ([]byte, error) {
	var n C.size_t
	var p *C.uint8_t
	if len(request) == 0 {
		p = C.cbb_call(nil, 0, &n)
	} else {
		p = C.cbb_call((*C.uint8_t)(unsafe.Pointer(&request[0])), C.size_t(len(request)), &n)
	}
	defer C.cbb_free(p, n)
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

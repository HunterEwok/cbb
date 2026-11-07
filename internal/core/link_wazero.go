// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build cbbwasm && !(cbbcore && cgo)

package core

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// module is wasm/ built for wasm32-unknown-unknown. The file is never
// here: wasm/build.sh writes the go build overlay that lays the built
// module over this name.
//
//go:embed cbb_core.wasm
var module []byte

const how = "WebAssembly under wazero"

const linked = true

var (
	once     sync.Once
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	loadErr  error

	// mu holds the one instance, which runs one call at a time; a call
	// that traps drops it, and the next call makes a new one.
	mu       sync.Mutex
	instance api.Module
)

// memoryPages is the most memory the core may have, in pages of 64 KiB:
// 64 MiB, many times what a set of records at its limits needs
// (core/tests/memory.rs).
const memoryPages = 1024

// load compiles the module once, with the host's randomness as its one
// import.
func load() error {
	once.Do(func() {
		ctx := context.Background()
		// The core's memory is capped (memoryPages of 64 KiB), so that no
		// input makes it grow to the 4 GiB a module may have; a call past
		// the cap traps, and the next call starts afresh.
		runtime = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(memoryPages))
		_, err := runtime.NewHostModuleBuilder("env").
			NewFunctionBuilder().
			WithFunc(func(_ context.Context, m api.Module, buf, n uint32) int32 {
				b, ok := m.Memory().Read(buf, n)
				if !ok {
					return 1
				}
				rand.Read(b)
				return 0
			}).
			Export("cbb_random").
			Instantiate(ctx)
		if err != nil {
			loadErr = fmt.Errorf("core: the module's import: %w", err)
			return
		}
		if compiled, err = runtime.CompileModule(ctx, module); err != nil {
			loadErr = fmt.Errorf("core: compile the module: %w", err)
		}
	})
	return loadErr
}

// get returns the instance, making it when there is none; mu is held.
func get(ctx context.Context) (api.Module, error) {
	if err := load(); err != nil {
		return nil, err
	}
	if instance == nil {
		m, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
		if err != nil {
			return nil, fmt.Errorf("core: start the module: %w", err)
		}
		instance = m
	}
	return instance, nil
}

// drop closes the instance after a call that failed in it; mu is held.
func drop(ctx context.Context) {
	if instance != nil {
		_ = instance.Close(ctx)
		instance = nil
	}
}

func abi() (int, error) {
	mu.Lock()
	defer mu.Unlock()
	ctx := context.Background()
	m, err := get(ctx)
	if err != nil {
		return 0, err
	}
	r, err := m.ExportedFunction("cbb_abi").Call(ctx)
	if err != nil || len(r) != 1 {
		drop(ctx)
		return 0, errors.Join(errors.New("core: cbb_abi failed"), err)
	}
	return int(uint32(r[0])), nil
}

func call(request []byte) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()
	ctx := context.Background()
	m, err := get(ctx)
	if err != nil {
		return nil, err
	}
	answer, err := callIn(ctx, m, request)
	if err != nil {
		drop(ctx)
		return nil, err
	}
	return answer, nil
}

func callIn(ctx context.Context, m api.Module, request []byte) ([]byte, error) {
	n := uint64(len(request))
	r, err := m.ExportedFunction("cbb_alloc").Call(ctx, n)
	if err != nil || len(r) != 1 {
		return nil, errors.Join(errors.New("core: cbb_alloc failed"), err)
	}
	p := uint32(r[0])
	if !m.Memory().Write(p, request) {
		return nil, errors.New("core: the request does not fit the module's memory")
	}
	r, err = m.ExportedFunction("cbb_call").Call(ctx, uint64(p), n)
	if err != nil || len(r) != 1 {
		return nil, errors.Join(errors.New("core: cbb_call failed"), err)
	}
	ap, an := uint32(r[0]>>32), uint32(r[0])
	b, ok := m.Memory().Read(ap, an)
	if !ok {
		return nil, errors.New("core: the answer is outside the module's memory")
	}
	answer := append([]byte(nil), b...)
	if _, err := m.ExportedFunction("cbb_free").Call(ctx, uint64(ap), uint64(an)); err != nil {
		return nil, fmt.Errorf("core: cbb_free failed: %w", err)
	}
	return answer, nil
}

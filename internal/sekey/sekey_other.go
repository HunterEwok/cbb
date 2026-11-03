// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin || !cgo

package sekey

type ref struct{}

func (ref) release()                     {}
func (ref) sign([]byte) ([]byte, error)  { return nil, ErrNoEnclave }
func (ref) agree([]byte) ([]byte, error) { return nil, ErrNoEnclave }

func available() bool { return false }

func create() (ref, []byte, []byte, error) { return ref{}, nil, nil, ErrNoEnclave }

func load([]byte) (ref, []byte, error) { return ref{}, nil, ErrNoEnclave }

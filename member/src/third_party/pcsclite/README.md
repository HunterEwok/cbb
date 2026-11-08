# pcsclite

A client of pcscd's socket, the PC/SC daemon of Linux and the BSDs, without
libpcsclite: enough to list the readers, connect to a card, send it APDUs and
disconnect, for `member/src/piv.rs`.

Translated to Rust from `winscard.go`, `msg.go` and `doc.go` of
github.com/gballet/go-libpcsclite at v0.0.0-20250918194357-1ec6f2e601c6, which
the Go side's `internal/piv` uses. The BSD 3-Clause license is in `LICENSE`.

Changes: reads take whole messages (`read_exact`), every answer's length is
checked before it is used, reader names end at their first NUL, and the
socket has read and write timeouts.

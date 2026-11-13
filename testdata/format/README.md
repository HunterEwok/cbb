# The 0.6 format's vectors

The vectors of the 0.6 wire format: the strict CBOR profile, keys, signed envelopes, records,
keys statements, commands, grants, server credentials, frames, the copy and the TLS key
container. `gen.py` writes them (`python3 -I testdata/format/gen.py testdata/format`); they are
deterministic, with test keys from fixed labels and RFC 6979 signatures, so writing them again
gives the same bytes. Wraps and sealed parts are placeholder bytes of the right size.

Each signed vector has a verdict: `take`, `hold` (a valid form that a reader keeps and passes
on but does not apply) or `refuse` with the rule it breaks (`cbor/…`, `env/…`, `sig/…`,
`frame/…` at the format level; `records/…`, `keys/…`, `form/…` for a kind's own fields).

Three readers check them:

- the Rust core, `core/src/format` (`cargo test -p cbb-core --lib format::`), which also checks
  that everything it takes has exactly one form (the fuzz target `format` and its property
  tests);
- `check/`, a reader in Go that shares no code with the core (fxamacker/cbor, Go's crypto and
  `x509`), its own module: `cd testdata/format/check && go run . ..`;
- `gen.py`'s own strict reader, as it writes them.

Field-level refusals (`records/…`, `form/default`) are for the readers of each kind.

`push.json` (push to a phone whose app is closed, format section 20.4: message `push`, the push
service's messages, the sealed body with its derived nonce, the send key's signatures and the
UnifiedPush token) is written apart by
`push_gen.py` (`python3 -I testdata/format/push_gen.py`), which borrows `gen.py`'s encoder and
table checks and writes only that file; the core (`cargo test -p cbb-core --lib push::`) and
`check/push.go` (Go's ChaCha20-Poly1305, HKDF and HMAC) read it.

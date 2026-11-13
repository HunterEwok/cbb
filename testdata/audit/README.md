# Closed audit findings and their tests

`closed.json` lists each closed finding of the security audits by an opaque id, with the tests
that hold it closed (language, file, test name). It names closed findings only: no title,
severity or text, and nothing about findings still open.

`go run ./tools/coverage -audit testdata/audit/closed.json` fails when a named test is gone, so
a finding cannot reopen quietly (docs/testing.md, "Coverage"). A fix that closes a finding adds
its row in the same pull request.

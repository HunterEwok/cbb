#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""The vectors of push (format section 20.4): the tables of message `push`
(t 28), the UnifiedPush token, the push service's messages (t 100-104) and
the body's plaintext; registrations; sealed bodies; `once`; and the cases a
later version may write, which a 0.6 reader holds or treats neutrally.

Written apart from gen.py (whose helpers it borrows: the profile's encoder
and strict reader, frames and table checks) so that running it changes
only push.json. Deterministic: every key and nonce is fixed.

    python3 testdata/format/push_gen.py
"""

import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen  # noqa: E402
from gen import Bad, check_map, dec, enc, frame, head  # noqa: E402

TOKEN = "bytes 1..4096"
MAX_UP_URL = 4000
ENV = "uint 1..255"
TABLES = {
    "push": [
        (2, "push/token", TOKEN, False),
        (3, "push/env", ENV, False),
        (4, "push/key", "bytes 32", False),
        (5, "push/seq", "uint 1..9007199254740992", True),
        (6, "push/kinds", "uint 0..4294967295", True),
    ],
    "push-up": [
        (1, "push-up/url", "text 1..4000", True),
        (2, "push-up/p256dh", "bytes 65", True),
        (3, "push-up/auth", "bytes 16", True),
    ],
    "push/hello": [(2, "push/hello/credentials", "array 1..2 of envelope", True)],
    "push/ready": [(2, "push/ready/left", "uint 0..4294967295", True)],
    "push/send": [
        (2, "push/send/n", "uint 1..4294967295", True),
        (3, "push/send/token", TOKEN, True),
        (4, "push/send/env", ENV, True),
        (5, "push/send/once", "bytes 16", True),
        (6, "push/send/body", "bytes 1..2972", True),
        (7, "push/send/ttl", "uint 1..4", False),
    ],
    "push/sent": [
        (2, "push/sent/n", "uint 1..4294967295", True),
        (3, "push/sent/status", "uint 1..255", True),
        (4, "push/sent/retry_ms", "uint 1..9223372036854775807", False),
    ],
    "push/error": [(2, "push/error/reason", "text 1..256", True)],
    "pushbody": [
        (0, "pushbody/kind", "uint 1..9223372036854775807", True),
        (2, "pushbody/copy", "bytes 1..2944", False),
        (3, "pushbody/id", "bytes 16", False),
        (4, "pushbody/origin", "bytes 16", False),
        (5, "pushbody/event", "uint 1..9223372036854775807", False),
        (6, "pushbody/device", "bytes 16", False),
        (7, "pushbody/time_ms", "uint 0..9223372036854775807", False),
    ],
}
TYPES = {28: "push", 100: "push/hello", 101: "push/ready", 102: "push/send", 103: "push/sent", 104: "push/error"}
gen.TABLES.update(TABLES)

MAX_BODY = 2972
PLAIN = MAX_BODY - 28
ENVS = {1: "APNs", 2: "APNs sandbox", 3: "FCM", 4: "UnifiedPush", 5: "Push Kit", 6: "Aurora"}
LABEL_BODY, LABEL_ONCE, LABEL_AD = b"cbb push body v1", b"cbb push once v1", b"cbb push v1"


def fake(label, n):
    return hashlib.sha256(b"push vector " + label.encode()).digest()[:n] if n <= 32 else (fake(label, 32) + fake(label + "+", n - 32))


def derive(pk, info):
    # HKDF-SHA256, salt empty (RFC 5869: a salt of zeros).
    return gen.hkdf(pk, b"", info)


def once(pk, ident):
    return hmac.new(derive(pk, LABEL_ONCE), ident, hashlib.sha256).digest()[:16]


def ad(seq):
    return LABEL_AD + b"\x00" + seq.to_bytes(8, "big")


def pad_to(entries, size):
    """The plaintext: the map with the one `pad` (key 1) that brings it to size."""
    base = enc(entries)
    if len(base) == size:
        return base
    for plen in range(0, size):
        m = dict(entries)
        m[1] = bytes(plen)
        b = enc(m)
        if len(b) == size:
            return b
        if len(b) > size:
            return None
    return None


def read_body(b):
    """The verdict of a plaintext: the kind's name, or the rule it breaks."""
    try:
        v = dec(b)
    except Bad as e:
        return e.rule
    # A kind a later version numbers is the neutral hint before any other
    # field is read against the table.
    kind = v.get(0) if isinstance(v, dict) else None
    if not isinstance(kind, int) or isinstance(kind, bool) or kind < 1:
        return "pushbody/kind"
    if kind > 3:
        return "neutral"
    r = check_map("pushbody", v)
    if r:
        return r
    if 1 in v and (not isinstance(v[1], bytes) or any(v[1])):
        return "pushbody/pad"
    kind = v[0]
    needs = {1: [2], 2: [3, 4], 3: [3, 5]}.get(kind, [])
    names = {2: "pushbody/copy", 3: "pushbody/id", 4: "pushbody/origin", 5: "pushbody/event"}
    for n in needs:
        if n not in v:
            return names[n]
    rest = {k: x for k, x in v.items() if k != 1}
    if pad_to(rest, len(b)) != b:
        return "pushbody/pad"
    return {1: "copy", 2: "waits", 3: "event"}.get(kind, "neutral")


def seal(pk, seq, plain, nonce):
    return nonce + ChaCha20Poly1305(derive(pk, LABEL_BODY)).encrypt(nonce, plain, ad(seq))


def open_body(pk, seq, sealed):
    if len(sealed) < 28 or len(sealed) > MAX_BODY:
        return "pushbody/size"
    try:
        plain = ChaCha20Poly1305(derive(pk, LABEL_BODY)).decrypt(sealed[:12], sealed[12:], ad(seq))
    except Exception:
        return "pushbody/open"
    return read_body(plain)


def registration(m):
    """The verdict of message `push`: on, off, or a rule."""
    r = check_map("push", m)
    if r:
        return r
    have = [n in m for n in (2, 3, 4)]
    if m[6] == 0 and not any(have):
        return "off"
    if m[6] != 0 and all(have):
        return "on"
    return "push/shape"


def up_token(t):
    try:
        v = dec(t)
    except Bad as e:
        return e.rule
    r = check_map("push-up", v)
    if r:
        return r
    if not up_url(v[1]):
        return "push-up/url"
    try:
        if v[2][0] != 4:
            raise ValueError
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), v[2])
    except ValueError:
        return "push-up/p256dh"
    return "take"


def point(label):
    """An uncompressed point of P-256, from a fixed scalar."""
    k = ec.derive_private_key(int.from_bytes(fake(label, 32), "big") % (2**255), ec.SECP256R1())
    return k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def up_url(url):
    """The endpoint's rows: printable ASCII, https, no user or fragment, a
    host name of two labels at least (never an address), port 443."""
    if not url.startswith("https://") or "#" in url or not all(0x21 <= ord(c) <= 0x7E for c in url):
        return False
    rest = url[len("https://"):]
    authority = rest
    for sep in "/?":
        authority = authority.split(sep, 1)[0]
    if "@" in authority:
        return False
    host = authority
    if ":" in authority:
        host, port = authority.rsplit(":", 1)
        if port != "443":
            return False
    labels = host.split(".")
    ok = lambda lab: (1 <= len(lab) <= 63 and all(c.isascii() and (c.isalnum() or c == "-") for c in lab)
                      and not lab.startswith("-") and not lab.endswith("-"))
    return len(host) <= 253 and len(labels) >= 2 and all(ok(lab) for lab in labels) and not labels[-1].isdigit()


def main():
    pk = fake("push key", 32)
    token = fake("apns token", 32)
    out = {
        "draft": "format-0.6-bytes.md section 20.4, 2026-11-12",
        "labels": {"body": LABEL_BODY.decode(), "once": LABEL_ONCE.decode(), "ad": LABEL_AD.decode()},
        "tables": {name: [{"n": n, "rule": r, "type": t, "needed": nd} for n, r, t, nd in rows]
                   for name, rows in TABLES.items()},
        "types": {str(t): name for t, name in TYPES.items()},
        "envs": {str(e): {"platform": p, "body": MAX_BODY} for e, p in ENVS.items()},
    }

    # registrations
    regs = []

    def reg(name, m, note=None):
        f = frame({0: 28, **m})
        e = {"name": name, "verdict": registration(dec(f[4:])), "frame": f.hex()}
        if note:
            e["note"] = note
        regs.append(e)

    on = {2: token, 3: 1, 4: pk, 5: 3, 6: 3}
    reg("on, copies and events, APNs", on)
    reg("off", {5: 4, 6: 0})
    reg("a later platform's env is held", {**on, 3: 200}, "kept and handed on as it is (E-1)")
    reg("only a later version's kinds bit", {**on, 6: 64}, "asks for nothing a 0.6 sender sends")
    reg("a later version's bit 31 beside copies", {**on, 6: (1 << 31) | 1}, "unknown bits are ignored")
    reg("a token of 4096 bytes", {**on, 2: fake("long token", 4096)})
    reg("a token of 4097 bytes", {**on, 2: fake("long token", 4097)})
    reg("off with a token", {2: token, 5: 4, 6: 0})
    reg("on without a key", {2: token, 3: 1, 5: 4, 6: 1})
    reg("on without an env", {2: token, 4: pk, 5: 4, 6: 1})
    reg("a key of 31 bytes", {**on, 4: pk[:31]})
    reg("seq 0", {**on, 5: 0})
    reg("seq over 2^53", {**on, 5: (1 << 53) + 1})
    reg("kinds 2^32", {**on, 6: 1 << 32})
    reg("env 0", {**on, 3: 0})
    reg("env 256", {**on, 3: 256})
    reg("without seq", {2: token, 3: 1, 4: pk, 6: 1})
    reg("a field of a later version is skipped", {**on, 9: b"x"})
    out["registrations"] = regs

    # bodies
    bodies = []
    nonce = fake("nonce", 12)
    cases = [
        ("a reduced copy (its bytes are the copy's own vectors')", {0: 1, 2: fake("reduced copy", 32) * 40}),
        ("a copy waits", {0: 2, 3: fake("copy id", 16), 4: fake("origin", 16)}),
        ("a device was removed", {0: 3, 3: fake("record id", 16), 5: 2, 6: fake("device", 16), 7: 1_790_000_000_000}),
        ("the root changed", {0: 3, 3: fake("record id 2", 16), 5: 4}),
        ("the group stopped", {0: 3, 3: fake("record id 3", 16), 5: 6}),
        ("an event a later version numbers", {0: 3, 3: fake("record id 4", 16), 5: 99}),
        ("a kind a later version numbers, with a field of its own", {0: 4, 9: b"later"}),
        ("a later kind whose field 3 is not 16 bytes", {0: 7, 3: b"short", 5: "text"}),
        ("a field 8 of a later version beside a known kind", {0: 2, 3: fake("copy id", 16), 4: fake("origin", 16), 8: 1}),
        ("a copy without the copy", {0: 1}),
        ("a hint without its id", {0: 2, 4: fake("origin", 16)}),
        ("an event without its event", {0: 3, 3: fake("record id", 16)}),
        ("kind 0", {0: 0}),
    ]
    for name, m in cases:
        plain = pad_to(m, PLAIN)
        assert plain is not None, name
        sealed = seal(pk, 3, plain, nonce)
        assert len(sealed) == MAX_BODY
        bodies.append({"name": name, "key": pk.hex(), "seq": 3, "env": 1, "plaintext": plain.hex(),
                       "sealed": sealed.hex(), "verdict": open_body(pk, 3, sealed)})
    good = bytes.fromhex(bodies[1]["sealed"])
    good_plain = bytes.fromhex(bodies[1]["plaintext"])
    bent_pad = bytearray(good_plain)
    bent_pad[20] = 1
    long_pad = dict(cases[1][1])
    other = enc({**long_pad, 1: bytes(10)})  # a smaller body, padded for its own size: read
    for name, sealed, seq in [
        ("under another registration's number", good, 4),
        ("a byte bent", good[:100] + bytes([good[100] ^ 1]) + good[101:], 3),
        ("27 bytes", good[:27], 3),
        ("a pad byte not zero", seal(pk, 3, bytes(bent_pad), nonce), 3),
        ("a smaller body with its own one padding", seal(pk, 3, other, nonce), 3),
        ("a padding one byte too short for its size", seal(pk, 3, enc({**long_pad, 1: bytes(10)}) + b"\x00", nonce), 3),
    ]:
        bodies.append({"name": name, "key": pk.hex(), "seq": seq, "env": 1, "sealed": sealed.hex(),
                       "verdict": open_body(pk, seq, sealed)})
    out["bodies"] = bodies

    out["once"] = [{"key": pk.hex(), "id": i.hex(), "once": once(pk, i).hex()}
                   for i in (fake("copy id", 16), fake("record id", 16))]

    # UnifiedPush tokens
    ups = []
    up = {1: "https://up.example.org/" + "a" * (MAX_UP_URL - 23), 2: point("p256dh"), 3: fake("auth", 16)}
    for name, t in [
        ("the longest endpoint", up),
        ("a short endpoint", {**up, 1: "https://ntfy.example.net/upAbc123"}),
        ("port 443 named, and a query", {**up, 1: "https://up.example.org:443/x?t=1"}),
        ("port 8443", {**up, 1: "https://up.example.org:8443/x"}),
        ("a trailing dot", {**up, 1: "https://up.example.org./x"}),
        ("a backslash", {**up, 1: "https://up.example.org\\@other.example/"}),
        ("http", {**up, 1: "http://up.example.org/x"}),
        ("https:// alone", {**up, 1: "https://"}),
        ("an endpoint of 4001 bytes", {**up, 1: "https://up.example.org/" + "a" * (MAX_UP_URL - 22)}),
        ("a single label", {**up, 1: "https://localhost/x"}),
        ("an IPv4 address", {**up, 1: "https://10.0.0.1/x"}),
        ("an IPv6 address", {**up, 1: "https://[::1]/x"}),
        ("port 8080", {**up, 1: "https://up.example.org:8080/x"}),
        ("a user", {**up, 1: "https://user@up.example.org/x"}),
        ("a fragment", {**up, 1: "https://up.example.org/x#f"}),
        ("a space", {**up, 1: "https://up.example.org/a b"}),
        ("a key of 64 bytes", {**up, 2: fake("p256dh", 64)}),
        ("a key of 65 bytes not on the curve", {**up, 2: b"\x04" + fake("p256dh", 64)}),
        ("a compressed key padded to 65 bytes", {**up, 2: b"\x02" + up[2][1:]}),
        ("without auth", {1: up[1], 2: up[2]}),
    ]:
        b = enc(t)
        ups.append({"name": name, "token": b.hex(), "length": len(b), "verdict": up_token(b)})
    assert ups[0]["length"] <= 4096
    out["unifiedpush"] = ups

    # the service's messages
    msgs = []
    body = bytes(MAX_BODY)

    def msg(name, m, sized=None):
        f = frame(m)
        e = {"name": name, "t": m[0], "frame": f.hex(), "length": len(f) - 4,
             "verdict": check_map(TYPES[m[0]], dec(f[4:])) or "take"}
        if sized is not None:
            e["sized"] = sized
        msgs.append(e)

    send = {0: 102, 2: 1, 3: token, 4: 1, 5: once(pk, fake("copy id", 16)), 6: body}
    msg("send to APNs", send, True)
    msg("send with the longest token and a ttl", {**send, 2: 4294967295, 3: fake("long token", 4096), 4: 4, 7: 4}, True)
    msg("send of a body not its env's size", {**send, 6: body[:100]}, False)
    msg("send to a later platform", {**send, 4: 200}, False)
    msg("send of a body over 2972", {**send, 6: bytes(MAX_BODY + 1)})
    msg("send without once", {k: v for k, v in send.items() if k != 5})
    msg("send with ttl 5", {**send, 7: 5})
    msg("ready", {0: 101, 2: 1200})
    msg("sent", {0: 103, 2: 1, 3: 1})
    msg("sent over budget with a retry", {0: 103, 2: 2, 3: 3, 4: 60000})
    msg("sent with a status of a later version", {0: 103, 2: 3, 3: 77})
    msg("sent with status 0", {0: 103, 2: 3, 3: 0})
    msg("error", {0: 104, 2: "the group's credentials do not verify"})
    msg("hello with two credentials", {0: 100, 2: [[enc({1: 3}), bytes(64)], [enc({1: 4}), bytes(64)]]})
    msg("hello without credentials", {0: 100, 2: []})
    for m in msgs:
        if m["t"] == 102 and m.get("sized"):
            # An APNs token keeps a send on the 4096 step, the longest on 16384.
            assert m["length"] == (16384 if "longest" in m["name"] else 4096), m
    out["messages"] = msgs

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "push.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("wrote", path)


if __name__ == "__main__":
    main()

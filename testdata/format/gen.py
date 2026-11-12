#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# The test vectors of the 0.6 wire format (testdata/format), from the byte
# layout the owner agreed on 2026-11-11. The Rust core (core/src/format)
# and the Go reader in check/ read them.
# Run: python3 -I gen.py testdata/format
# Deterministic: the keys come from fixed labels, ECDSA uses RFC 6979.
# The wraps and sealed parts are placeholder bytes of the right size:
# these vectors test the format (bytes, fields, signatures), not X-Wing.

import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# ---------------------------------------------------------------- CBOR


class Raw:
    """Bytes inserted as they are (for refused forms)."""

    def __init__(self, b):
        self.b = b


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def enc(v):
    if isinstance(v, Raw):
        return v.b
    if isinstance(v, bool):
        raise TypeError("no booleans in the profile")
    if isinstance(v, int):
        assert 0 <= v < 2**63
        return head(0, v)
    if isinstance(v, (bytes, bytearray)):
        return head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        ks = sorted(v)
        return head(5, len(v)) + b"".join(enc(k) + enc(v[k]) for k in ks)
    raise TypeError(type(v))


class Bad(Exception):
    def __init__(self, rule):
        self.rule = rule


def dec(b, max_depth=8, max_count=4096):
    """The profile's strict reader. Returns the value or raises Bad(rule)."""
    pos = 0

    def need(n):
        if pos + n > len(b):
            raise Bad("cbor/truncated")

    def arg(ai):
        nonlocal pos
        if ai < 24:
            return ai
        if ai == 31:
            raise Bad("cbor/indefinite")
        if ai > 27:
            raise Bad("cbor/reserved")
        n = 1 << (ai - 24)
        need(n)
        v = int.from_bytes(b[pos : pos + n], "big")
        pos += n
        if (n == 1 and v < 24) or (n > 1 and v < (1 << (8 * n // 2))):
            raise Bad("cbor/shortest")
        return v

    def item(depth):
        nonlocal pos
        need(1)
        ib = b[pos]
        pos += 1
        major, ai = ib >> 5, ib & 31
        if major == 1:
            raise Bad("cbor/negative")
        if major == 6:
            raise Bad("cbor/tag")
        if major == 7:
            raise Bad("cbor/simple")
        n = arg(ai)
        if major == 0:
            if n >= 2**63:
                raise Bad("cbor/int-range")
            return n
        if major in (2, 3):
            need(n)
            s = b[pos : pos + n]
            pos += n
            if major == 3:
                try:
                    return s.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    raise Bad("cbor/utf8")
            return bytes(s)
        if depth >= max_depth:
            raise Bad("cbor/depth")
        if n > max_count:
            raise Bad("cbor/count")
        if major == 4:
            return [item(depth + 1) for _ in range(n)]
        m = {}
        last = -1
        for _ in range(n):
            need(1)
            if b[pos] >> 5 != 0:
                raise Bad("cbor/map-key")
            k = item(depth + 1)
            if k > 65535:
                raise Bad("cbor/map-key")
            if k <= last:
                raise Bad("cbor/map-order")
            last = k
            m[k] = item(depth + 1)
        return m

    v = item(0)
    if pos != len(b):
        raise Bad("cbor/trailing")
    return v


def diag(v):
    if isinstance(v, int):
        return str(v)
    if isinstance(v, bytes):
        return "h'" + v.hex() + "'"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(diag(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}: {diag(v[k])}" for k in sorted(v)) + "}"
    raise TypeError(type(v))


# ---------------------------------------------------------------- keys

ES256, XWING, X25519 = 1, 2, 3


def sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


class Signer:
    def __init__(self, name):
        self.name = name
        d = int.from_bytes(sha(b"cbb test key " + name.encode()), "big") % (N - 1) + 1
        self.priv = ec.derive_private_key(d, ec.SECP256R1())
        self.pub = self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.key = [ES256, self.pub]
        self.hash = sha(enc(self.key))
        self.id16 = self.hash[:16]
        self.d = d

    def sign(self, label, data):
        msg = label.encode() + b"\x00" + data
        der = self.priv.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        if s > N // 2:
            s = N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(key, label, data, sig):
    """ES256 check of the profile: 64 bytes, low S."""
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key[1])
    try:
        pk.verify(encode_dss_signature(r, s), label.encode() + b"\x00" + data,
                  ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def fake(label, n):
    """Placeholder bytes of a given size (X-Wing keys, wraps, sealed parts)."""
    out = b""
    i = 0
    while len(out) < n:
        out += sha(label.encode(), i.to_bytes(4, "big"))
        i += 1
    return out[:n]


ROOT = Signer("root")
ROOT2 = Signer("root 2")
ADMIN = Signer("admin key")
PHONE = Signer("phone member key")
LAPTOP = Signer("laptop member key")
BOARD = Signer("board member key")
LOCK = Signer("lock member key")
TABLET = Signer("tablet member key")
ADMIN2 = Signer("admin key 2")
ADMIN3 = Signer("admin key 3")
STRANGER = Signer("stranger")
PERIOD = Signer("period key")
SRVKEY = Signer("laptop server key")
OPERATOR = Signer("server operator")
GROUP = ROOT.id16
T0 = 1793000000000  # 2026-10-26, display only

LABELS = {
    "record": "cbb record v3",
    "keys": "cbb keys v1",
    "command": "cbb command v3",
    "credential": "cbb credential v2",
    "grant": "cbb grant v1",
    "beacon": "cbb beacon v1",
    "card": "cbb server card v1",
}


def envelope(kind, signer, body_map, body_raw=None):
    body = body_raw if body_raw is not None else enc(body_map)
    return enc([body, signer.sign(LABELS[kind], body)]), body


# ---------------------------------------------------------------- vectors

out = {}


def profile_vectors():
    v = []

    def ok(name, value):
        b = enc(value)
        v.append({"name": name, "hex": b.hex(), "valid": True, "diag": diag(value)})

    def bad(name, rule, b):
        v.append({"name": name, "hex": b.hex(), "valid": False, "rule": rule})

    ok("uint 0", 0)
    ok("uint 23", 23)
    ok("uint 24", 24)
    ok("uint 255", 255)
    ok("uint 256", 256)
    ok("uint 65536", 65536)
    ok("uint 2^32", 2**32)
    ok("uint 2^63-1", 2**63 - 1)
    ok("empty bytes", b"")
    ok("bytes", b"\x01\x02\x03")
    ok("text", "cbb")
    ok("text utf-8", "café ✓")
    ok("empty array", [])
    ok("empty map", {})
    ok("map in key order", {1: 1, 2: 2, 24: 3, 256: 4, 65535: 5})
    ok("nested to depth 8", [[[[[[[[0]]]]]]]])
    bad("uint 0 in two bytes", "cbor/shortest", bytes.fromhex("1800"))
    bad("uint 23 in two bytes", "cbor/shortest", bytes.fromhex("1817"))
    bad("uint 255 in three bytes", "cbor/shortest", bytes.fromhex("1900ff"))
    bad("uint 65535 in five bytes", "cbor/shortest", bytes.fromhex("1a0000ffff"))
    bad("uint 2^32-1 in nine bytes", "cbor/shortest", bytes.fromhex("1b00000000ffffffff"))
    bad("uint 2^63", "cbor/int-range", bytes.fromhex("1b8000000000000000"))
    bad("length in two bytes", "cbor/shortest", bytes.fromhex("580103"))
    bad("negative integer", "cbor/negative", bytes.fromhex("20"))
    bad("tag 24", "cbor/tag", bytes.fromhex("d81840"))
    bad("false", "cbor/simple", bytes.fromhex("f4"))
    bad("true", "cbor/simple", bytes.fromhex("f5"))
    bad("null", "cbor/simple", bytes.fromhex("f6"))
    bad("undefined", "cbor/simple", bytes.fromhex("f7"))
    bad("half float 0.0", "cbor/simple", bytes.fromhex("f90000"))
    bad("double 1.0", "cbor/simple", bytes.fromhex("fb3ff0000000000000"))
    bad("indefinite bytes", "cbor/indefinite", bytes.fromhex("5f4101ff"))
    bad("indefinite array", "cbor/indefinite", bytes.fromhex("9f00ff"))
    bad("indefinite map", "cbor/indefinite", bytes.fromhex("bf0000ff"))
    bad("break alone", "cbor/simple", bytes.fromhex("ff"))
    bad("reserved additional info 28", "cbor/reserved", bytes.fromhex("1c"))
    bad("text key", "cbor/map-key", bytes.fromhex("a1616100"))
    bad("bytes key", "cbor/map-key", bytes.fromhex("a1410100"))
    bad("key over 65535", "cbor/map-key", bytes.fromhex("a11a0001000000"))
    bad("keys out of order", "cbor/map-order", bytes.fromhex("a202000100"))
    bad("duplicate key, same value", "cbor/map-order", bytes.fromhex("a201000100"))
    bad("24 before 2", "cbor/map-order", bytes.fromhex("a21818000200"))
    bad("invalid utf-8", "cbor/utf8", bytes.fromhex("62c328"))
    bad("overlong utf-8", "cbor/utf8", bytes.fromhex("62c0af"))
    bad("surrogate in utf-8", "cbor/utf8", bytes.fromhex("63eda080"))
    bad("nested to depth 9", "cbor/depth", bytes.fromhex("81" * 9 + "00"))
    bad("trailing byte", "cbor/trailing", bytes.fromhex("0000"))
    bad("two items", "cbor/trailing", bytes.fromhex("8000"))
    bad("cut bytes", "cbor/truncated", bytes.fromhex("430102"))
    bad("cut map", "cbor/truncated", bytes.fromhex("a201"))
    bad("array of 4097", "cbor/count", head(4, 4097) + b"\x00" * 4097)
    bad("empty input", "cbor/truncated", b"")
    # check our own reader against the list
    for t in v:
        b = bytes.fromhex(t["hex"])
        try:
            dec(b)
            got = None
        except Bad as e:
            got = e.rule
        if t["valid"]:
            assert got is None, (t["name"], got)
        else:
            assert got == t["rule"], (t["name"], got, t["rule"])
    return v


def set_key(x):
    """The order of a set (section 1): an element's encoding, an array
    element by its first element's."""
    return enc(x[0]) if isinstance(x, list) else enc(x)


def srt(xs):
    return sorted(xs, key=set_key)


def rec(signer, seq, typ, fields, prev=None, time=None, extra=None):
    m = {1: typ, 2: GROUP, 3: signer.hash, 4: seq, 6: time if time is not None else T0 + seq * 1000}
    if prev is not None:
        m[5] = prev
    m.update(fields)
    if extra:
        m.update(extra)
    return m


def record_vectors():
    take, refuse = [], []
    chain = {}

    def seen_of(*signers):
        """`seen` (section 4.2): each signer's head as the author holds it,
        `[key hash, seq, record ID]`, a set."""
        return srt([[x.hash, chain[x.name][0], chain[x.name][1]] for x in signers])

    def add(name, signer, typ, fields, verdict="take", note=None, extra=None, sig2=None):
        seq = chain.get(signer.name, (0, None))[0] + 1
        prev = chain.get(signer.name, (0, None))[1]
        m = rec(signer, seq, typ, fields, prev=prev, extra=extra)
        env, body = envelope("record", signer, m)
        if 8 in m:  # room for a second signature: [body, sig, sig2]
            env = enc([body, signer.sign(LABELS["record"], body),
                       sig2 if sig2 is not None else ADMIN.sign(LABELS["record"], body)])
        rid = sha(body)
        if verdict == "take":
            chain[signer.name] = (seq, rid)
        e = {
            "name": name,
            "verdict": verdict,
            "signer": signer.name,
            "diag": diag(m),
            "body": body.hex(),
            "id": rid.hex(),
            "envelope": env.hex(),
        }
        if note:
            e["note"] = note
        take.append(e)
        return env, body, m

    # device records
    add("root's own phone", ROOT, 1, {10: PHONE.key, 11: "Phone", 12: 2, 13: 0b1111,
                                      17: 4, 18: 2, 20: ADMIN.key, 21: 0b111111111,
                                      22: (1 << 10) - 1, 23: 1})
    lap_env, lap_body, lap_m = add("laptop admitted by the root", ROOT, 1,
                                   {10: LAPTOP.key, 11: "Laptop", 12: 1, 13: 0b0111, 16: 0b111, 17: 1, 18: 2})
    add("board admitted by an admin, base rights", ADMIN, 1,
        {10: BOARD.key, 11: "Kettle", 12: 4, 13: 0b0011, 17: 10},
        note="an ordinary leaf: any admin with admit admits it, and it obeys the group's admins")
    add("settings", ROOT, 7, {10: 0, 14: 1,
                              15: [[1, "forward.cbb.tools:8764", OPERATOR.key]]})
    add("copies", ADMIN, 8, {10: 30000, 11: seen_of(ROOT)})
    # hubs keep the user's order (not sorted), each once
    add("hubs", ROOT, 10, {10: sorted([LAPTOP.id16, PHONE.id16], reverse=True), 11: seen_of(ADMIN)})
    add("revoke", ROOT, 2, {10: srt([STRANGER.hash, Signer("stranger 2").hash]), 11: seen_of(ADMIN, ROOT)})
    add("freeze", ROOT, 3, {10: [ADMIN.hash], 11: seen_of(ADMIN, ROOT)})
    thaw_target = take[-1]["id"]
    add("thaw", ROOT, 4, {10: [bytes.fromhex(thaw_target)], 11: seen_of(ADMIN)})
    add("claim", ADMIN, 5, {10: ROOT2.key, 11: seen_of(ADMIN, ROOT)})
    add("resolve", ROOT, 6, {10: [bytes.fromhex(take[-1]["id"])]})
    add("recovery", ROOT, 11, {10: Signer("recovery").key})
    add("handover", ROOT, 12, {10: ADMIN.hash})
    add("checkpoint", ROOT, 9, {10: srt([[ADMIN.hash, 3, bytes.fromhex(take[-2]["id"])],
                                         [ROOT.hash, 10, bytes.fromhex(take[-1]["id"])]]),
                                11: srt([bytes.fromhex(take[0]["id"]), bytes.fromhex(take[1]["id"])])})
    add("device with an optional field from a later version", ROOT, 1,
        {10: Signer("tv").key, 11: "TV", 12: 1, 13: 0b0011},
        extra={300: "later"},
        note="key 300 is in the optional zone: ignored, covered by the signature")
    add("device with a critical field from a later version", ROOT, 1,
        {10: Signer("tv 2").key, 11: "TV 2", 12: 1, 13: 0b0011},
        verdict="hold", extra={99: 1},
        note="key 99 is unknown in the critical zone: keep, pass on, do not apply")
    add("record of a type from a later version", ROOT, 40, {10: b"\x01"}, verdict="hold",
        note="unknown type: keep, pass on, do not apply")
    add("second signer named (room only in 0.6)", ROOT, 7, {10: 3600000},
        verdict="hold", extra={8: ADMIN.hash},
        note="signer2 (key 8) with a three-element envelope; 0.6 checks the first signature, keeps the record and never applies it")
    add("second signature of 3000 bytes (a later algorithm)", ROOT, 7, {10: 3600000},
        verdict="hold", extra={8: ADMIN.hash}, sig2=fake("later signature", 3000),
        note="sig2 is not fixed at 64 bytes; up to 4096 it is kept, outside the ID; the size counts from the body")

    add("admin admits a desktop with secrets (its own device has them)", ADMIN, 1,
        {10: Signer("desktop member key").key, 11: "Desktop", 12: 1, 13: 0b1011, 17: 1, 18: 2},
        note="the admin's own device (the root's phone record, admin key) has the secrets bit, "
             "so it may give it; one without it may not (records/device/admin-rights)")

    add("guarded lock admitted by the root", ROOT, 1,
        {10: LOCK.key, 11: "Lock", 12: 4, 13: 0b0011, 17: 10, 25: 1},
        note="guarded (25): only the root admits it and signs its grant")
    add("admin marks a leaf guarded", ADMIN, 1,
        {10: Signer("lamp member key").key, 11: "Lamp", 12: 4, 13: 0b0011, 17: 10, 25: 1},
        verdict="refuse",
        note="records/device/guarded: only a root sets guarded; the form is valid, the evaluation counts it for nothing")

    # the root takes the admin key off its device; what the key signed up
    # to the head named in seen (26) still counts
    add("root takes the admin key off a device", ROOT, 1,
        {10: PHONE.key, 11: "Phone", 12: 2, 13: 0b1111, 17: 4, 18: 2, 23: 1, 26: seen_of(ADMIN)})

    # an admin's later record of the board that widens it: counts for nothing
    add("admin widens a device it admitted", ADMIN, 1,
        {10: BOARD.key, 11: "Kettle", 12: 4, 13: 0b0111, 17: 10},
        verdict="refuse",
        note="records/device/admin-rights: an admin never widens rights (here: hub); "
             "the form is valid, the evaluation counts it for nothing")

    # refusals, built on the laptop record
    sig = ROOT.sign(LABELS["record"], lap_body)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")

    def bad(name, rule, env_bytes):
        refuse.append({"name": name, "rule": rule, "verdict": "refuse", "envelope": env_bytes.hex()})

    bad("high S", "sig/low-s", enc([lap_body, r.to_bytes(32, "big") + (N - s).to_bytes(32, "big")]))
    bad("DER signature", "sig/size", enc([lap_body, encode_dss_signature(r, s)]))
    bad("signature over another label", "sig/verify",
        enc([lap_body, ROOT.sign("cbb command v3", lap_body)]))
    bad("signature of another key", "sig/verify", enc([lap_body, ADMIN.sign(LABELS["record"], lap_body)]))
    bad("r = 0", "sig/range", enc([lap_body, bytes(32) + sig[32:]]))
    bad("three elements without signer2", "env/shape", enc([lap_body, sig, sig]))
    bad("one element", "env/shape", enc([lap_body]))
    bad("body as a map, not bytes", "env/shape", Raw(head(4, 2) + enc(lap_m) + enc(sig)).b)
    bad("trailing byte after the envelope", "cbor/trailing", enc([lap_body, sig]) + b"\x00")
    m2 = rec(ROOT, 91, 7, {10: 3600000}, extra={8: ADMIN.hash})
    b2 = enc(m2)
    bad("second signature over 4096 bytes", "env/sig2",
        enc([b2, ROOT.sign(LABELS["record"], b2), fake("later signature", 4097)]))

    def bad_body(name, rule, m=None, raw=None):
        body = raw if raw is not None else enc(m)
        bad(name, rule, enc([body, ROOT.sign(LABELS["record"], body)]))

    m = dict(lap_m)
    m[13] = 0
    bad_body("rights 0 written (default)", "form/default", m)
    m = dict(lap_m)
    del m[11]
    bad_body("device without a name", "records/device/name", m)
    m = dict(lap_m)
    m[11] = "Lap\ntop"
    bad_body("control character in a name", "records/device/name", m)
    for what, ch in [("a C1 control", "\u009b"), ("a line separator", "\u2028"),
                     ("a paragraph separator", "\u2029"), ("a right-to-left override", "\u202e"),
                     ("a bidi isolate", "\u2066")]:
        m = dict(lap_m)
        m[11] = "Lap" + ch + "top"
        bad_body("name with " + what, "records/device/name", m)
    m = dict(lap_m)
    m[10] = [ES256, LAPTOP.pub[:33]]
    bad_body("member key of 33 bytes", "keys/es256", m)
    m = dict(lap_m)
    m[10] = [ES256, b"\x04" + bytes(64)]
    bad_body("member key not on the curve", "keys/es256", m)
    m = dict(lap_m)
    m[10] = [XWING, fake("x", 1216)]
    bad_body("member key of a KEM algorithm", "records/device/key", m)
    m = dict(lap_m)
    m[3] = ROOT.hash[:16]
    bad_body("signer of 16 bytes", "records/signer", m)
    m = dict(lap_m)
    m[4] = 0
    bad_body("seq 0", "records/seq", m)
    m = dict(lap_m)
    m[4] = 2**31
    bad_body("seq 2^31", "records/seq", m)
    m = dict(lap_m)
    m[2] = STRANGER.id16
    bad_body("another group", "records/group", m)
    m = dict(lap_m)
    m[12] = 9
    bad_body("unknown role", "records/device/role", m)
    m = dict(lap_m)
    m[16] = 0b1000
    bad_body("unknown capability bit", "records/device/caps", m)
    # os numbers: 11 harmonyos; a number this version does not name (a later
    # version's system) is taken as it is and shown as unknown
    for name, n, os_name in [("HarmonyOS phone", 11, "harmonyos"), ("phone of a later system", 12, "unknown")]:
        add(f"device with os {n} ({os_name})", ROOT, 1,
            {10: Signer(name).key, 11: name, 12: 2, 13: 0b0011, 17: n},
            note="an os number this version does not name is kept, signed bytes untouched, and shown as unknown"
            if os_name == "unknown" else None)
        take[-1]["os"] = n
        take[-1]["os_name"] = os_name
    # non-canonical body: the same map with a key written long
    mm = dict(lap_m)
    body_long = enc(mm).replace(bytes([0x0b]) + enc("Laptop"), bytes([0x18, 0x0b]) + enc("Laptop"), 1)
    bad_body("key written in two bytes", "cbor/shortest", raw=body_long)
    m = dict(lap_m)
    m[25] = 1
    bad_body("guarded on a member, not a leaf", "records/device/guarded", m)
    m = dict(lap_m)
    m[15] = [[PHONE.hash, 1]]
    bad_body("field 15 (accepts, gone)", "form/critical", m)
    sm = {1: 7, 2: GROUP, 3: ROOT.hash, 4: 90, 6: T0, 10: 0, 13: 64}
    bad_body("settings field 13 (admin_limit, gone)", "form/critical", sm)
    m = dict(lap_m)
    m[24] = LAPTOP.hash
    bad_body("replaces itself", "records/device/replaces", m)
    # sets (section 1): sorted by the element's encoding (an array element
    # by its first element's), each value once; hubs each once, in order
    a, b = srt([STRANGER.hash, Signer("stranger 2").hash])
    i1, i2 = srt([bytes.fromhex(take[0]["id"]), bytes.fromhex(take[1]["id"])])
    sa, sb = srt([[ADMIN.hash, 2, i1], [ROOT.hash, 5, i2]])
    ha, hb = srt([[ADMIN.hash, 3, i1], [ROOT.hash, 11, i2]])
    for name, rule, typ, fields in [
        ("revoke keys out of order", "records/revoke/keys", 2, {10: [b, a], 11: [sa, sb]}),
        ("revoke keys with one twice", "records/revoke/keys", 2, {10: [a, a], 11: [sa, sb]}),
        ("revoke seen out of order", "records/revoke/seen", 2, {10: [a], 11: [sb, sa]}),
        ("revoke seen with one key twice", "records/revoke/seen", 2, {10: [a], 11: [sa, [sa[0], 3, i2]]}),
        ("revoke seen entry without its record ID", "records/revoke/seen", 2, {10: [a], 11: [sa[:2], sb]}),
        ("revoke seen entry at sequence 0", "records/revoke/seen", 2, {10: [a], 11: [[sa[0], 0, sa[2]], sb]}),
        ("thaw records out of order", "records/thaw/records", 4, {10: [i2, i1], 11: [sa]}),
        ("checkpoint heads out of order", "records/checkpoint/heads", 9, {10: [hb, ha]}),
        ("checkpoint heads with one key twice", "records/checkpoint/heads", 9, {10: [ha, [ha[0], 4, i2]]}),
        ("checkpoint keep out of order", "records/checkpoint/keep", 9, {10: [ha, hb], 11: [i2, i1]}),
        ("hubs with one device twice", "records/hubs/hubs", 10, {10: [LAPTOP.id16, LAPTOP.id16], 11: [sa]}),
        ("device seen out of order", "records/device/seen", 1, {**{k: lap_m[k] for k in (10, 11, 12)}, 26: [sb, sa]}),
        ("thaw seen out of order", "records/thaw/seen", 4, {10: [i1], 11: [sb, sa]}),
        ("thaw without its seen", "records/thaw/seen", 4, {10: [i1]}),
        ("hubs seen with one key twice", "records/hubs/seen", 10, {10: [LAPTOP.id16], 11: [sa, [sa[0], 3, i2]]}),
        ("copies seen entry without its record ID", "records/copies/seen", 8, {10: 30000, 11: [sa[:2]]}),
        ("copies without its seen", "records/copies/seen", 8, {10: 30000}),
    ]:
        bad_body(name, rule, rec(ROOT, 90, typ, fields))
    return take, refuse


def statement_vectors():
    take, refuse = [], []

    def st(signer, epoch, seal, extra=None):
        m = {1: 1, 2: GROUP, 3: signer.hash, 4: epoch, 6: T0 + epoch, 10: [XWING, seal]}
        if extra:
            m.update(extra)
        env, body = envelope("keys", signer, m)
        return m, env, body

    for name, sg, ep in [("laptop, epoch 1", LAPTOP, 1), ("laptop, epoch 2", LAPTOP, 2),
                         ("board, epoch 1", BOARD, 1)]:
        m, env, body = st(sg, ep, fake(name, 1216))
        take.append({"name": name, "verdict": "take", "diag": diag(m), "body": body.hex(),
                     "id": sha(body).hex(), "envelope": env.hex()})
    m, env, body = st(LAPTOP, 1, fake("short", 1215))
    refuse.append({"name": "seal key of 1215 bytes", "rule": "keys/xwing", "verdict": "refuse",
                   "envelope": env.hex()})
    m, env, body = st(LAPTOP, 0, fake("e0", 1216))
    refuse.append({"name": "epoch 0", "rule": "statements/epoch", "verdict": "refuse",
                   "envelope": env.hex()})
    m = {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 3, 10: [XWING, fake("admin signs", 1216)]}
    body = enc(m)
    refuse.append({"name": "signed by an admin, not the device", "rule": "sig/verify",
                   "verdict": "refuse", "envelope": enc([body, ADMIN.sign(LABELS["keys"], body)]).hex()})
    return take, refuse


def command_vectors():
    take, refuse = [], []

    def cmd(typ, signer, n, to, extra, sealed=True):
        m = {1: typ, 2: GROUP, 3: signer.hash, 4: n, 6: T0 + 5000, 7: T0 + 35000,
             10: to, 11: sha(b"cmd", n.to_bytes(8, "big"))[:16]}
        m.update(extra)
        if sealed:
            m[14] = 1
            ad = LABELS["command"].encode() + b"\x00" + enc(m)
            m[15] = fake("sealed " + str(n), 1120 + 40 + 16)
            return m, ad
        return m, None

    m, ad = cmd(3, ADMIN, 1793000005000, LAPTOP.id16, {})
    env, body = envelope("command", ADMIN, m)
    take.append({"name": "paste, sealed", "verdict": "take", "diag": diag(m), "body": body.hex(),
                 "envelope": env.hex(),
                 "seal_ad": (LABELS["command"].encode() + b"\x00" +
                             enc({k: v for k, v in m.items() if k != 15})).hex(),
                 "orders": enc({10: 1, 12: 1, 13: "hello"}).hex(),
                 "note": "orders are what `sealed` holds once opened; seal_ad is the label, a zero byte and the body without key 15"})
    m, _ = cmd(4, ADMIN, 1793000006000, LAPTOP.id16, {}, sealed=False)
    env, body = envelope("command", ADMIN, m)
    take.append({"name": "paste-off, no orders", "verdict": "take", "diag": diag(m),
                 "body": body.hex(), "envelope": env.hex()})
    m, _ = cmd(10, PHONE, 7, LOCK.id16, {13: fake("nonce", 16)})
    env, body = envelope("command", PHONE, m)
    take.append({"name": "device command to a guarded lock, with its nonce", "verdict": "take",
                 "diag": diag(m), "body": body.hex(), "envelope": env.hex(),
                 "orders": enc({10: "heat", 11: enc({1: 90})}).hex()})
    m, _ = cmd(3, ADMIN, 9, LAPTOP.id16, {7: T0 + 5000 + 30001})
    m[7] = T0 + 5000 + 30001
    env, body = envelope("command", ADMIN, m)
    refuse.append({"name": "lifetime over 30 s", "rule": "commands/expires", "verdict": "refuse",
                   "envelope": env.hex()})
    m, _ = cmd(10, PHONE, 8, LOCK.id16, {})
    env, body = envelope("command", PHONE, m)
    refuse.append({"name": "command to a guarded lock without a nonce", "rule": "commands/nonce", "verdict": "refuse",
                   "envelope": env.hex(),
                   "note": "the form is valid; the lock, which knows it is guarded, refuses it"})
    m, _ = cmd(10, PHONE, 9, LOCK.id16, {12: 4, 13: fake("nonce 2", 16)})
    env, body = envelope("command", PHONE, m)
    refuse.append({"name": "field 12 (class, gone)", "rule": "form/critical", "verdict": "refuse",
                   "envelope": env.hex(), "note": "command classes are gone; 12 stays unused"})
    m, _ = cmd(3, ADMIN, 10, LAPTOP.id16, {}, sealed=False)
    m[300] = 1
    env, body = envelope("command", ADMIN, m)
    take.append({"name": "optional field from a later version", "verdict": "take",
                 "diag": diag(m), "body": body.hex(), "envelope": env.hex(),
                 "note": "a paste without `sealed` is refused later by a receiver with a keys statement; at the form level it is taken"})
    m, _ = cmd(3, ADMIN, 11, LAPTOP.id16, {99: 1})
    env, body = envelope("command", ADMIN, m)
    refuse.append({"name": "critical field from a later version", "rule": "form/critical",
                   "verdict": "refuse", "envelope": env.hex(),
                   "note": "a command is never held: it is refused"})
    return take, refuse


def grant_vectors(admin_record):
    """Two kinds of leaf (design-small-device section 15). A grant is one
    signed envelope (section 7) for one leaf of one group, and lists the
    keys the leaf obeys (`commanders`). The root signs any grant; for an
    ordinary leaf a commander of its current grant signs one too, naming
    the grant it replaces (field 18), and the first comes from the admitter
    with the root's record of that admin key (message field 3). A guarded
    leaf takes grants from the root only and carries `guarded`. The leaf
    keeps the root's counter and the admins' counter apart. Each vector
    names the leaf that reads it (`leaf`); the group is the file's."""
    take, refuse, sequences = [], [], []
    by_hash = lambda keys: sorted(keys, key=lambda k: sha(enc(k)))

    def message(genv, admin=None):
        msg = {0: 20, 2: dec(genv)}
        if admin is not None:
            msg[3] = dec(admin)
        return msg

    def signed(g, signer):
        g = dict(g)
        g[3] = signer.hash
        genv, gbody = envelope("grant", signer, g)
        assert len(gbody) <= 2048
        return g, genv, gbody

    def ok(name, g, signer, admin=None):
        g, genv, gbody = signed(g, signer)
        msg = message(genv, admin)
        take.append({"name": name, "verdict": "take", "leaf": g[10].hex(), "grant_diag": diag(g),
                     "grant": gbody.hex(), "envelope": genv.hex(), "message": enc(msg).hex(),
                     "frame": frame(msg).hex()})
        return g

    def bad(name, rule, msg, leaf):
        refuse.append({"name": name, "rule": rule, "verdict": "refuse", "leaf": leaf.hex(),
                       "message": enc(msg).hex()})

    kettle = {1: 1, 2: GROUP, 10: BOARD.id16, 12: by_hash([ADMIN.key, ADMIN2.key]),
              13: [[LAPTOP.id16, LAPTOP.key]], 14: sorted([LAPTOP.hash, PHONE.hash]), 16: T0 + 9000}
    ok("ordinary kettle, first grant signed by the admitting admin", {**kettle, 4: 1}, ADMIN,
       admin=admin_record)
    lock = {1: 1, 2: GROUP, 4: 3, 10: LOCK.id16, 12: by_hash([PHONE.key, LAPTOP.key]),
            13: sorted([[LAPTOP.id16, LAPTOP.key], [TABLET.id16, TABLET.key]], key=lambda a: a[0]),
            14: sorted([LAPTOP.hash, PHONE.hash]), 15: 1, 16: T0 + 9000}
    g = ok("guarded lock, grant signed by the root", lock, ROOT)
    ok("guarded lock, lifetime of 40 days", {**lock, 11: 3456000000}, ROOT)
    ok("guarded lock, an optional field from a later version", {**lock, 300: "later"}, ROOT)
    L, K = LOCK.id16, BOARD.id16

    def root_bad(name, rule, fields, leaf=L):
        _, genv, _ = signed(fields, ROOT)
        bad(name, rule, message(genv), leaf)

    _, genv, _ = signed(g, ADMIN)
    bad("guarded grant signed by an admin", "grants/guarded", message(genv, admin_record), L)
    root_bad("lifetime in an ordinary grant", "grants/life",
             {**{k: v for k, v in g.items() if k != 15}, 11: 86400000})
    root_bad("guarded with the value 2", "grants/guarded-value", {**g, 15: 2})
    root_bad("guarded lifetime 0", "grants/life", {**g, 11: 0})
    root_bad("guarded lifetime over 40 days", "grants/life", {**g, 11: 3456000001})
    root_bad("guarded lifetime as text", "grants/life", {**g, 11: "forever"})
    root_bad("nine commanders", "grants/commanders", {**g, 12: by_hash([Signer(f"c{i}").key for i in range(9)])})
    root_bad("five readers", "grants/readers",
             {**g, 13: sorted([[Signer(f"r{i}").id16, Signer(f"r{i}").key] for i in range(5)], key=lambda a: a[0])})
    root_bad("readers as a number", "grants/readers", {**g, 13: 5})
    root_bad("a reader without its key", "grants/readers", {**g, 13: [[LAPTOP.id16]]})
    root_bad("a reader with text for its key", "grants/readers", {**g, 13: [[LAPTOP.id16, "key"]]})
    root_bad("neighbors as text", "grants/neighbors", {**g, 14: "peers"})
    root_bad("a neighbour of 16 bytes", "grants/neighbors", {**g, 14: [LAPTOP.id16]})
    root_bad("grant for another leaf", "grants/shape", {**g, 10: Signer("lamp member key").id16})
    root_bad("grant for another group", "grants/shape", {**g, 2: ROOT2.id16})
    root_bad("grant of another type", "grants/shape", {**g, 1: 2})
    root_bad("grant with an unknown critical field", "form/critical", {**g, 200: 1})
    root_bad("grant with field 9", "form/critical", {**g, 9: 1})
    root_bad("root grant naming a grant it replaces", "grants/replaces", {**g, 18: sha(b"some grant")})
    g2 = {**g, 3: ROOT.hash, 8: ADMIN.hash}
    gb2 = enc(g2)
    bad("grant with a second signer", "form/critical",
        message(enc([gb2, ROOT.sign(LABELS["grant"], gb2), ADMIN.sign(LABELS["grant"], gb2)])), L)
    _, genv, _ = signed({**kettle, 4: 2}, ADMIN)
    bad("admin's first grant without the root's record", "grants/admin", message(genv), K)
    root_bad("a reader under another device's ID", "grants/readers",
             {**g, 13: [[TABLET.id16, LAPTOP.key]]})
    # the root's record in a first grant is read as a record: a device
    # record of this group with the fields of 0.6 only
    rec_body = dec(dec(admin_record)[0])
    _, genv, _ = signed({**kettle, 4: 2}, ADMIN)

    def record_bad(name, fields, raw=None):
        renv = raw if raw is not None else envelope("record", ROOT, fields)[0]
        bad(name, "grants/admin", message(genv, renv), K)

    record_bad("admin's record with a critical field from a later version", {**rec_body, 99: 1})
    record_bad("admin's record of another type", {**rec_body, 1: 7})
    record_bad("admin's record of another group", {**rec_body, 2: ROOT2.id16})
    record_bad("admin's record without a name", {k: v for k, v in rec_body.items() if k != 11})
    rb2 = enc({**rec_body, 8: ADMIN.hash})
    record_bad("admin's record naming a second signer", None,
               enc([rb2, ROOT.sign(LABELS["record"], rb2), ADMIN.sign(LABELS["record"], rb2)]))
    _, genv, _ = signed({**kettle, 4: 2, 18: sha(b"some grant")}, ADMIN)
    bad("admin's first grant naming a grant it replaces", "grants/replaces", message(genv, admin_record), K)
    for name, rule, field, val in [
        ("commanders out of order", "grants/commanders", 12, list(reversed(g[12]))),
        ("readers out of order", "grants/readers", 13, list(reversed(g[13]))),
        ("neighbors out of order", "grants/neighbors", 14, list(reversed(g[14]))),
        ("neighbors with one twice", "grants/neighbors", 14, [g[14][0], g[14][0]]),
    ]:
        root_bad(name, rule, {**g, field: val})
    bad("message without its grant", "grants/shape", {0: 20}, L)
    _, genv, gbody = signed({**kettle, 4: 2}, ROOT)
    bad("grant signed by a key other than its signer's", "sig/verify",
        message(enc([gbody, ADMIN.sign(LABELS["grant"], gbody)])), K)

    # Sequences: the grants one leaf receives in order, each checked against
    # what the leaf kept from those it took before. An admin grant after the
    # first names the kept grant (field 18) unless the step says otherwise.
    class Seq:
        def __init__(self, name, leaf):
            self.kept = None
            self.row = {"name": name, "leaf": leaf.hex(), "steps": []}
            sequences.append(self.row)

        def step(self, name, g, signer, rule=None, admin=None, replaces="kept"):
            g = dict(g)
            if replaces == "kept" and signer is not ROOT and self.kept is not None:
                g[18] = sha(self.kept)
            elif isinstance(replaces, bytes):
                g[18] = sha(replaces)
            _, genv, gbody = signed(g, signer)
            r = {"name": name, "message": enc(message(genv, admin)).hex(), "verdict": "refuse" if rule else "take"}
            if rule:
                r["rule"] = rule
            else:
                self.kept = gbody
            self.row["steps"].append(r)
            return gbody

    k1 = {**kettle, 4: 1}
    k_a2 = {**kettle, 4: 2, 12: [ADMIN2.key]}
    k_root1 = {**kettle, 4: 1, 12: by_hash([ADMIN.key, ADMIN2.key])}
    k_root2 = {**kettle, 4: 2, 12: [ADMIN2.key]}
    q = Seq("ordinary kettle", K)
    q.step("first grant from the admitting admin, admin counter 1", k1, ADMIN, admin=admin_record)
    q.step("grant from a current commander drops the other admin, admin counter 2", k_a2, ADMIN2)
    q.step("grant from an admin no longer among the commanders", {**kettle, 4: 3}, ADMIN,
           "grants/signer", admin=admin_record)
    q.step("same admin counter again from a commander", {**k_a2, 16: T0 + 9001}, ADMIN2, "grants/counter")
    q.step("root grant, root counter 1, below the admin counter 2", k_root1, ROOT)
    q.step("root grant, root counter 2", k_root2, ROOT)
    q.step("the old root grant replayed", k_root1, ROOT, "grants/counter")
    q.step("grant from a current commander made under root counter 2, admin counter 1",
           {**k_a2, 4: 1, 17: 2}, ADMIN2)
    # An admin grant names the root counter it was made under (field 17), so
    # one signed before a root grant never beats it, whatever its counter.
    both = by_hash([ADMIN.key, ADMIN2.key])
    q = Seq("ordinary kettle, an admin grant held back past the root's", K)
    q.step("first grant from the admitting admin, admin counter 1", {**kettle, 4: 1, 12: both}, ADMIN,
           admin=admin_record)
    before_root = q.step("grant from a commander, admin counter 2", {**kettle, 4: 2, 12: both}, ADMIN2)
    q.step("root grant without the removed admin, root counter 1", {**kettle, 4: 1, 12: [ADMIN2.key]}, ROOT)
    q.step("a commander's grant at admin counter 3 made before the root grant, delivered late",
           {**kettle, 4: 3, 12: both}, ADMIN2, "grants/counter", replaces=before_root)
    q.step("the same commander's grant made under root counter 1, admin counter 1",
           {**kettle, 4: 1, 12: [ADMIN2.key], 17: 1}, ADMIN2)
    q.step("a root grant that names a root counter", {**kettle, 4: 2, 12: [ADMIN2.key], 17: 1}, ROOT,
           "grants/counter")
    # An admin grant names the grant it replaces (field 18), so an older
    # admin grant held back is not taken after a newer one, whatever its
    # counter.
    three = by_hash([ADMIN.key, ADMIN2.key, ADMIN3.key])
    q = Seq("ordinary kettle, an older admin grant held back", K)
    first = q.step("first grant from the admitting admin, admin counter 1", {**kettle, 4: 1, 12: three}, ADMIN,
                   admin=admin_record)
    q.step("a commander drops an admin, admin counter 3", {**kettle, 4: 3, 12: by_hash([ADMIN2.key, ADMIN3.key])},
           ADMIN2)
    q.step("another commander's grant at admin counter 5 made on the first grant, delivered late",
           {**kettle, 4: 5, 12: three}, ADMIN3, "grants/replaces", replaces=first)
    q.step("a commander's grant that names no grant it replaces", {**kettle, 4: 6, 12: three}, ADMIN3,
           "grants/replaces", replaces=None)
    q.step("that commander's grant made on the current grant, admin counter 4",
           {**kettle, 4: 4, 12: by_hash([ADMIN2.key, ADMIN3.key])}, ADMIN3)
    q = Seq("guarded lock", L)
    q.step("root grant, root counter 3", lock, ROOT)
    q.step("a commander of the lock signs it a grant", {**lock, 4: 4}, PHONE, "grants/guarded")
    q.step("root grant without guarded", {k: v for k, v in {**lock, 4: 5}.items() if k != 15}, ROOT,
           "grants/guarded")
    q.step("root grant, root counter 6", {**lock, 4: 6}, ROOT)
    # Who may send a leaf copies (owner 2026-11-11): an ordinary leaf takes
    # them from its readers, a guarded leaf only from its commanders.
    kettle, lock = take[0]["grant"], take[1]["grant"]
    senders = []
    for name, gb, origin, rule in [
        ("ordinary kettle, copy from its reader", kettle, LAPTOP, None),
        ("ordinary kettle, copy from a neighbour that is not a reader", kettle, PHONE, "copy/leaf-sender"),
        ("guarded lock, copy from its commander", lock, PHONE, None),
        ("guarded lock, copy from a commander that is also a reader", lock, LAPTOP, None),
        ("guarded lock, copy from a reader that is not a commander", lock, TABLET, "copy/leaf-sender"),
        ("guarded lock, copy from a stranger", lock, BOARD, "copy/leaf-sender"),
    ]:
        row = {"name": name, "grant": gb, "origin": origin.id16.hex(), "verdict": "refuse" if rule else "take"}
        if rule:
            row["rule"] = rule
        senders.append(row)
    return take, refuse, senders, sequences


def credential_vectors():
    take, refuse = [], []
    tag = fake("period tag", 16)

    def cred(name, signer, m):
        env, body = envelope("credential", signer, m)
        take.append({"name": name, "verdict": "take", "diag": diag(m), "body": body.hex(),
                     "id": sha(body).hex(), "envelope": env.hex()})

    def pad(hs, n):
        return hs + [fake(f"pad {i}", 32) for i in range(n - len(hs))]

    exp = T0 + 35 * 86400000
    cred("period", ROOT, {1: 1, 2: GROUP, 3: ROOT.key, 4: 1, 7: exp, 10: tag, 11: PERIOD.key})
    cred("server", LAPTOP, {1: 2, 2: GROUP, 3: LAPTOP.key, 4: 1, 7: exp, 10: tag, 11: SRVKEY.key})
    cred("hubs", PERIOD, {1: 3, 2: tag, 3: PERIOD.key, 4: 1, 7: exp,
                          12: pad([SRVKEY.hash], 4), 13: pad([], 4)})
    cred("members", PERIOD, {1: 4, 2: tag, 3: PERIOD.key, 4: 1, 7: exp,
                             14: pad([SRVKEY.hash], 4)})
    m = {1: 4, 2: tag, 3: PERIOD.key, 4: 1, 7: exp, 14: pad([SRVKEY.hash], 3)}
    env, _ = envelope("credential", PERIOD, m)
    refuse.append({"name": "members list of 3 (not a padded length)", "rule": "credentials/members/members",
                   "verdict": "refuse", "envelope": env.hex()})
    m = {1: 3, 2: tag, 3: PERIOD.key, 4: 1, 7: exp, 10: tag, 12: pad([SRVKEY.hash], 4), 13: pad([], 4)}
    env, _ = envelope("credential", PERIOD, m)
    refuse.append({"name": "tag in a hubs credential", "rule": "credentials/hubs/tag",
                   "verdict": "refuse", "envelope": env.hex()})
    m = {1: 1, 2: GROUP, 3: ROOT.key, 4: 1, 7: exp, 10: tag, 11: PERIOD.key}
    body = enc(m)
    refuse.append({"name": "signer key does not verify", "rule": "sig/verify", "verdict": "refuse",
                   "envelope": enc([body, ADMIN.sign(LABELS["credential"], body)]).hex()})
    return take, refuse


GRID = [64, 256, 1024, 4096, 16384]


def grid_ok(n):
    return n in GRID or (n > 16384 and n % 16384 == 0)


def grid_targets():
    for g in GRID:
        yield g
    k = 2
    while True:
        yield 16384 * k
        k += 1


def frame(msg):
    """Pads a message so that its encoding is on the grid; returns the frame.
    One form: no `pad` when the message is on the grid already, else the
    smallest grid size that a `pad` of zeros can reach."""
    assert 1 not in msg
    base = enc(msg)
    if grid_ok(len(base)):
        return len(base).to_bytes(4, "big") + base
    for target in grid_targets():
        if target < len(base) + 2:
            continue
        for plen in range(0, target):
            m = dict(msg)
            m[1] = bytes(plen)
            b = enc(m)
            if len(b) == target:
                return len(b).to_bytes(4, "big") + b
            if len(b) > target:
                break


STEPS = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20]


def pad_content(content):
    """Pads a content (section 10.3) as frame() pads a message: no `pad` when
    it is a step by itself, else the smallest step a `pad` of zeros reaches."""
    assert 1 not in content
    base = enc(content)
    if len(base) in STEPS:
        return base
    for target in STEPS:
        if target < len(base) + 2:
            continue
        for plen in range(0, target):
            c = dict(content)
            c[1] = bytes(plen)
            b = enc(c)
            if len(b) == target:
                return b
            if len(b) > target:
                break
    raise ValueError("content over 4 MiB")


def copy_vector():
    K = sha(b"test copy key")
    readers = sorted([[LAPTOP.id16, 2], [PHONE.id16, 1], [BOARD.id16, 1]], key=lambda a: a[0])
    commit = hkdf(K, b"", b"cbb copy commit v2")
    hdr = {1: sha(b"copy id")[:16], 2: LAPTOP.id16, 3: [T0 + 1234, 0], 4: readers, 6: commit}
    hb = enc(hdr)
    h = sha(b"cbb copy v2\x00" + hb)
    wraps = [fake("wrap " + r[0].hex(), 1168) for r in readers]
    payload = fake("payload", 1024 + 16)
    W = sha(b"".join(sha(w) for w in wraps))
    P = sha(payload)
    sig = LAPTOP.sign("cbb copy sig v2", h + W + P)
    full = {1: hb, 2: 15, 3: wraps, 4: payload, 6: sig}
    # the board's reduced copy: its own wrap whole, the others as hashes, the payload as its hash
    bi = [r[0] for r in readers].index(BOARD.id16)
    red_wraps = [w if i == bi else sha(w) for i, w in enumerate(wraps)]
    reduced = {1: hb, 2: 15, 3: red_wraps, 5: P, 6: sig}
    content = dec(pad_content({0: 1, 5: "hello"}))
    assert len(enc(content)) == 1024
    assert verify(LAPTOP.key, "cbb copy sig v2", h + W + P, sig)
    return {
        "name": "a text copy for three readers",
        "hdr_diag": diag(hdr), "hdr": hb.hex(), "h": h.hex(), "K": K.hex(), "commit": commit.hex(),
        "payload_key": hkdf(K, h, b"cbb copy payload v2").hex(),
        "blob_key": hkdf(K, h, b"cbb copy blob v2").hex(),
        "W": W.hex(), "P": P.hex(), "sig": sig.hex(),
        "copy": enc(full).hex(), "reduced_copy_for_board": enc(reduced).hex(),
        "refuse_copies": [
            {"name": name, "rule": rule, "copy": enc(c).hex()}
            for name, rule, c in [
                ("three readers, no wraps", "copy/shape", {**full, 3: []}),
                ("three readers, five wraps", "copy/shape", {**full, 3: wraps + wraps[:2]}),
                ("reuse in the header", "copy/reuse", {**full, 1: enc({**hdr, 7: [sha(b"copy")[:16], 1]})}),
                ("unknown critical field in the header", "form/critical", {**full, 1: enc({**hdr, 200: 1})}),
                ("a header of readers only", "copy/shape", {**full, 1: enc({4: readers})}),
                ("origin of 15 bytes", "copy/shape", {**full, 1: enc({**hdr, 2: LAPTOP.id16[:15]})}),
                ("time [0, 0]", "copy/shape", {**full, 1: enc({**hdr, 3: [0, 0]})}),
                ("readers that are numbers", "copy/readers", {**full, 1: enc({**hdr, 4: [1, 2, 3]})}),
                ("an outer field the format does not name", "form/critical", {**full, 7: 1}),
                ("outer field 200", "form/critical", {**full, 200: b"x"}),
            ]
        ],
        "refuse_readers": [
            {"name": name, "rule": "copy/readers", "copy": enc({**full, 1: enc({**hdr, 4: rs})}).hex()}
            for name, rs in [("readers out of order", list(reversed(readers))),
                             ("a reader twice", [readers[0], [readers[0][0], 3], readers[2]])]
        ],
        "refuse_commit": [
            {"name": "a copy key that does not match its commit", "rule": "copy/commit",
             "K": hkdf(K, b"", b"another key").hex()},
        ],
        "refuse_contents": [
            {"name": name, "rule": "copy/content-pad", "content": b.hex()}
            for name, b in [
                ("a pad one byte longer than its step", enc({**content, 1: content[1] + b"\x00"})),
                ("a content short of its step without a pad", enc({0: 1, 5: "a" * 1015})),
                ("a pad of text", enc({**{k: v for k, v in content.items() if k != 1}, 1: "0" * len(content[1])})),
                ("a pad of ones", enc({**content, 1: b"\x01" * len(content[1])})),
            ]
        ],
        "content_plaintext": enc(content).hex(), "content_diag": diag({k: v for k, v in content.items() if k != 1}) + " with pad to 1024",
        "frame": frame({0: 2, 2: full}).hex(),
        "content_edges": [
            {"name": name, "text_bytes": n, "content": pad_content({0: 1, 5: "a" * n}).hex(),
             "size": len(pad_content({0: 1, 5: "a" * n})), "note": note}
            for name, n, note in [
                ("two bytes short of 1 KiB: empty pad", 1015, "1022 bytes without pad"),
                ("one byte short of 1 KiB: next step", 1016, "1023 bytes without pad; no pad is one byte long, so 4 KiB"),
                ("exactly 1 KiB: no pad", 1017, "a content that is a step by itself carries no pad, as a frame (10.3)"),
            ]
        ],
        "note": "wraps and payload are placeholder bytes of the right size; the signature and keys are real",
    }


def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def message_vectors(records_take):
    v = []

    def add(name, msg, note=None):
        f = frame(msg)
        e = {"name": name, "frame": f.hex(), "length": len(f) - 4}
        if note:
            e["note"] = note
        v.append(e)

    add("ping", {0: 3})
    add("bye", {0: 4})
    add("hello from the laptop", {0: 1, 2: 0b111, 3: 1, 4: "Laptop", 5: T0, 7: sha(b"set"), 8: 14,
                                  13: {1: 1, 3: "0.6.0"}, 20: 1, 21: 2})
    ids = sorted(bytes.fromhex(r["id"]) for r in records_take if r["verdict"] == "take")
    add("records", {0: 5, 2: [dec(bytes.fromhex(r["envelope"])) for r in records_take[:3]]})
    add("intro from the board", {0: 8, 2: [dec(bytes.fromhex(r["envelope"])) for r in records_take[:3]]},
        note="the root's records first, then the admitter's record, then the board's")
    add("welcome", {0: 67, 2: fake("Tb", 32), 3: {
        1: ROOT.key,
        2: [dec(bytes.fromhex(r["envelope"])) for r in records_take[:3]],
        3: srt([[bytes.fromhex(records_take[9]["id"]), 3600000], [bytes.fromhex(records_take[10]["id"]), 60000]]),
        5: T0 + 60000}})
    add("pairing error taken", {0: 69, 2: 8})
    add("have", {0: 6, 2: ids[:3]})
    add("reach", {0: 18, 2: srt([LAPTOP.id16, PHONE.id16, BOARD.id16])})
    # The edges of a grid step: a message two bytes short of 64 takes an
    # empty `pad` (its key and an empty byte string are two bytes); one byte
    # short cannot be padded to 64 (no `pad` is one byte long), so it goes to
    # 256; a message of 64 bytes by itself has no `pad`.
    add("two bytes short of 64: empty pad", {0: 3, 2: bytes(56)},
        note="62 bytes without pad; the key 1 and an empty byte string make 64")
    add("one byte short of 64: next step", {0: 3, 2: bytes(57)},
        note="63 bytes without pad; no pad is one byte long, so the frame is 256")
    add("exactly 64: no pad", {0: 3, 2: bytes(58)})
    digest = sha(b"cbb set v3\x00" + b"".join(ids))
    bad = []
    f = frame({0: 3})
    bad.append({"name": "ping not padded (frame of 2 bytes)", "rule": "frame/grid",
                "frame": (2).to_bytes(4, "big").hex() + enc({0: 3}).hex()})
    padded = bytearray(frame({0: 3}))
    padded[-1] = 1
    bad.append({"name": "padding not zero", "rule": "frame/pad", "frame": bytes(padded).hex()})
    bad.append({"name": "length 0", "rule": "frame/grid", "frame": "00000000"})
    m = enc({0: 3, 1: bytes(60)})
    bad.append({"name": "frame of 65 bytes", "rule": "frame/grid",
                "frame": len(m + b"").to_bytes(4, "big").hex() + m.hex()})
    # sets in messages (section 1): a message whose set is out of order or
    # holds a value twice is refused, with the field's rule
    a, b = ids[0], ids[1]
    w = [bytes.fromhex(records_take[9]["id"]), 3600000]
    w2 = [bytes.fromhex(records_take[10]["id"]), 60000]
    wa, wb = srt([w, w2])
    fields = [
        ("have out of order", "messages/have", [2], {0: 6, 2: [b, a]}),
        ("have with one ID twice", "messages/have", [2], {0: 6, 2: [a, a]}),
        ("reach out of order", "messages/reach", [2], {0: 18, 2: list(reversed(srt([LAPTOP.id16, PHONE.id16])))}),
        ("welcome claim_ages out of order", "pairing/welcome/claim_ages", [3, 3],
         {0: 67, 2: fake("Tb", 32), 3: {1: ROOT.key, 3: [wb, wa], 5: T0 + 60000}}),
    ]
    field_bad = [{"name": n, "rule": r, "path": p, "message": enc(m).hex()} for n, r, p, m in fields]
    return v, bad, digest.hex(), field_bad


def container_vector():
    """The key container (task 2's tested template): a pure function of the point.
    Serial = SHA-256(point)[0..16] with the first byte 0x40 | (b & 0x3f);
    signature the constant ECDSA r=1, s=1 (pending the owner, section 12)."""
    def tlv(tag, body):
        n = len(body)
        if n < 128:
            l = bytes([n])
        elif n < 256:
            l = bytes([0x81, n])
        else:
            l = bytes([0x82]) + n.to_bytes(2, "big")
        return bytes([tag]) + l + body

    alg = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    name = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, bytes.fromhex("550403")) + tlv(0x0C, b"cbb"))))
    validity = tlv(0x30, tlv(0x17, b"700101000000Z") + tlv(0x18, b"99991231235959Z"))
    sig = tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x01")))

    def serial(pub):
        h = bytearray(sha(pub)[:16])
        h[0] = 0x40 | (h[0] & 0x3F)
        return bytes(h)

    def spki(pub):
        return tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201")) +
                             tlv(0x06, bytes.fromhex("2a8648ce3d030107"))) + tlv(0x03, b"\x00" + pub))

    def tbs(pub, ser=None):
        return tlv(0x30, tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, ser or serial(pub)) + alg + name +
                   validity + name + spki(pub))

    def cont(pub):
        return tlv(0x30, tbs(pub) + alg + sig)

    # task 2's vectors must come out byte for byte
    task2 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "../../research-0.6/key-container/template-vectors.json")
    matched = 0
    if os.path.exists(task2):
        for v in json.load(open(task2))["Vectors"]:
            if v["Valid"]:
                assert cont(bytes.fromhex(v["Point"])).hex() == v["Container"], v["Seed"]
                matched += 1
    t = tbs(LAPTOP.pub)
    c = cont(LAPTOP.pub)
    from cryptography import x509
    xc = x509.load_der_x509_certificate(c)
    assert xc.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint) == LAPTOP.pub
    i = t.index(LAPTOP.pub)
    assert len(t) == 195 and len(c) == 221 and i == 130 and t[10:26] == serial(LAPTOP.pub)
    # TBS 192 bytes after its header; the key at offset 133 of the container (130 of the TBS)
    return {
        "source": "the template task 2 tested on five TLS stacks (research-0.6/key-container); gen.py checks its valid vectors byte for byte when that file is beside it",
        "tbs_template_hex": t[:10].hex() + "<16-byte serial>" + t[26:i].hex() + "<65-byte key>" + t[i + 65:].hex(),
        "key_offset_in_tbs": i,
        "tbs_length": len(t),
        "example_cert": c.hex(), "example_key_hash": LAPTOP.hash.hex(),
        "example_device_id": LAPTOP.id16.hex(), "example_serial": serial(LAPTOP.pub).hex(),
        "refuse": [
            {"name": "serial not derived from the key",
             "cert": tlv(0x30, tbs(LAPTOP.pub, serial(BOARD.pub)) + alg + sig).hex()},
            {"name": "key off the curve", "cert": cont(b"\x04" + bytes(64)).hex()},
            {"name": "any extension", "note": "the template has no extensions field; a certificate with one is refused"},
        ],
    }


def keys_table():
    rows = []
    for s in [ROOT, ROOT2, ADMIN, PHONE, LAPTOP, BOARD, LOCK, STRANGER, PERIOD, SRVKEY, OPERATOR]:
        rows.append({"name": s.name, "private_scalar": format(s.d, "064x"), "key": enc(s.key).hex(),
                     "key_hash": s.hash.hex(), "id16": s.id16.hex()})
    return {"group_id": GROUP.hex(), "keys": rows,
            "note": "test keys only; private scalar = SHA-256('cbb test key ' + name) mod (n-1) + 1"}


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    rt, rr = record_vectors()
    st, sr = statement_vectors()
    ct, cr = command_vectors()
    gt, gr, gs, gq = grant_vectors(bytes.fromhex(rt[0]["envelope"]))
    kt, kr = credential_vectors()
    mv, mb, digest, mf = message_vectors(rt)
    files = {
        "profile.json": {"vectors": profile_vectors()},
        "keys.json": keys_table(),
        "records.json": {"label": LABELS["record"], "take": rt, "refuse": rr},
        "statements.json": {"label": LABELS["keys"], "take": st, "refuse": sr},
        "commands.json": {"label": LABELS["command"], "take": ct, "refuse": cr},
        "grants.json": {"label": LABELS["grant"], "group": GROUP.hex(), "take": gt, "refuse": gr, "copy_senders": gs, "sequences": gq},
        "credentials.json": {"label": LABELS["credential"], "take": kt, "refuse": kr},
        "frames.json": {"grid": "64, 256, 1024, 4096, 16384, then multiples of 16384",
                        "take": mv, "refuse": mb, "refuse_fields": mf,
                        "set_digest_of_records_take": digest},
        "copy.json": copy_vector(),
        "container.json": container_vector(),
    }
    # Each signature has one form: the high-S twin of a valid signature
    # (the same r, n - s) is refused for every kind.
    def twin(sig):
        s_ = int.from_bytes(sig[32:], "big")
        return sig[:32] + (N - s_).to_bytes(32, "big")

    for fname in ["statements.json", "commands.json", "credentials.json"]:
        t = files[fname]["take"][0]
        env = dec(bytes.fromhex(t["envelope"]))
        files[fname]["refuse"].append({
            "name": "high-S twin of " + t["name"], "rule": "sig/low-s", "verdict": "refuse",
            "envelope": enc([env[0], twin(env[1])]).hex()})
    g = dec(bytes.fromhex(files["grants.json"]["take"][1]["message"]))
    g[2] = [g[2][0], twin(g[2][1])]
    files["grants.json"]["refuse"].append({"name": "high-S twin of the root's grant", "rule": "sig/low-s",
                                           "leaf": files["grants.json"]["take"][1]["leaf"],
                                           "verdict": "refuse", "message": enc(g).hex()})
    c = dec(bytes.fromhex(files["copy.json"]["copy"]))
    c[6] = twin(c[6])
    files["copy.json"]["copy_high_s_twin"] = enc(c).hex()

    # self-check: every signed vector marked take or hold verifies and reads
    for fname in ["records.json", "statements.json", "credentials.json", "commands.json"]:
        for t in files[fname]["take"]:
            env = dec(bytes.fromhex(t["envelope"]))
            dec(env[0])
    for name, data in files.items():
        with open(os.path.join(outdir, name), "w") as f:
            json.dump({"draft": "format-0.6-bytes.md, draft of 2026-11-11", **data}, f,
                      indent=1, ensure_ascii=False)
            f.write("\n")
    print("wrote", len(files), "files to", outdir)


if __name__ == "__main__":
    main()

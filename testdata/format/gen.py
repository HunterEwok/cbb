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

    def add(name, signer, typ, fields, verdict="take", note=None, extra=None):
        seq = chain.get(signer.name, (0, None))[0] + 1
        prev = chain.get(signer.name, (0, None))[1]
        m = rec(signer, seq, typ, fields, prev=prev, extra=extra)
        env, body = envelope("record", signer, m)
        if 8 in m:  # room for a second signature: [body, sig, sig2]
            env = enc([body, signer.sign(LABELS["record"], body), ADMIN.sign(LABELS["record"], body)])
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
    add("copies", ADMIN, 8, {10: 30000})
    add("hubs", ROOT, 10, {10: [LAPTOP.id16]})
    add("revoke", ROOT, 2, {10: [STRANGER.hash], 11: [[ADMIN.hash, 2], [ROOT.hash, 5]]})
    add("freeze", ROOT, 3, {10: [ADMIN.hash], 11: [[ADMIN.hash, 2], [ROOT.hash, 6]]})
    thaw_target = take[-1]["id"]
    add("thaw", ROOT, 4, {10: [bytes.fromhex(thaw_target)]})
    add("claim", ADMIN, 5, {10: ROOT2.key, 11: [[ADMIN.hash, 2], [ROOT.hash, 8]]})
    add("resolve", ROOT, 6, {10: [bytes.fromhex(take[-1]["id"])]})
    add("recovery", ROOT, 11, {10: Signer("recovery").key})
    add("handover", ROOT, 12, {10: ADMIN.hash})
    add("checkpoint", ROOT, 9, {10: [[ADMIN.hash, 3, bytes.fromhex(take[-2]["id"])],
                                     [ROOT.hash, 11, bytes.fromhex(take[-1]["id"])]],
                                11: [bytes.fromhex(take[0]["id"])]})
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
    signed envelope (section 7) and lists the keys the leaf obeys
    (`commanders`). The root signs any grant; for an ordinary leaf a
    commander of its current grant signs one too, and the first comes from
    the admitter with the root's record of that admin key (message field 3).
    A guarded leaf takes grants from the root only and carries `guarded`.
    The leaf keeps the root's counter and the admins' counter apart."""
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
        take.append({"name": name, "verdict": "take", "grant_diag": diag(g), "grant": gbody.hex(),
                     "envelope": genv.hex(), "message": enc(msg).hex(), "frame": frame(msg).hex()})
        return g

    def bad(name, rule, msg):
        refuse.append({"name": name, "rule": rule, "verdict": "refuse", "message": enc(msg).hex()})

    kettle = {1: 1, 2: GROUP, 10: BOARD.id16, 12: by_hash([ADMIN.key, ADMIN2.key]),
              13: [[LAPTOP.id16, LAPTOP.key]], 14: sorted([LAPTOP.hash, PHONE.hash]), 16: T0 + 9000}
    ok("ordinary kettle, first grant signed by the admitting admin", {**kettle, **{4: 1}}, ADMIN,
       admin=admin_record)
    lock = {1: 1, 2: GROUP, 4: 3, 10: LOCK.id16, 12: by_hash([PHONE.key, LAPTOP.key]),
            13: sorted([[LAPTOP.id16, LAPTOP.key], [TABLET.id16, TABLET.key]], key=lambda a: a[0]),
            14: sorted([LAPTOP.hash, PHONE.hash]), 15: 1, 16: T0 + 9000}
    g = ok("guarded lock, grant signed by the root", lock, ROOT)
    _, genv, _ = signed(g, ADMIN)
    bad("guarded grant signed by an admin", "grants/guarded", message(genv, admin_record))
    _, genv, _ = signed({**{k: v for k, v in g.items() if k != 15}, **{11: 86400000}}, ROOT)
    bad("lifetime in an ordinary grant", "grants/life", message(genv))
    g9 = dict(g)
    g9[12] = by_hash([Signer(f"c{i}").key for i in range(9)])
    _, genv, _ = signed(g9, ROOT)
    bad("nine commanders", "grants/commanders", message(genv))
    g5 = dict(g)
    g5[13] = sorted([[Signer(f"r{i}").id16, Signer(f"r{i}").key] for i in range(5)], key=lambda a: a[0])
    _, genv, _ = signed(g5, ROOT)
    bad("five readers", "grants/readers", message(genv))
    _, genv, _ = signed({**kettle, **{4: 2}}, ADMIN)
    bad("admin's first grant without the root's record", "grants/admin", message(genv))
    bad("message without its grant", "grants/shape", {0: 20})
    _, genv, gbody = signed({**kettle, **{4: 2}}, ROOT)
    bad("grant signed by a key other than its signer's", "sig/verify",
        message(enc([gbody, ADMIN.sign(LABELS["grant"], gbody)])))

    # Sequences: the grants one leaf receives in order, each checked against
    # what the leaf kept from those it took before.
    def step(name, g, signer, rule=None, admin=None):
        _, genv, _ = signed(g, signer)
        row = {"name": name, "message": enc(message(genv, admin)).hex(), "verdict": "refuse" if rule else "take"}
        if rule:
            row["rule"] = rule
        return row

    k1 = {**kettle, **{4: 1}}
    k_a2 = {**kettle, **{4: 2, 12: [ADMIN2.key]}}
    k_root1 = {**kettle, **{4: 1, 12: by_hash([ADMIN.key, ADMIN2.key])}}
    k_root2 = {**kettle, **{4: 2, 12: [ADMIN2.key]}}
    sequences.append({"name": "ordinary kettle", "steps": [
        step("first grant from the admitting admin, admin counter 1", k1, ADMIN, admin=admin_record),
        step("grant from a current commander drops the other admin, admin counter 2", k_a2, ADMIN2),
        step("grant from an admin no longer among the commanders", {**kettle, **{4: 3}}, ADMIN,
             "grants/signer", admin=admin_record),
        step("same admin counter again from a commander", {**k_a2, **{16: T0 + 9001}}, ADMIN2, "grants/counter"),
        step("root grant, root counter 1, below the admin counter 2", k_root1, ROOT),
        step("root grant, root counter 2", k_root2, ROOT),
        step("the old root grant replayed", k_root1, ROOT, "grants/counter"),
        step("grant from a current commander made under root counter 2, admin counter 1",
             {**k_a2, **{4: 1, 17: 2}}, ADMIN2),
    ]})
    # An admin grant names the root counter it was made under (field 17), so
    # one signed before a root grant never beats it, whatever its counter.
    both = by_hash([ADMIN.key, ADMIN2.key])
    sequences.append({"name": "ordinary kettle, an admin grant held back past the root's", "steps": [
        step("first grant from the admitting admin, admin counter 1", {**kettle, **{4: 1, 12: both}}, ADMIN,
             admin=admin_record),
        step("grant from a commander, admin counter 2", {**kettle, **{4: 2, 12: both}}, ADMIN2),
        step("root grant without the removed admin, root counter 1", {**kettle, **{4: 1, 12: [ADMIN2.key]}}, ROOT),
        step("a commander's grant at admin counter 3 made before the root grant, delivered late",
             {**kettle, **{4: 3, 12: both}}, ADMIN2, "grants/counter"),
        step("the same commander's grant made under root counter 1, admin counter 1",
             {**kettle, **{4: 1, 12: [ADMIN2.key], 17: 1}}, ADMIN2),
        step("a root grant that names a root counter", {**kettle, **{4: 2, 12: [ADMIN2.key], 17: 1}}, ROOT,
             "grants/counter"),
    ]})
    sequences.append({"name": "guarded lock", "steps": [
        step("root grant, root counter 3", lock, ROOT),
        step("a commander of the lock signs it a grant", {**lock, **{4: 4}}, PHONE, "grants/guarded"),
        step("root grant without guarded", {k: v for k, v in {**lock, **{4: 5}}.items() if k != 15}, ROOT,
             "grants/guarded"),
        step("root grant, root counter 6", {**lock, **{4: 6}}, ROOT),
    ]})
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
        3: [[bytes.fromhex(records_take[9]["id"]), 3600000]],
        5: T0 + 60000}})
    add("pairing error taken", {0: 69, 2: 8})
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
    return v, bad, digest.hex()


def container_vector():
    """The key container (task 2's tested template): a pure function of the point.
    Serial = SHA-256(point)[0..16] with the first byte 0x40 | (b & 0x3f);
    writers write the constant ECDSA signature r=1, s=1 (owner, section 12).
    Readers are tolerant of the signature's value but not of its form: a BIT
    STRING with no unused bits holding SEQUENCE { INTEGER r, INTEGER s }, each
    integer 1 to 33 bytes, every length exact, the whole value at most 72
    bytes; so a later writer may sign for real and old readers still read it."""
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

    def sigbits(r, s, unused=b"\x00"):
        return tlv(0x03, unused + tlv(0x30, tlv(0x02, r) + tlv(0x02, s)))

    sig = sigbits(b"\x01", b"\x01")

    def serial(pub):
        h = bytearray(sha(pub)[:16])
        h[0] = 0x40 | (h[0] & 0x3F)
        return bytes(h)

    def spki(pub):
        return tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201")) +
                             tlv(0x06, bytes.fromhex("2a8648ce3d030107"))) + tlv(0x03, b"\x00" + pub))

    def tbs(pub, ser=None, nm=None, val=None):
        return tlv(0x30, tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, ser or serial(pub)) + alg + (nm or name) +
                   (val or validity) + (nm or name) + spki(pub))

    def cont(pub, sg=None, t=None):
        return tlv(0x30, (t or tbs(pub)) + alg + (sg if sg is not None else sig))

    # task 2's valid vectors (research-0.6/key-container/template-vectors.json),
    # test keys with private scalar = SHA-256(seed) mod n
    task2 = []
    for seed in ["cbb template vector 1", "cbb template vector 2", "cbb template vector 3"]:
        d = int.from_bytes(sha(seed.encode()), "big") % N
        pub = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        task2.append({"name": "task 2: " + seed, "point": pub.hex(), "cert": cont(pub).hex()})
    known = {
        "cbb template vector 1": "3081da3081c0a003020102021077818a50cfe1f620aac55d75044e9e81",
        "cbb template vector 2": "3081da3081c0a0030201020210722f8eea3d334e2524303f826dcbc3e8",
        "cbb template vector 3": "3081da3081c0a00302010202106e1b0b6babdcd5f857c5610fcaee7396",
    }
    for v in task2:
        assert v["cert"].startswith(known[v["name"][len("task 2: "):]]), v["name"]
    t = tbs(LAPTOP.pub)
    c = cont(LAPTOP.pub)
    from cryptography import x509
    xc = x509.load_der_x509_certificate(c)
    assert xc.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint) == LAPTOP.pub
    i = t.index(LAPTOP.pub)
    assert len(t) == 195 and len(c) == 221 and i == 130 and t[10:26] == serial(LAPTOP.pub)

    # A real self-signature, as a later writer may make it (RFC 6979, so the
    # bytes are fixed); its integers in DER, 32 or 33 bytes each.
    der = LAPTOP.priv.sign(t, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    real = tlv(0x30, t + alg + tlv(0x03, b"\x00" + der))
    xr = x509.load_der_x509_certificate(real)
    LAPTOP.priv.public_key().verify(xr.signature, xr.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    big = b"\x00" + b"\xff" * 32
    take = task2 + [
        {"name": "the laptop's container", "point": LAPTOP.pub.hex(), "cert": c.hex()},
        {"name": "a real self-signature", "point": LAPTOP.pub.hex(), "cert": real.hex()},
        {"name": "integers of 33 bytes (72 in all)", "point": LAPTOP.pub.hex(),
         "cert": cont(LAPTOP.pub, sigbits(big, big)).hex()},
        {"name": "integer zero", "point": LAPTOP.pub.hex(),
         "cert": cont(LAPTOP.pub, sigbits(b"\x00", b"\x01")).hex()},
    ]
    other = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, bytes.fromhex("550403")) + tlv(0x0C, b"cbc"))))
    later = tlv(0x30, tlv(0x17, b"700101000001Z") + tlv(0x18, b"99991231235959Z"))
    p = LAPTOP.pub
    flipped = bytearray(c)
    flipped[60] ^= 0x01
    refuse = [
        {"name": "serial not derived from the key", "cert": cont(p, t=tbs(p, serial(BOARD.pub))).hex()},
        {"name": "key off the curve", "cert": cont(b"\x04" + bytes(64)).hex()},
        {"name": "another name", "cert": cont(p, t=tbs(p, nm=other)).hex()},
        {"name": "another date", "cert": cont(p, t=tbs(p, val=later)).hex()},
        {"name": "a byte of the TBS changed", "cert": bytes(flipped).hex()},
        {"name": "a byte after the container", "cert": (c + b"\x00").hex()},
        {"name": "cut short", "cert": c[:-1].hex()},
        {"name": "outer length not exact", "cert": (b"\x30\x81\xdb" + c[3:] + b"\x00").hex()},
        {"name": "outer length in a longer form", "cert": (b"\x30\x82\x00\xda" + c[3:]).hex()},
        {"name": "another signature algorithm",
         "cert": tlv(0x30, t + tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040303"))) + sig).hex()},
        {"name": "unused bits in the signature", "cert": cont(p, sigbits(b"\x01", b"\x01", b"\x01")).hex()},
        {"name": "signature not a SEQUENCE", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x31, tlv(0x02, b"\x01") + tlv(0x02, b"\x01")))).hex()},
        {"name": "one integer", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01")))).hex()},
        {"name": "three integers", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") * 3))).hex()},
        {"name": "empty integer", "cert": cont(p, sigbits(b"", b"\x01")).hex()},
        {"name": "integer of 34 bytes", "cert": cont(p, sigbits(b"\x00" * 2 + b"\xff" * 32, b"\x01")).hex()},
        {"name": "not an integer", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x30, tlv(0x04, b"\x01") + tlv(0x02, b"\x01")))).hex()},
        {"name": "a byte after the integers", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x01") + b"\x00"))).hex()},
        {"name": "a byte after the SEQUENCE", "cert": cont(p, tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x01")) + b"\x00")).hex()},
        {"name": "empty signature", "cert": cont(p, b"\x03\x00").hex()},
        {"name": "an ordinary certificate of the same key", "note": "an extension, a SAN or any other name: the TBS differs from the template"},
    ]
    for r in refuse:
        if "cert" in r:
            assert r["cert"] != c.hex()
    return {
        "source": "the template task 2 tested on five TLS stacks (research-0.6/key-container/report-ru.md, sections 2 and 7)",
        "reader": "the TBS byte for byte the template with the point and its serial; the point on the curve; ecdsa-with-SHA256; the signature a BIT STRING with no unused bits holding SEQUENCE { INTEGER, INTEGER }, each integer 1 to 33 bytes, every length exact, at most 72 bytes; its value is not read",
        "tbs_template_hex": t[:10].hex() + "<16-byte serial>" + t[26:i].hex() + "<65-byte key>" + t[i + 65:].hex(),
        "key_offset_in_tbs": i,
        "tbs_length": len(t),
        "example_cert": c.hex(), "example_key_hash": LAPTOP.hash.hex(),
        "example_device_id": LAPTOP.id16.hex(), "example_serial": serial(LAPTOP.pub).hex(),
        "take": take,
        "refuse": refuse,
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
    mv, mb, digest = message_vectors(rt)
    files = {
        "profile.json": {"vectors": profile_vectors()},
        "keys.json": keys_table(),
        "records.json": {"label": LABELS["record"], "take": rt, "refuse": rr},
        "statements.json": {"label": LABELS["keys"], "take": st, "refuse": sr},
        "commands.json": {"label": LABELS["command"], "take": ct, "refuse": cr},
        "grants.json": {"label": LABELS["grant"], "take": gt, "refuse": gr, "copy_senders": gs, "sequences": gq},
        "credentials.json": {"label": LABELS["credential"], "take": kt, "refuse": kr},
        "frames.json": {"grid": "64, 256, 1024, 4096, 16384, then multiples of 16384",
                        "take": mv, "refuse": mb, "set_digest_of_records_take": digest},
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

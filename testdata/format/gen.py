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
import subprocess
import sys
import tempfile
import unicodedata

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


def dec(b, max_depth=8, max_count=65535):
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


_SLH_SIGNER = None


def slh_sign(seeds, items):
    """SLH-DSA-SHA2-128s (FIPS 205) through check/'s circl: the public key
    of the three seeds and the deterministic signature of each (msg, ctx).
    Python has no SLH-DSA of its own here; the Rust core checks these with
    another implementation (RustCrypto's slh-dsa)."""
    global _SLH_SIGNER
    if _SLH_SIGNER is None:
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check")
        _SLH_SIGNER = os.path.join(tempfile.mkdtemp(), "check")
        subprocess.run(["go", "build", "-o", _SLH_SIGNER, "."], cwd=here, check=True)
    req = {"seeds": seeds.hex(), "items": [{"msg": m.hex(), "ctx": c.hex()} for m, c in items]}
    got = json.loads(subprocess.run([_SLH_SIGNER, "slhdsa-sign"], input=json.dumps(req).encode(),
                                    capture_output=True, check=True).stdout)
    return bytes.fromhex(got["pk"]), [bytes.fromhex(x) for x in got["sigs"]]


SLH_DSA = 4  # the registry's SLH-DSA-SHA2-128s


class PqSigner:
    """The recovery key's second half, K2 (E-6): SLH-DSA-SHA2-128s from
    three seeds made from a fixed label."""

    def __init__(self, name):
        self.name = name
        self.seeds = hashlib.sha512(b"cbb test key " + name.encode()).digest()[:48]
        self.pub, _ = slh_sign(self.seeds, [])
        self.key = [SLH_DSA, self.pub]
        self.hash = sha(enc(self.key))
        self._sigs = {}

    def sign(self, data, ctx):
        k = (data, ctx)
        if k not in self._sigs:
            self._sigs[k] = slh_sign(self.seeds, [k])[1][0]
        return self._sigs[k]


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
RECOVERY = Signer("recovery")
RECOVERY2 = PqSigner("recovery 2")
# The Group ID commits to the first root key and both halves of the
# recovery key (rule 33, E-6).
GROUP = sha(b"cbb group v3\x00" + enc(ROOT.key) + enc(RECOVERY.key) + enc(RECOVERY2.key))[:16]
# The contexts of K2's signatures.
CTX_RECORD = b"cbb record v3"
CTX_FETCH = b"cbb recovery fetch v3"
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


def head_envelope(body, sig2=None):
    """A recovery head's envelope (E-6): K2 signs the body first; K1 signs
    the body and the SHA-256 of K2's signature (Q-1)."""
    if sig2 is None:
        sig2 = RECOVERY2.sign(body, CTX_RECORD)
    return enc([body, RECOVERY.sign(LABELS["record"], body + sha(sig2)), sig2])


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
    bad("array of 65536", "cbor/count", head(4, 65536) + b"\x00" * 65536)
    ok("array of 4097 (over the old count)", [0] * 4097)
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
    if typ == 13:  # a recovery head names K2 (E-6)
        m[8] = RECOVERY2.hash
    if prev is not None:
        m[5] = prev
    m.update(fields)
    if extra:
        m.update(extra)
    return m


def list_hash(b):
    """The hash a recovery head names its list by (rule 33)."""
    return sha(b"cbb recovery list v3\x00" + b)


def record_vectors():
    take, refuse, lists = [], [], []
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
        if typ == 13:  # a recovery head: both halves of the recovery key
            env = head_envelope(body, sig2)
        elif 8 in m:  # room for a second signature: [body, sig, sig2]
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
                                      17: 4, 18: 2, 20: ADMIN.key, 21: 0b110111111,
                                      22: (1 << 10) - 1, 23: 1})
    lap_env, lap_body, lap_m = add("laptop admitted by the root", ROOT, 1,
                                   {10: LAPTOP.key, 11: "Laptop", 12: 1, 13: 0b0111, 16: 0b111, 17: 1, 18: 2})
    add("board admitted by an admin, base rights", ADMIN, 1,
        {10: BOARD.key, 11: "Kettle", 12: 4, 13: 0b0011, 17: 10},
        note="an ordinary leaf: any admin with admit admits it, and it obeys the group's admins")
    add("settings", ROOT, 7, {14: 1,
                              15: [[1, "forward.cbb.tools:8764", OPERATOR.key]]})
    add("copies", ADMIN, 8, {10: 30000, 11: seen_of(ROOT)})
    # hubs keep the user's order (not sorted), each once
    add("hubs", ROOT, 10, {10: sorted([LAPTOP.id16, PHONE.id16], reverse=True), 11: seen_of(ADMIN)})
    add("revoke", ROOT, 2, {10: srt([STRANGER.hash, Signer("stranger 2").hash]), 11: seen_of(ADMIN, ROOT)})
    add("freeze", ROOT, 3, {10: [ADMIN.hash], 11: seen_of(ADMIN, ROOT)})
    thaw_target = take[-1]["id"]
    add("thaw", ROOT, 4, {10: [bytes.fromhex(thaw_target)], 11: seen_of(ADMIN)})
    add("resolve", ROOT, 6, {10: [bytes.fromhex(take[-1]["id"])]})
    add("checkpoint", ROOT, 9, {10: srt([[ADMIN.hash, *chain[ADMIN.name]], [ROOT.hash, *chain[ROOT.name]]]),
                                11: srt([bytes.fromhex(take[0]["id"]), bytes.fromhex(take[1]["id"])])})
    # the change of root by the recovery key (rule 33): a small head that
    # names its list by hash; the list rides beside it
    listed = sorted(bytes.fromhex(t["id"]) for t in take if t["signer"] == ROOT.name)
    list_bytes = enc(listed)
    # the new root's first checkpoint, signed before the head that names
    # it (field 13): it keeps the whole list
    _, first_body, _ = add("first checkpoint of root 2", ROOT2, 9,
                           {10: [[ROOT.hash, *chain[ROOT.name]]], 11: listed},
                           note="the head below names it; the head applies once its list and this are held")
    add("recovery head: the recovery key makes root 2 the root", RECOVERY, 13,
        {10: ROOT2.key, 11: list_hash(list_bytes), 13: sha(first_body)},
        note="the list (lists[0]) rides beside it, taken from anyone by its hash")
    lists.append({"name": "the list of the first head", "bytes": list_bytes.hex(),
                  "hash": list_hash(list_bytes).hex(), "ids": len(listed)})
    # a second head names an admin key as the root: field 12 `from` says
    # where its records as the root start; below it they count only if
    # listed (a fresh key leaves 12 out)
    admin_from = chain[ADMIN.name][0] + 1
    empty = enc([])
    _, admin_first, _ = add("first checkpoint of the admin key as the root", ADMIN, 9,
                            {10: [[ROOT.hash, *chain[ROOT.name]]]})
    add("recovery head: an admin key becomes the root, its root records from seq %d" % admin_from, RECOVERY, 13,
        {10: ADMIN.key, 11: list_hash(empty), 12: admin_from, 13: sha(admin_first)},
        note="the admin's records below field 12 count only if listed; this list (lists[1]) is empty")
    lists.append({"name": "the empty list of the second head", "bytes": empty.hex(),
                  "hash": list_hash(empty).hex(), "ids": 0})
    # bytes that are no list (a map), taken by their hash as any list is:
    # they read as the empty list (rule 33)
    not_a_list = enc({1: 1})
    lists.append({"name": "bytes that are no list: the empty list", "bytes": not_a_list.hex(),
                  "hash": list_hash(not_a_list).hex(), "ids": 0})
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
    add("second signer named (room only in 0.6)", ROOT, 7, {14: 1},
        verdict="hold", extra={8: ADMIN.hash},
        note="signer2 (key 8) with a three-element envelope; 0.6 checks the first signature, keeps the record and never applies it")
    add("second signature of 3000 bytes (a later algorithm)", ROOT, 7, {14: 1},
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
    m2 = rec(ROOT, 91, 7, {14: 1}, extra={8: ADMIN.hash})
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
        # a checkpoint names heads before itself: its own key's below its seq
        ("checkpoint naming its own key at its own seq", "records/checkpoint/own-head", 9,
         {10: srt([[ADMIN.hash, 3, i1], [ROOT.hash, 90, i2]])}),
        ("checkpoint naming its own key above its seq", "records/checkpoint/own-head", 9,
         {10: srt([[ADMIN.hash, 3, i1], [ROOT.hash, 91, i2]])}),
        ("hubs with one device twice", "records/hubs/hubs", 10, {10: [LAPTOP.id16, LAPTOP.id16], 11: [sa]}),
        ("device seen out of order", "records/device/seen", 1, {**{k: lap_m[k] for k in (10, 11, 12)}, 26: [sb, sa]}),
        ("thaw seen out of order", "records/thaw/seen", 4, {10: [i1], 11: [sb, sa]}),
        ("thaw without its seen", "records/thaw/seen", 4, {10: [i1]}),
        ("hubs seen with one key twice", "records/hubs/seen", 10, {10: [LAPTOP.id16], 11: [sa, [sa[0], 3, i2]]}),
        ("copies seen entry without its record ID", "records/copies/seen", 8, {10: 30000, 11: [sa[:2]]}),
        ("copies without its seen", "records/copies/seen", 8, {10: 30000}),
    ]:
        bad_body(name, rule, rec(ROOT, 90, typ, fields))
    # what rule 33 retired (format 0.6 freezes): the claim, the root's
    # recovery record and the handover; the takeover power; settings'
    # takeover delay
    for name, typ, fields in [("claim (type 5, retired)", 5, {10: ROOT2.key, 11: [sa]}),
                              ("root's recovery record (type 11, retired)", 11, {10: RECOVERY.key}),
                              ("handover (type 12, retired)", 12, {10: ADMIN.hash})]:
        bad_body(name, "records/retired", rec(ROOT, 90, typ, fields))
    m = dict(lap_m)
    m.update({20: ADMIN.key, 21: 64})
    bad_body("admin with power bit 64 (takeover, retired)", "records/device/powers", m)
    bad_body("settings field 10 (takeover delay, gone)", "form/critical",
             {1: 7, 2: GROUP, 3: ROOT.hash, 4: 90, 6: T0, 10: 86400000})

    def bad_signed(name, rule, signer, m):
        body = enc(m)
        if m.get(1) == 13 and signer is RECOVERY and 8 in m:
            bad(name, rule, head_envelope(body))
        else:
            bad(name, rule, enc([body, signer.sign(LABELS["record"], body)]))

    some = list_hash(enc([]))
    cp = sha(b"a first checkpoint")
    bad_signed("recovery head naming the recovery key as the root", "records/recovery/root", RECOVERY,
               rec(RECOVERY, 2, 13, {10: RECOVERY.key, 11: some, 13: cp}))
    bad_signed("recovery head at seq 65 (at most 64 for the group's life)", "records/recovery/seq", RECOVERY,
               rec(RECOVERY, 65, 13, {10: Signer("root 65").key, 11: some, 13: cp}))
    bad_signed("recovery head without its list", "records/recovery/list", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 13: cp}))
    bad_signed("recovery head with a list hash of 31 bytes", "records/recovery/list", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some[:31], 13: cp}))
    bad_signed("recovery head with from 0 written (a fresh key leaves it out)", "form/default", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 12: 0, 13: cp}))
    bad_signed("recovery head with from past the highest seq", "records/recovery/from", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 12: 2**31, 13: cp}))
    bad_signed("recovery head without the new root's first checkpoint", "records/recovery/first", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some}))
    bad_signed("recovery head with a first checkpoint ID of 31 bytes", "records/recovery/first", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 13: cp[:31]}))
    no2 = rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 13: cp})
    del no2[8]
    bad_signed("recovery head without signer2 (K2's hash)", "records/recovery/signer2", RECOVERY, no2)
    bad_signed("recovery head whose signer2 is its signer", "records/recovery/signer2", RECOVERY,
               {**rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 13: cp}), 8: RECOVERY.hash})
    bad_signed("recovery head naming K2 as the root", "records/recovery/root", RECOVERY,
               rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 13: cp}) | {10: RECOVERY2.key})
    hb = enc(rec(RECOVERY, 2, 13, {10: Signer("root 3").key, 11: some, 13: cp}))
    bad("recovery head whose second signature is over 32 KiB", "env/sig2",
        head_envelope(hb, fake("later signature", 32 * 1024 + 1)))
    bad("recovery head with K2's signature over another body", "sig/verify",
        head_envelope(hb, RECOVERY2.sign(enc(rec(RECOVERY, 3, 13, {10: Signer("root 3").key, 11: some,
                                                                   13: cp})), CTX_RECORD)))
    return take, refuse, lists


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
    keeps the root's counter and the admins' counter apart. Every grant
    names the recovery seq it was made under (field 19, absent before any
    change of root); a leaf takes only the newest it knows and never goes
    back. Each vector names the leaf that reads it (`leaf`); the group is
    the file's. A row with `recovery` is read by a leaf that knows that
    recovery seq as the newest, whose root is then the key with the hash
    `root` (else 0 and the file's root)."""
    take, refuse, sequences = [], [], []
    by_hash = lambda keys: sorted(keys, key=lambda k: sha(enc(k)))

    def message(genv, admin=None):
        msg = {0: 20, 2: dec(genv)}
        if admin is not None:
            msg[3] = dec(admin)
        return msg

    def signed(g, signer, big=False):
        g = dict(g)
        g[3] = signer.hash
        genv, gbody = envelope("grant", signer, g)
        assert big or len(gbody) <= 4096
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
        return refuse[-1]

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
    sixteen = {**lock, 12: by_hash([Signer(f"c{i}").key for i in range(16)]),
               13: sorted([[Signer(f"r{i}").id16, Signer(f"r{i}").key] for i in range(16)], key=lambda a: a[0])}
    ok("guarded lock, sixteen commanders and sixteen readers", sixteen, ROOT)
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
    root_bad("seventeen commanders", "grants/commanders",
             {**g, 12: by_hash([Signer(f"c{i}").key for i in range(17)])})
    root_bad("seventeen readers", "grants/readers",
             {**g, 13: sorted([[Signer(f"r{i}").id16, Signer(f"r{i}").key] for i in range(17)], key=lambda a: a[0])})
    _, genv, _ = signed({**g, 300: fake("later", 4096)}, ROOT, big=True)
    bad("grant body over 4096 bytes", "env/size", message(genv), L)
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
    root_bad("grant with recovery seq 0 written", "form/default", {**g, 19: 0})
    root_bad("grant made under a recovery seq the leaf does not know", "grants/recovery", {**g, 19: 1})
    root_bad("grant with a recovery seq as text", "grants/shape", {**g, 19: "1"})
    _, genv, _ = signed({**g, 19: 65}, ROOT2)
    row = bad("grant made under recovery seq 65 (at most 64 heads)", "grants/recovery", message(genv), L)
    row.update({"recovery": 65, "root": ROOT2.hash.hex()})
    _, genv, _ = signed(g, ROOT)
    row = bad("the old root's grant made before the change the leaf knows", "grants/recovery", message(genv), L)
    row.update({"recovery": 1, "root": ROOT2.hash.hex()})
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

        def step(self, name, g, signer, rule=None, admin=None, replaces="kept", recovery=0, root=ROOT):
            g = dict(g)
            if replaces == "kept" and signer is not root and self.kept is not None:
                g[18] = sha(self.kept)
            elif isinstance(replaces, bytes):
                g[18] = sha(replaces)
            _, genv, gbody = signed(g, signer)
            r = {"name": name, "message": enc(message(genv, admin)).hex(), "verdict": "refuse" if rule else "take"}
            if recovery:
                r.update({"recovery": recovery, "root": root.hash.hex()})
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
    # A change of root (records rule 33): the leaf learns the recovery
    # head of seq 1, which makes root 2 the root. Grants made under seq 0
    # no longer count; the counters and commanders start afresh.
    q = Seq("ordinary kettle across a change of root", K)
    q.step("first grant from the admitting admin, admin counter 1", {**kettle, 4: 1, 12: both}, ADMIN,
           admin=admin_record)
    q.step("root grant, root counter 3", {**kettle, 4: 3, 12: both}, ROOT)
    old = q.step("grant from a commander made under root counter 3, admin counter 1",
                 {**kettle, 4: 1, 12: both, 17: 3}, ADMIN2)
    q.step("after the change, a commander's grant made before it", {**kettle, 4: 2, 12: both, 17: 3}, ADMIN2,
           "grants/recovery", recovery=1, root=ROOT2)
    q.step("after the change, the old root's grant", {**kettle, 4: 4, 12: both}, ROOT, "grants/recovery",
           replaces=None, recovery=1, root=ROOT2)
    q.step("the new root's grant made under recovery seq 1, root counter 1", {**kettle, 4: 1, 12: [ADMIN2.key],
                                                                              19: 1}, ROOT2, recovery=1, root=ROOT2)
    q.step("a commander's grant made under recovery seq 1 and root counter 1, admin counter 1",
           {**kettle, 4: 1, 12: [ADMIN2.key], 17: 1, 19: 1}, ADMIN2, recovery=1, root=ROOT2)
    q.step("the leaf asked to read under recovery seq 0 again", {**kettle, 4: 2, 12: [ADMIN2.key], 17: 3}, ADMIN2,
           "grants/recovery", replaces=old)
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
    # The optional zone (section 3.3): skipped, the signature covers it.
    cred("period with an unknown optional field", ROOT,
         {1: 1, 2: GROUP, 3: ROOT.key, 4: 1, 7: exp, 10: tag, 11: PERIOD.key, 300: "later"})
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
        5: T0 + 60000,
        9: RECOVERY.key,
        11: RECOVERY2.key}})
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
    fields = [
        ("have out of order", "messages/have", [2], {0: 6, 2: [b, a]}),
        ("have with one ID twice", "messages/have", [2], {0: 6, 2: [a, a]}),
        ("reach out of order", "messages/reach", [2], {0: 18, 2: list(reversed(srt([LAPTOP.id16, PHONE.id16])))}),
    ]
    field_bad = [{"name": n, "rule": r, "path": p, "message": enc(m).hex()} for n, r, p, m in fields]
    return v, bad, digest.hex(), field_bad


def container_vector():
    """The key container (task 2's tested template): a pure function of the point.
    Serial = SHA-256(point)[0..16] with the first byte 0x40 | (b & 0x3f);
    writers write the constant ECDSA signature r=1, s=1 (owner, section 12).
    Readers are tolerant of the signature's value but not of its form: a BIT
    STRING with no unused bits holding SEQUENCE { INTEGER r, INTEGER s }, each
    integer 1 to 33 bytes in DER (no needless zero in front, not negative),
    every length exact, the whole value at most 72
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
        {"name": "integer with a needless zero in front", "cert": cont(p, sigbits(b"\x00\x01", b"\x01")).hex()},
        {"name": "negative integer", "cert": cont(p, sigbits(b"\x01", b"\x80")).hex()},
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
        "reader": "the TBS byte for byte the template with the point and its serial; the point on the curve; ecdsa-with-SHA256; the signature a BIT STRING with no unused bits holding SEQUENCE { INTEGER, INTEGER }, each integer 1 to 33 bytes in DER (no needless zero in front, not negative), every length exact, at most 72 bytes; its value is not read",
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
    for s in [ROOT, ROOT2, ADMIN, PHONE, LAPTOP, BOARD, LOCK, STRANGER, PERIOD, SRVKEY, OPERATOR, RECOVERY]:
        rows.append({"name": s.name, "private_scalar": format(s.d, "064x"), "key": enc(s.key).hex(),
                     "key_hash": s.hash.hex(), "id16": s.id16.hex()})
    return {"group_id": GROUP.hex(), "keys": rows,
            "recovery2": {"name": RECOVERY2.name, "seeds": RECOVERY2.seeds.hex(), "key": enc(RECOVERY2.key).hex(),
                          "key_hash": RECOVERY2.hash.hex(), "id16": RECOVERY2.hash[:16].hex()},
            "group_id_of": "the first 16 bytes of SHA-256('cbb group v3' 0x00 key(root) key(recovery) "
                           "key(recovery2)) (rule 33, E-6)",
            "note": "test keys only; private scalar = SHA-256('cbb test key ' + name) mod (n-1) + 1; "
                    "recovery2's seeds (sk_seed, sk_prf, pk_seed) = the first 48 bytes of "
                    "SHA-512('cbb test key ' + name)"}


# ---------------------------------------------------------------- wave 3 messages
#
# The tables of the messages wave 3 numbers (format sections 9 and 11):
# pairing, the invitation, the hub's offer, `tunnel`, `hubs`, `guest`, the
# request that waits for an admin, the forwarder's and the relay's. The Rust
# core's tables (core/src/msg/tables.rs) must equal these; the Go check
# reads the vectors against them. Rows: number, rule, type, needed. A
# reader skips a field its table does not list; a bad field inside a map
# breaks the field that holds the map.

TABLES = {
    "pair/adb": [
        (1, "pair/adb/group", "bytes 16", True),
        (2, "pair/adb/device", "bytes 16", True),
        (3, "pair/adb/name", "text 1..128", True),
    ],
    "pair/start": [
        (2, "pair/start/ya", "bytes 1..256", True),
        (3, "pair/start/ada", "bytes 1..16384", True),
        (4, "pair/start/commitment", "bytes 32", True),
    ],
    "pair/reply": [
        (2, "pair/reply/yb", "bytes 1..256", True),
        (3, "pair/reply/adb", "bytes 1..1024", True),
        (4, "pair/reply/nonce", "bytes 32", True),
    ],
    "pair/confirm": [
        (2, "pair/confirm/ta", "bytes 1..64", True),
        (3, "pair/confirm/nonce", "bytes 32", True),
    ],
    "pair/welcome": [
        (2, "pair/welcome/tb", "bytes 1..64", True),
        (3, "pair/welcome/welcome", "map welcome", True),
    ],
    "pair/done": [
    ],
    "pair/error": [
        (2, "pair/error/code", "uint 1..255", True),
    ],
    "welcome": [
        (1, "welcome/root", "key 1", True),
        (2, "welcome/records", "array 1..8192 of envelope", True),
        (4, "welcome/keys", "array 1..256 of envelope", False),
        (5, "welcome/time", "uint 1..9223372036854775807", True),
        (6, "welcome/grant", "map welcome/grant", False),
        (7, "welcome/credentials", "array 1..259 of envelope", False),
        (9, "welcome/recovery", "key 1", True),
        (10, "welcome/list", "bytes 1..34820", False),
        (11, "welcome/recovery2", "key 4", True),
    ],
    "welcome/grant": [
        (2, "welcome/grant", "envelope", True),
        (3, "welcome/grant", "bytes 1..8192", True),
        (4, "welcome/grant", "array 1..8 of bytes 32", False),
        (5, "welcome/grant", "uint 1..4294967295", False),
    ],
    "pair/info": [
        (1, "pair/info/name", "text 1..128", True),
        (2, "pair/info/os", "uint 1..4294967295", False),
        (3, "pair/info/caps", "uint 1..7", False),
        (4, "pair/info/role", "uint 1..4", True),
        (5, "pair/info/admin", "key 1", False),
        (6, "pair/info/admin-pop", "bytes 1..8192", False),
        (7, "pair/info/keys", "envelope", False),
        (8, "pair/info/device", "map pair/info/device", False),
        (9, "pair/info/invite", "id 16", False),
    ],
    "pair/info/device": [],
    "invite": [
        (1, "invite/shape", "bytes 16", True),
        (2, "invite/shape", "bytes 32", True),
        (3, "invite/path", "array 1..4 of map invite/path", True),
        (4, "invite/profile", "map invite/profile", True),
    ],
    "invite/path": [
        (1, "invite/path", "uint 1..3", True),
        (2, "invite/path", "once 1..8 of addr", False),
        (3, "invite/path", "key 3", False),
        (4, "invite/path", "bytes 32", False),
        (5, "invite/path", "bytes 32", False),
        (6, "invite/obfuscation", "map obfuscation", False),
    ],
    "invite/profile": [
        (1, "invite/profile", "uint 1..4", True),
        (2, "invite/profile", "uint 1..15", False),
        (3, "invite/profile", "flag", False),
        (4, "invite/profile", "flag", False),
    ],
    "obfuscation": [
        (1, "obfuscation/jc", "uint 1..128", True),
        (2, "obfuscation/jmin", "uint 0..1280", True),
        (3, "obfuscation/jmax", "uint 1..1280", True),
        (4, "obfuscation/s", "array 1..4 of uint 0..1280", True),
        (5, "obfuscation/h", "array 1..4 of array 1..2 of uint 0..4294967295", True),
        (6, "obfuscation/key", "bytes 32", False),
    ],
    "vless": [
        (1, "vless/user", "bytes 16", True),
        (2, "vless/port", "uint 1..65535", False),
        (3, "vless/host", "text 1..253", False),
        (4, "vless/path", "text 1..128", False),
    ],
    "offer": [
        (1, "offer/hub-key", "key 3", True),
        (2, "offer/endpoints", "once 1..8 of addr", False),
        (3, "offer/obfuscation", "map obfuscation", False),
        (4, "offer/vless", "map vless", False),
        (6, "offer/moved", "flag", False),
        (7, "offer/next-key", "key 3", False),
        (8, "offer/confirm", "bytes 32", False),
        (9, "offer/endpoint-keys", "array 1..8 of map offer/endpoint-key", False),
    ],
    "offer/endpoint-key": [
        (1, "offer/endpoint-key/endpoint", "addr", True),
        (2, "offer/endpoint-key/key", "key 3", True),
    ],
    "tunnel": [
        (2, "tunnel/key", "key 3", True),
        (3, "tunnel/confirm", "bytes 32", True),
    ],
    "hubs": [
        (2, "hubs/stopped", "flag", False),
        (3, "hubs/serving", "flag", False),
    ],
    "guest": [
        (2, "guest/op", "uint 1..7", True),
        (3, "guest/key", "key 3", True),
        (4, "guest/psk", "bytes 32", False),
        (5, "guest/expires", "uint 1..9223372036854775807", False),
        (6, "guest/offer", "map offer", False),
        (7, "guest/reason", "text 1..256", False),
        (8, "guest/conn", "uint 1..4294967295", False),
        (9, "guest/data", "bytes 1..16384", False),
        (10, "guest/device", "bytes 16", False),
        (11, "guest/invite", "id 16", False),
    ],
    "waiting/request": [
        (1, "waiting/request/invite", "id 16", True),
        (2, "waiting/request/key", "key 1", True),
        (3, "waiting/request/info", "map pair/info", True),
        (4, "waiting/request/network", "uint 1..3", True),
        (5, "waiting/request/held", "uint 1..86400000", False),
        (6, "waiting/request/attempts", "uint 1..255", True),
    ],
    "waiting": [
        (2, "waiting/requests", "once 1..48 of map waiting/request", True),
    ],
    "dismiss": [
        (2, "dismiss/invite", "id 16", True),
        (3, "dismiss/key", "bytes 32", False),
    ],
    "forward/challenge": [
        (2, "forward/challenge/e", "bytes 32", True),
    ],
    "forward/register": [
        (2, "forward/register/key", "key 3", True),
        (3, "forward/register/proof", "bytes 32", True),
        (4, "forward/register/obfuscation", "map obfuscation", False),
        (5, "forward/register/vless", "bytes 16", False),
        (6, "forward/register/credentials", "array 1..3 of envelope", True),
    ],
    "forward/registered": [
        (2, "forward/registered/id", "uint 1..9223372036854775807", True),
        (3, "forward/registered/mask", "bytes 32", True),
        (4, "forward/registered/vless", "map vless", False),
    ],
    "server/error": [
        (2, "server/error/reason", "text 1..256", True),
    ],
    "forward/seen": [
        (2, "forward/seen/addr", "addr", True),
    ],
    "relay/challenge": [
        (2, "relay/challenge/e", "bytes 32", True),
        (3, "relay/challenge/root", "flag", False),
    ],
    "relay/register": [
        (2, "relay/register/key", "key 3", True),
        (3, "relay/register/proof", "bytes 32", True),
        (4, "relay/register/credentials", "array 1..3 of envelope", True),
        (5, "relay/register/root", "key 1", False),
    ],
    "relay/registered": [
        (2, "relay/registered/key", "key 3", True),
        (3, "relay/registered/psk", "bytes 32", True),
        (4, "relay/registered/addr", "text 1..261", True),
    ],
    "relay/watch": [
    ],
    "relay/dial": [
        (2, "relay/dial/name", "bytes 32", True),
    ],
    "relay/answer": [
        (2, "relay/answer/ticket", "bytes 16", True),
    ],
    "relay/online": [
        (2, "relay/online/names", "set 1..64 of bytes 32", False),
    ],
    "relay/call": [
        (2, "relay/call/name", "bytes 32", True),
        (3, "relay/call/ticket", "bytes 16", True),
    ],
    "relay/ok": [
    ],
    "result": [
        (2, "result/id", "bytes 16", True),
        (3, "result/by", "bytes 16", True),
        (4, "result/status", "uint 1..3", True),
        (5, "result/reason", "text 1..256", False),
        (6, "result/tunnel", "map offer", False),
    ],
    "member-credentials": [
        (2, "member-credentials/list", "array 1..259 of envelope", True),
        (3, "member-credentials/obfuscation", "map obfuscation", False),
    ],
}

MESSAGE_TYPES = {
    10: "result", 11: "member-credentials", 15: "tunnel", 16: "hubs", 17: "guest", 26: "waiting", 27: "dismiss",
    64: "pair/start", 65: "pair/reply", 66: "pair/confirm", 67: "pair/welcome", 68: "pair/done",
    69: "pair/error", 80: "forward/challenge", 81: "forward/register", 82: "forward/registered",
    83: "server/error", 84: "forward/seen", 90: "relay/challenge", 91: "relay/register",
    92: "relay/registered", 93: "server/error", 94: "relay/watch", 95: "relay/dial", 96: "relay/answer",
    97: "relay/online", 98: "relay/call", 99: "relay/ok",
}


def addr_ok(t):
    """An addr in its one canonical text: RFC 5952 for IPv6, no zone, not
    IPv4-mapped, not unspecified, the port 1..65535 in its shortest digits."""
    import ipaddress
    try:
        if t.startswith("["):
            host, sep, port = t[1:].partition("]:")
            if not sep or "%" in host:
                return False
            a = ipaddress.IPv6Address(host)
            if a.ipv4_mapped or a.compressed != host:
                return False
        else:
            host, port = t.rsplit(":", 1)
            a = ipaddress.IPv4Address(host)
            if str(a) != host:
                return False
        return (port.isascii() and port.isdigit() and str(int(port)) == port
                and 1 <= int(port) <= 65535 and not a.is_unspecified)
    except ValueError:
        return False


def public_v4(a):
    """Not this network, private, shared, loopback, link-local, multicast or reserved."""
    x, y = a.packed[0], a.packed[1]
    return not (x == 0 or x == 10 or x == 127 or x >= 224 or (x == 172 and 16 <= y < 32)
                or (x == 192 and y == 168) or (x == 100 and 64 <= y < 128) or (x == 169 and y == 254))


def public_ip(a):
    """An address a card may name: a public IPv4 address, or an IPv6 address that is not
    loopback, unspecified, multicast, link-local, site-local or unique-local, nor a refused
    IPv4 address in a translated, NAT64 or 6to4 form."""
    import ipaddress
    if a.version == 4:
        return public_v4(a)
    p = a.packed
    v4 = lambda b: public_v4(ipaddress.IPv4Address(b))
    first = int.from_bytes(p[:2], "big")
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return False
    if first & 0xffc0 in (0xfe80, 0xfec0) or first & 0xfe00 == 0xfc00:
        return False
    if p[:12] == bytes(8) + b"\xff\xff\x00\x00" and not v4(p[12:]):
        return False
    if p[:12] == b"\x00\x64\xff\x9b" + bytes(8) and not v4(p[12:]):
        return False
    if first == 0x2002 and not v4(p[2:6]):
        return False
    return True


def endpoint_ok(t):
    """A card's endpoint: an addr, or a lower-case DNS name whose last label
    is neither all digits nor starts with 0x, with its port."""
    import ipaddress
    if addr_ok(t):
        return public_ip(ipaddress.ip_address(t.rpartition(":")[0].strip("[]")))
    host, sep, port = t.rpartition(":")
    if not sep or not (port.isascii() and port.isdigit() and str(int(port)) == port and 1 <= int(port) <= 65535):
        return False
    labels = host.split(".")
    last = labels[-1]
    return (0 < len(host) <= 253 and not last.isdigit() and not last.startswith("0x")
            and last not in ("localhost", "local")
            and all(0 < len(l) <= 63 and not l.startswith("-") and not l.endswith("-")
                    and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in l) for l in labels))


def key_ok(v, alg):
    if not (isinstance(v, list) and len(v) == 2 and v[0] == alg and isinstance(v[1], bytes)):
        return False
    if alg == ES256:
        if len(v[1]) != 65 or v[1][0] != 4:
            return False
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), v[1])
            return True
        except ValueError:
            return False
    return len(v[1]) == 32 if alg == X25519 else True


def ty_ok(ty, v):
    import unicodedata
    w = ty.split(" ", 2)
    if w[0] == "uint":
        lo, hi = map(int, w[1].split(".."))
        return isinstance(v, int) and lo <= v <= hi
    if w[0] == "flag":
        return v == 1
    if w[0] == "bytes":
        if not isinstance(v, bytes):
            return False
        if ".." in w[1]:
            return 1 <= len(v) <= int(w[1].split("..")[1])
        return len(v) == int(w[1])
    if w[0] == "id":
        return isinstance(v, bytes) and len(v) == int(w[1]) and any(v)
    if w[0] == "text":
        return (isinstance(v, str) and 1 <= len(v.encode()) <= int(w[1].split("..")[1])
                and not any(unicodedata.category(c) == "Cc" for c in v))
    if w[0] == "addr":
        return isinstance(v, str) and addr_ok(v)
    if w[0] == "key":
        return key_ok(v, int(w[1]))
    if w[0] == "envelope":
        if not (isinstance(v, list) and len(v) in (2, 3) and all(isinstance(x, bytes) for x in v)):
            return False
        try:
            return isinstance(dec(v[0]), dict)
        except Exception:
            return False
    if w[0] in ("array", "once", "set"):
        n = int(w[1].split("..")[1])
        inner = w[2][len("of "):]
        if not (isinstance(v, list) and 1 <= len(v) <= n):
            return False
        es = [enc(x) for x in v]
        if w[0] == "once" and len(set(es)) != len(es):
            return False
        if w[0] == "set" and any(a >= b for a, b in zip(es, es[1:])):
            return False
        return all(ty_ok(inner, x) for x in v)
    if w[0] == "map":
        return check_map(w[1], v) is None
    raise ValueError(ty)


def check_map(name, v):
    """The rule v breaks against table name, or None."""
    if not isinstance(v, dict):
        return name + "/shape"
    for n, rule, ty, needed in TABLES[name]:
        if n not in v:
            if needed:
                return rule
        elif not ty_ok(ty, v[n]):
            return rule
    # The one rule between fields of a map: AmneziaWG's junk sizes.
    if name == "obfuscation" and v[2] > v[3]:
        return "obfuscation/jmax"
    if name == "offer" and 9 in v:
        named = [k[1] for k in v[9]]
        if len(set(named)) != len(named) or any(n not in v.get(2, []) for n in named):
            return "offer/endpoint-keys"
    # A root's fork is two records.
    if name == "roots" and 3 in v and len(v[3]) != 2:
        return "roots/fork"
    # Fields 3 (claim ages) and 8 (counted claims) of earlier drafts.
    if name == "welcome" and (3 in v or 8 in v):
        return "welcome/retired"
    return None


def check_message(m):
    t = m.get(0) if isinstance(m, dict) else None
    if not isinstance(t, int):
        return "frame/message"
    return check_map(MESSAGE_TYPES[t], m) if t in MESSAGE_TYPES else None


def wave3_vectors(records_take):
    take, refuse, maps = [], [], []
    wg = lambda label: [X25519, fake(label, 32)]
    hub_key, dev_key, guest_key = wg("hub wg key"), wg("device wg key toward the hub"), wg("guest wg key")
    obf = {1: 4, 2: 40, 3: 70, 4: [15, 20, 0, 0], 5: [[1000, 1100], [2000, 2100], [3000, 3100], [4000, 4100]]}
    offer = {1: hub_key, 2: ["203.0.113.5:51820", "[2001:db8::5]:51820"], 3: obf,
             4: {1: fake("vless user", 16)}, 8: fake("tunnel confirm", 32)}
    info = {1: "kitchen tablet", 2: 3, 4: 1, 9: fake("invite id", 16)}
    request = {1: fake("invite id", 16), 2: TABLET.key, 3: info, 4: 2, 5: 120000, 6: 2}
    envs = [bytes.fromhex(r["envelope"]) for r in records_take[:2]]
    welcome = {1: ROOT.key, 2: [dec(e) for e in envs], 5: T0, 9: RECOVERY.key, 11: RECOVERY2.key}

    def msg(name, m, note=None):
        assert check_message(m) is None, (name, check_message(m))
        e = {"name": name, "t": m[0], "message": enc(m).hex()}
        if note:
            e["note"] = note
        take.append(e)

    def bad(name, m, rule):
        got = check_message(m)
        assert got == rule, (name, got, rule)
        refuse.append({"name": name, "rule": rule, "message": enc(m).hex()})

    def mp(name, table, v, rule=None):
        got = check_map(table, v)
        assert got == rule, (name, got, rule)
        e = {"name": name, "table": table, "value": enc(v).hex()}
        if rule:
            e["rule"] = rule
        maps.append(e)

    adb = {1: GROUP, 2: PHONE.id16, 3: "Ewok's phone"}
    msg("credentials", {0: 11, 2: [dec(envs[0])]}, "the credential is a placeholder envelope")
    msg("credentials with settings for later", {0: 11, 2: [dec(envs[0])], 3: obf},
        "field 3: room for the settings to change with the period; no 0.6 writer sets it, a reader checks its shape and does not apply it")
    bad("credentials with settings out of shape", {0: 11, 2: [dec(envs[0])], 3: {**obf, 2: 80}},
        "member-credentials/obfuscation")
    msg("pair start", {0: 64, 2: fake("cpace ya", 32), 3: enc(info), 4: fake("code commitment", 32)})
    msg("pair reply", {0: 65, 2: fake("cpace yb", 32), 3: enc(adb), 4: fake("member nonce", 32)})
    msg("pair confirm", {0: 66, 2: fake("cpace ta", 32), 3: fake("joiner nonce", 32)})
    msg("pair welcome", {0: 67, 2: fake("cpace tb", 32), 3: welcome}, "records: the first two of records.json")
    msg("pair done", {0: 68})
    msg("pair error: taken", {0: 69, 2: 8})
    msg("result with the hub's offer", {0: 10, 2: fake("command id", 16), 3: PHONE.id16, 4: 1, 6: offer})
    msg("tunnel", {0: 15, 2: dev_key, 3: fake("tunnel confirm", 32)})
    msg("hubs: serving", {0: 16, 3: 1})
    msg("hubs: stopped", {0: 16, 2: 1})
    msg("guest open", {0: 17, 2: 1, 3: guest_key, 4: fake("guest psk", 32), 5: T0 + 86400000,
                       11: fake("invite id", 16)})
    msg("guest opened", {0: 17, 2: 2, 3: guest_key, 6: offer})
    msg("guest data", {0: 17, 2: 4, 3: guest_key, 8: 1, 9: b"\x01\x02"})
    msg("guest admitted", {0: 17, 2: 6, 3: guest_key, 10: TABLET.id16})
    msg("waiting", {0: 26, 2: [request, {**request, 2: STRANGER.key, 6: 1}]})
    msg("dismiss an invitation", {0: 27, 2: fake("invite id", 16)})
    msg("dismiss one key", {0: 27, 2: fake("invite id", 16), 3: TABLET.hash})
    msg("forwarder challenge", {0: 80, 2: fake("fwd e", 32)})
    msg("forwarder register", {0: 81, 2: hub_key, 3: fake("fwd proof", 32), 4: obf, 5: fake("vless user", 16),
                               6: [dec(envs[0])]}, "the credential is a placeholder envelope")
    msg("forwarder registered", {0: 82, 2: 7, 3: fake("fwd mask", 32), 4: {1: fake("vless user", 16), 2: 443}})
    msg("forwarder error", {0: 83, 2: "unknown group"})
    msg("forwarder seen", {0: 84, 2: "198.51.100.7:40000"})
    msg("forwarder seen: IPv6", {0: 84, 2: "[2001:db8::7]:40000"})
    msg("forwarder seen: IPv6, one zero group written out", {0: 84, 2: "[2001:db8:0:1:1:1:1:1]:40000"})
    msg("relay challenge", {0: 90, 2: fake("relay e", 32), 3: 1})
    msg("relay register", {0: 91, 2: dev_key, 3: fake("relay proof", 32), 4: [dec(envs[0])], 5: ROOT.key})
    msg("relay registered", {0: 92, 2: hub_key, 3: fake("relay psk", 32), 4: "10.64.0.2"})
    msg("relay error", {0: 93, 2: "not on the list"})
    msg("relay watch", {0: 94})
    names = sorted([fake("name a", 32), fake("name b", 32), fake("name c", 32)])
    msg("relay dial", {0: 95, 2: names[0]})
    msg("relay answer", {0: 96, 2: fake("ticket", 16)})
    msg("relay online: names sorted", {0: 97, 2: names})
    msg("relay call", {0: 98, 2: names[1], 3: fake("ticket", 16)})
    msg("relay ok", {0: 99})
    msg("a type this version does not number", {0: 200, 2: "anything"}, "ignored, not refused")
    msg("an unknown field skipped", {0: 15, 2: dev_key, 3: fake("tunnel confirm", 32), 300: "later"})

    bad("tunnel without its confirmation", {0: 15, 2: dev_key}, "tunnel/confirm")
    bad("tunnel with an ES256 key", {0: 15, 2: LAPTOP.key, 3: fake("c", 32)}, "tunnel/key")
    bad("hubs: flag 2", {0: 16, 2: 2}, "hubs/stopped")
    bad("guest op 8", {0: 17, 2: 8, 3: guest_key}, "guest/op")
    bad("pair error code 0", {0: 69, 2: 0}, "pair/error/code")
    bad("pair start without the code's commitment", {0: 64, 2: fake("cpace ya", 32), 3: enc(info)},
        "pair/start/commitment")
    bad("pair confirm with a short nonce", {0: 66, 2: fake("cpace ta", 32), 3: fake("joiner nonce", 31)},
        "pair/confirm/nonce")
    bad("relay online: names out of order", {0: 97, 2: list(reversed(names))}, "relay/online/names")
    bad("relay online: a name twice", {0: 97, 2: [names[0], names[0]]}, "relay/online/names")
    bad("relay online: 65 names", {0: 97, 2: sorted(fake(f"n{i}", 32) for i in range(65))}, "relay/online/names")
    bad("waiting: a request twice", {0: 26, 2: [request, request]}, "waiting/requests")
    bad("waiting: held over a day", {0: 26, 2: [{**request, 5: 86400001}]}, "waiting/requests")
    bad("waiting: 49 requests", {0: 26, 2: [{**request, 6: (i % 255) + 1, 5: i + 1} for i in range(49)]},
        "waiting/requests")
    bad("result: an endpoint twice in the offer", {0: 10, 2: fake("command id", 16), 3: PHONE.id16, 4: 1,
                                                   6: {**offer, 2: ["203.0.113.5:51820"] * 2}}, "result/tunnel")
    bad("forwarder register: 4 credentials", {0: 81, 2: hub_key, 3: fake("p", 32), 6: [dec(envs[0])] * 4},
        "forward/register/credentials")
    bad("forwarder seen: a host name", {0: 84, 2: "example.org:1"}, "forward/seen/addr")
    bad("forwarder seen: an IPv6 zone", {0: 84, 2: "[fe80::1%2]:443"}, "forward/seen/addr")
    bad("forwarder seen: an IPv4-mapped address", {0: 84, 2: "[::ffff:192.0.2.1]:443"}, "forward/seen/addr")
    bad("forwarder seen: a port with a leading zero", {0: 84, 2: "192.0.2.1:080"}, "forward/seen/addr")
    for a in ["[2001:DB8::1]:443", "[2001:db8:0:0:0:0:0:1]:443", "[2001:0db8::0001]:443", "[2001:db8::0.0.0.1]:443",
              "[2001:db8:0::1]:443", "[2001:db8::1:1:1:1:1]:443", "192.0.2.1:0", "0.0.0.0:443", "[::]:443"]:
        bad(f"forwarder seen: {a}", {0: 84, 2: a}, "forward/seen/addr")
    bad("relay error: empty reason", {0: 93, 2: ""}, "server/error/reason")
    # "No invitation" has one spelling, the field left out: the zero ID is refused.
    zero_id = bytes(16)
    bad("dismiss: the zero invitation ID", {0: 27, 2: zero_id}, "dismiss/invite")
    bad("guest open: the zero invitation ID", {0: 17, 2: 1, 3: guest_key, 4: fake("guest psk", 32),
                                                5: T0 + 86400000, 11: zero_id}, "guest/invite")
    bad("waiting: a request with the zero invitation ID", {0: 26, 2: [{**request, 1: zero_id}]}, "waiting/requests")
    bad("waiting: a request whose info has the zero invitation ID",
        {0: 26, 2: [{**request, 3: {**info, 9: zero_id}}]}, "waiting/requests")

    mp("an info with the hello's device map", "pair/info", {1: "tv", 4: 1, 8: {1: 1}})
    mp("an info: device not a map", "pair/info", {1: "tv", 4: 1, 8: 5}, "pair/info/device")
    mp("an offer", "offer", offer)
    mp("an offer: endpoints in the hub's order", "offer", {**offer, 2: list(reversed(offer[2]))})
    mp("an offer: an endpoint twice", "offer", {**offer, 2: [offer[2][0]] * 2}, "offer/endpoints")
    face_key = [X25519, fake("hub face key", 32)]
    mp("an offer: an endpoint with its own hub key", "offer", {**offer, 9: [{1: offer[2][0], 2: face_key}]})
    mp("an offer: a key for an endpoint it does not list", "offer",
       {**offer, 9: [{1: "198.51.100.99:443", 2: face_key}]}, "offer/endpoint-keys")
    mp("an offer: two keys for one endpoint", "offer",
       {**offer, 9: [{1: offer[2][0], 2: face_key}] * 2}, "offer/endpoint-keys")
    mp("an offer: an endpoint key that is no addr", "offer",
       {**offer, 9: [{1: "fwd.example.org:443", 2: face_key}]}, "offer/endpoint-keys")
    mp("an offer: bad settings", "offer", {**offer, 3: {**obf, 1: 129}}, "offer/obfuscation")
    mp("the settings", "obfuscation", obf)
    mp("the settings: jmin above jmax", "obfuscation", {**obf, 2: 80}, "obfuscation/jmax")
    mp("the settings: jmin equal to jmax", "obfuscation", {**obf, 2: 70})
    mp("the settings: five sizes", "obfuscation", {**obf, 4: [1, 2, 3, 4, 5]}, "obfuscation/s")
    mp("ADb", "pair/adb", adb)
    mp("ADb without a name", "pair/adb", {1: GROUP, 2: PHONE.id16}, "pair/adb/name")
    mp("a request", "waiting/request", request)
    mp("a request with the zero invitation ID", "waiting/request", {**request, 1: bytes(16)}, "waiting/request/invite")
    mp("an info with the zero invitation ID", "pair/info", {**info, 9: bytes(16)}, "pair/info/invite")
    mp("a Welcome", "welcome", welcome)
    mp("a Welcome without its time", "welcome", {1: ROOT.key, 2: welcome[2]}, "welcome/time")
    mp("a Welcome without the recovery key", "welcome", {k: v for k, v in welcome.items() if k != 9},
       "welcome/recovery")
    mp("a Welcome without the recovery key's second half", "welcome",
       {k: v for k, v in welcome.items() if k != 11}, "welcome/recovery2")
    mp("a Welcome whose second half is an ES256 key", "welcome", {**welcome, 11: RECOVERY.key},
       "welcome/recovery2")
    lst = enc(sorted(bytes.fromhex(r["id"]) for r in records_take[:2]))
    mp("a Welcome with the newest list", "welcome", {**welcome, 10: lst})
    mp("a Welcome with an empty list", "welcome", {**welcome, 10: b""}, "welcome/list")
    claims = sorted([fake("claim a", 32), fake("claim b", 32)])
    mp("a Welcome with claim ages (field 3, retired)", "welcome", {**welcome, 3: [[claims[0], 1]]},
       "welcome/retired")
    mp("a Welcome with counted claims (field 8, retired)", "welcome", {**welcome, 8: claims}, "welcome/retired")
    return take, refuse, maps


def invitation_vectors():
    take, refuse = [], []
    home = {1: 1}
    guest = {1: 2, 2: ["203.0.113.5:51820"], 3: [X25519, fake("hub wg key", 32)],
             4: fake("guest wg private", 32), 5: fake("guest psk", 32)}
    obf = {1: 4, 2: 40, 3: 70, 4: [15, 20, 0, 0], 5: [[1000, 1100], [2000, 2100], [3000, 3100], [4000, 4100]]}
    prof = {1: 1, 2: 3}
    base = {1: fake("invite id", 16), 2: fake("invite secret", 32), 3: [home, guest], 4: prof}

    def cross_rule(v):
        """The rules between fields the invitation's reader adds to its tables."""
        if v[1] == bytes(16) or v[2] == bytes(32):
            return "invite/shape"
        for p in v[3]:
            g = (4 in p, 5 in p)
            if g[0] != g[1] or p.get(4) == bytes(32) or p.get(5) == bytes(32) or \
                    (3 in p and p[3][1] == bytes(32)):
                return "invite/path"
            if p[1] == 1 and any(k in p for k in (2, 3, 4, 5)):
                return "invite/path"
            if p[1] == 2 and not all(k in p for k in (2, 3, 4)):
                return "invite/path"
            if p[1] == 3 and 2 not in p:
                return "invite/path"
            if p[1] == 1 and 6 in p:
                return "invite/obfuscation"
        pr = v[4]
        if pr.get(4) == 1 and pr[1] != 4:
            return "invite/profile"
        if pr.get(3) == 1 and any(p[1] != 1 for p in v[3]):
            return "invite/profile"
        return None

    def rule_of(v):
        return check_map("invite", v) or cross_rule(v)

    def ok(name, v):
        assert rule_of(v) is None, name
        take.append({"name": name, "invitation": enc(v).hex(),
                     "text": "cbb://join#" + __import__("base64").urlsafe_b64encode(enc(v)).decode().rstrip("=")})

    def no(name, v, rule, cross=False):
        assert check_map("invite", v) is None if cross else True, name
        got = rule_of(v)
        assert got == rule, (name, got)
        e = {"name": name, "rule": rule, "invitation": enc(v).hex()}
        if cross:
            e["cross"] = "a rule between fields"
        refuse.append(e)

    ok("home and away, plain WireGuard", base)
    ok("home and away, a group with AmneziaWG", {**base, 3: [home, {**guest, 6: obf}]})
    ok("a small device: a leaf, home only", {**base, 3: [home], 4: {1: 4, 3: 1}})
    no("settings on the home path", {**base, 3: [{1: 1, 6: obf}, guest]}, "invite/obfuscation", cross=True)
    no("settings out of shape", {**base, 3: [home, {**guest, 6: {**obf, 3: 2000}}]}, "invite/path")
    no("jmin above jmax", {**base, 3: [home, {**guest, 6: {**obf, 2: 80}}]}, "invite/path")
    no("a home path with an endpoint", {**base, 3: [{1: 1, 2: ["203.0.113.5:51820"]}, guest]}, "invite/path",
       cross=True)
    no("a guest key without its pre-shared key", {**base, 3: [home, {k: v for k, v in guest.items() if k != 5}]},
       "invite/path", cross=True)
    no("a guest key of zeros", {**base, 3: [home, {**guest, 4: bytes(32)}]}, "invite/path", cross=True)
    no("a hub key of zeros", {**base, 3: [home, {**guest, 3: [X25519, bytes(32)]}]}, "invite/path", cross=True)
    no("a bypass path without endpoints", {**base, 3: [home, {1: 3}]}, "invite/path", cross=True)
    no("an ID of zeros", {**base, 1: bytes(16)}, "invite/shape", cross=True)
    no("a secret of zeros", {**base, 2: bytes(32)}, "invite/shape", cross=True)
    no("an endpoint twice", {**base, 3: [home, {**guest, 2: ["203.0.113.5:51820"] * 2}]}, "invite/path")
    no("an endpoint with an IPv6 zone", {**base, 3: [home, {**guest, 2: ["[fe80::1%2]:443"]}]}, "invite/path")
    no("an IPv4-mapped endpoint", {**base, 3: [home, {**guest, 2: ["[::ffff:192.0.2.1]:443"]}]}, "invite/path")
    no("one endpoint twice in two spellings of its port",
       {**base, 3: [home, {**guest, 2: ["192.0.2.1:80", "192.0.2.1:080"]}]}, "invite/path")
    no("five paths", {**base, 3: [home] * 5}, "invite/path")
    no("a guest path without the hub's key", {**base, 3: [home, {k: v for k, v in guest.items() if k != 3}]},
       "invite/path", cross=True)
    no("home only with a guest path", {**base, 4: {1: 1, 3: 1}}, "invite/profile", cross=True)
    no("guarded, not a leaf", {**base, 4: {1: 1, 4: 1}}, "invite/profile", cross=True)
    no("rights 16", {**base, 4: {1: 1, 2: 16}}, "invite/profile")
    no("a short secret", {**base, 2: fake("s", 16)}, "invite/shape")
    return take, refuse


def code_vectors():
    """The short code (W.3) and CPace's channel identifier (11.1), both
    with the invitation ID each end believes it is using; 16 zero bytes at
    home without an invitation. Each pair of cases differs in one input."""
    def h(label):
        return hashlib.sha256(label.encode()).digest()

    def code(exporter, nj, nm, inv):
        d = hashlib.sha256(b"cbb short code v3\x00" + exporter + nj + nm + inv).digest()
        return "%06d" % (int.from_bytes(d[:4], "big") % 1000000)

    def ci(member, joiner, inv):
        return b"cbb pair channel v3\x00" + member + joiner + inv

    exporter, nj, nm = h("vector exporter"), h("vector joiner nonce"), h("vector member nonce")
    inv = h("vector invitation")[:16]
    other = bytes([inv[0] ^ 1]) + inv[1:]
    home = bytes(16)
    short = []
    for name, e, a, b, i in [
        ("an invitation", exporter, nj, nm, inv),
        ("another invitation ID, one bit apart", exporter, nj, nm, other),
        ("at home without an invitation", exporter, nj, nm, home),
        ("the nonces swapped", exporter, nm, nj, inv),
        ("another session", h("vector exporter 2"), nj, nm, inv),
    ]:
        short.append({"name": name, "exporter": e.hex(), "nj": a.hex(), "nm": b.hex(), "invitation": i.hex(),
                      "code": code(e, a, b, i)})
    member, joiner = h("vector member key"), h("vector joiner key")
    channel = []
    for name, m, j, i in [
        ("an invitation", member, joiner, inv),
        ("another invitation ID, one bit apart", member, joiner, other),
        ("at home without an invitation", member, joiner, home),
        ("the keys swapped", joiner, member, inv),
    ]:
        channel.append({"name": name, "member": m.hex(), "joiner": j.hex(), "invitation": i.hex(),
                        "ci": ci(m, j, i).hex()})
    return {"short_code_label": "cbb short code v3", "channel_prefix": "cbb pair channel v3",
            "no_invitation": home.hex(), "short_code": short, "channel_id": channel}


def card_vectors():
    take, refuse = [], []
    tls = sorted([Signer("server tls").pub, Signer("server tls 2").pub])

    def card(kw=None):
        m = {1: 1, 3: OPERATOR.key, 4: 1, 7: T0 + 365 * 86400000, 10: "a forwarder in Europe",
             11: ["fwd.example.org:443", "192.0.2.7:443"], 12: [[ES256, tls[0]]], 13: 1, 14: 5}
        m.update(kw or {})
        return m

    def ok(name, m):
        env, body = envelope("card", OPERATOR, m)
        take.append({"name": name, "envelope": env.hex(), "id": sha(body).hex()})

    def no(name, m, rule, by=OPERATOR):
        env, _ = envelope("card", by, m)
        refuse.append({"name": name, "rule": rule, "envelope": env.hex()})

    ok("one key", card())
    ok("two keys in the order of their encodings", card({12: [[ES256, k] for k in tls]}))
    no("two keys out of order", card({12: [[ES256, k] for k in reversed(tls)]}), "card/keys")
    no("a key twice", card({12: [[ES256, tls[0]]] * 2}), "card/keys")
    no("an endpoint twice", card({11: ["fwd.example.org:443"] * 2}), "card/endpoints")
    for e in ["0192.0.2.7:443", "192.0.2.07:443", "3221225991:443", "0xc0.0.2.7:443", "EXAMPLE.org:443",
              "fwd.example.org:0", "[2001:DB8::1]:443", "[2001:db8:0:0:0:0:0:1]:443", "[::1]:443",
              "127.0.0.1:443", "[fe80::1]:443", "169.254.1.1:443", "[ff02::1]:443", "224.0.0.1:443",
              "0.0.0.0:443", "localhost:443", "a-.example.org:443", "10.1.2.3:443", "172.16.0.1:443",
              "192.168.1.1:443", "100.64.0.1:443", "0.1.2.3:443", "240.0.0.1:443", "[::ffff:0:7f00:1]:443",
              "[64:ff9b::7f00:1]:443", "[2002:7f00:1::1]:443", "[fec0::1]:443", "[fd00::1]:443",
              "printer.local:443"]:
        no(f"an endpoint {e}", card({11: [e]}), "card/endpoints")
    ok("an endpoint by IPv6 address", card({11: ["fwd.example.org:443", "[2001:db8::7]:443"]}))
    ok("an endpoint by NAT64 of a public address", card({11: ["[64:ff9b::c000:207]:443", "172.32.0.1:443"]}))
    no("kinds 4", card({13: 4}), "card/kinds")
    no("signed by another key than the operator it names", card(), "sig/verify", by=STRANGER)
    return take, refuse


# ---------------------------------------------------------------- wave 4

# The messages wave 4 adds (section 9.2): what each carries is read by its
# own reader; the copy (t 2) by the copy's.
TABLES4 = {
    "keys-message": [(2, "keys-message/list", "array 1..256 of envelope", True)],
    "command": [(2, "command/envelope", "envelope", True)],
    "nonce": [(2, "nonce/nonce", "bytes 16", False)],
    "beacon": [(2, "beacon/envelope", "envelope", True)],
    "reseal": [(2, "reseal/copy", "bytes 16", True), (3, "reseal/epoch", "uint 1..9223372036854775807", True)],
    # To a leaf: the recovery heads it needs, and its root's fork (two
    # records of the root at one seq, exactly two).
    "roots": [(2, "roots/heads", "array 1..64 of envelope", False), (3, "roots/fork", "array 1..2 of envelope", False)],
}
MESSAGE_TYPES4 = {7: "keys-message", 9: "command", 21: "nonce", 22: "beacon", 23: "reseal", 24: "roots"}
TABLES.update(TABLES4)

MEDIA_TYPES = 4


def _device(name):
    base = name.split(".", 1)[0].rstrip(" ").upper()
    if base in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"):
        return True
    for pre in ("COM", "LPT"):
        if base.startswith(pre) and base[3:] in [str(d) for d in range(10)] + ["¹", "²", "³"]:
            return True
    return False


def _reserved(name):
    base = name.split(".", 1)[0].upper()
    return base in ("CON", "PRN", "AUX", "NUL") or (
        len(base) == 4 and base[:3] in ("COM", "LPT") and "1" <= base[3] <= "9")


def _save_name(name):
    if not _device(name):
        return name
    if "." in name:
        base, ext = name.split(".", 1)
        return base + "_." + ext
    return name + "_"


def _save_path(path):
    return "/".join(_save_name(n) for n in path.split("/"))


def _name_ok(name):
    nb = len(name.encode())
    return not (nb == 0 or nb > 255 or len(_save_name(name).encode()) > 255 or name in (".", "..")
                or any(c in name for c in '/\\:*?"<>|') or name.endswith(".") or name.endswith(" ")
                or _reserved(name) or any(c < " " or c == "\x7f" or "\x80" <= c < "\xa0" for c in name))


def _path_ok(path):
    return (0 < len(path.encode()) <= 4096 and len(_save_path(path).encode()) <= 4096
            and all(_name_ok(n) for n in path.split("/")))


def read_manifest(m):
    """The manifest's rows (section 10.3): the parts as dicts, or a rule."""
    bad = "content/manifest"
    if not isinstance(m, dict) or any(k < 256 and k not in (1, 2) for k in m):
        return None, bad
    if 1 in m:
        if not isinstance(m[1], int) or m[1] >= 1 << 63:
            return None, bad
        if m[1] == 0:
            return None, "form/default"
    parts = m.get(2)
    if not isinstance(parts, list) or not 1 <= len(parts) <= 10000:
        return None, bad
    for p in parts:
        if not isinstance(p, dict) or any(k < 256 and k not in (1, 2, 3, 4, 5) for k in p):
            return None, bad
        if 1 in p and not (isinstance(p[1], int) and 1 <= p[1] <= MEDIA_TYPES):
            return None, bad
        if 2 in p and not (isinstance(p[2], str) and p[2]):
            return None, bad
        if 3 in p and p[3] != 1:
            return None, bad
        if 4 in p:
            if not isinstance(p[4], int) or p[4] >= 1 << 63:
                return None, bad
            if p[4] == 0:
                return None, "form/default"
        if 5 in p and not (isinstance(p[5], bytes) and len(p[5]) == 32):
            return None, bad
    return m, None


def manifest_ok(m):
    """Today's manifest rules."""
    parts = m[2]
    files = 2 in parts[0]
    if not files and len(parts) > 8:
        return False
    seen, total, paths = set(), 0, 0
    for p in parts:
        if files:
            if 2 not in p or 1 in p or not _path_ok(p[2]):
                return False
            paths += len(p[2].encode())
            key = _save_path(p[2])
        else:
            if 1 not in p or 3 in p:
                return False
            key = p[1]
        if key in seen:
            return False
        seen.add(key)
        if 3 in p:
            if 4 in p or 5 in p:
                return False
            continue
        if 5 not in p or p.get(4, 0) > 1 << 30:
            return False
        total += p.get(4, 0)
    if paths > 512 << 10 or total != m.get(1, 0) or total > 1 << 30:
        return False
    if files:
        kind = {_save_path(p[2]): 3 in p for p in parts}
        for p in parts:
            sp = _save_path(p[2])
            for i, ch in enumerate(sp):
                if ch == "/" and kind.get(sp[:i]) is False:
                    return False
    return True


def _bidi(c):
    o = ord(c)
    return o in (0x61C, 0x200E, 0x200F) or 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069


# The three simple case foldings (status S) of CaseFolding.txt 15.1 that
# Python's Unicode data does not give: their full folding is shared with
# another code point, and their lower case is themselves.
FOLD_S_EXTRA = {0xFB05: 0xFB06, 0x1FD3: 0x0390, 0x1FE3: 0x03B0}


def _simple_fold(c):
    """CaseFolding.txt's C and S mappings, from Python's Unicode data."""
    o = ord(c)
    if o in FOLD_S_EXTRA:
        return chr(FOLD_S_EXTRA[o])
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def _case_key(c):
    """The character two names are compared by when case is ignored: the
    simple case folding of its upper case (when that is one character), so
    names one on NTFS (upper case) or on APFS (case folding) are one here."""
    up = c.upper()
    return _simple_fold(up if len(up) == 1 else c)


def _nfc_ok(path):
    """The name is its own NFC."""
    return unicodedata.normalize("NFC", path) == path


def unicode_tables():
    """The tables of the name rules, from this Python's Unicode data: each
    canonical decomposition one level deep (Hangul aside, by rule), the
    primary composites by their pair, the non-zero combining classes, and
    the case key of each code point whose key is not itself."""
    decomp, comp, ccc, keys = [], [], [], []
    for c in range(0x110000):
        if 0xD800 <= c <= 0xDFFF:
            continue
        ch = chr(c)
        k = _case_key(ch)
        if k != ch:
            keys.append((c, ord(k)))
        cc = unicodedata.combining(ch)
        if cc:
            if ccc and ccc[-1][1] == c - 1 and ccc[-1][2] == cc:
                ccc[-1][1] = c
            else:
                ccc.append([c, c, cc])
        if 0xAC00 <= c <= 0xD7A3:
            continue
        d = unicodedata.decomposition(ch)
        if not d or d.startswith("<"):
            continue
        p = [int(x, 16) for x in d.split()]
        decomp.append((c, p[0], p[1] if len(p) > 1 else 0))
        if len(p) == 2 and unicodedata.normalize("NFC", ch) == ch:
            comp.append((p[0], p[1], c))
    return decomp, sorted(comp), ccc, keys


UNICODE_HEAD = ("Written by testdata/format/gen.py from Unicode %s for the names of files:\n"
                "canonical decompositions one level deep (second 0 for one code point), the\n"
                "primary composites by their pair (Hangul by rule), the non-zero combining\n"
                "classes, and the case keys (the simple case folding, C and S, of the upper\n"
                "case). Do not edit.")


def write_unicode(outdir):
    decomp, comp, ccc, keys = unicode_tables()
    head = UNICODE_HEAD % unicodedata.unidata_version
    lic = "SPDX-License-Identifier: AGPL-3.0-only\nCopyright (C) 2026 HunterEwok\n"
    rows = lambda items, f, per: "\n".join("    " + " ".join(f(x) for x in items[i:i + per]) for i in range(0, len(items), per))
    h3 = lambda r: "(0x%X, 0x%X, 0x%X)," % tuple(r)
    h2 = lambda r: "(0x%X, 0x%X)," % tuple(r)
    rs = ("".join("// " + l + "\n" for l in lic.splitlines()) + "\n" + "".join("//! " + l + "\n" for l in head.splitlines())
          + "\n#[rustfmt::skip]\npub(crate) static DECOMP: &[(u32, u32, u32)] = &[\n" + rows(decomp, h3, 4) + "\n];\n"
          + "\n#[rustfmt::skip]\npub(crate) static COMP: &[(u32, u32, u32)] = &[\n" + rows(comp, h3, 4) + "\n];\n"
          + "\n#[rustfmt::skip]\npub(crate) static CCC: &[(u32, u32, u8)] = &[\n" + rows(ccc, lambda r: "(0x%X, 0x%X, %d)," % tuple(r), 5) + "\n];\n"
          + "\n#[rustfmt::skip]\npub(crate) static CASE: &[(u32, u32)] = &[\n" + rows(keys, h2, 6) + "\n];\n")
    g = lambda f: (lambda r: f(r).replace("(", "{").replace("),", "},"))
    go = ("".join("// " + l + "\n" for l in lic.splitlines()) + "\n" + "".join("// " + l + "\n" for l in head.splitlines())
          + "\npackage main\n"
          + "\nvar uDecomp = [][3]rune{\n" + rows(decomp, g(h3), 4).replace("    ", "\t") + "\n}\n"
          + "\nvar uComp = [][3]rune{\n" + rows(comp, g(h3), 4).replace("    ", "\t") + "\n}\n"
          + "\nvar uCCC = [][3]rune{\n" + rows(ccc, lambda r: "{0x%X, 0x%X, %d}," % tuple(r), 5).replace("    ", "\t") + "\n}\n"
          + "\nvar uCase = [][2]rune{\n" + rows(keys, g(h2), 6).replace("    ", "\t") + "\n}\n")
    with open(os.path.join(outdir, "..", "..", "core", "src", "content", "unicode.rs"), "w") as f:
        f.write(rs)
    with open(os.path.join(outdir, "check", "unicode.go"), "w") as f:
        f.write(go)


def names_ok(m):
    """0.6's rules on names of files: no device name of Windows, no
    bidirectional control, every name its own NFC, no two paths one by the
    case key of each character, nor a path inside a file so."""
    kind = {}
    for p in m[2]:
        path = p[2]
        if any(_device(n) for n in path.split("/")) or any(_bidi(c) for c in path) or not _nfc_ok(path):
            return False
        key = "".join(_case_key(c) for c in path)
        if key in kind:
            return False
        kind[key] = 3 in p
    for key in kind:
        for i, ch in enumerate(key):
            if ch == "/" and kind.get(key[:i]) is False:
                return False
    return True


def content_rule(b):
    """The verdict on a content as section 10.3 has it: "take", "keep" (a
    type, flag or critical field of a later version: passed on, never
    written) or the rule it breaks."""
    try:
        c = dec(b)
    except Bad as e:
        return e.rule
    if not isinstance(c, dict) or not isinstance(c.get(0), int):
        return "copy/shape"
    pad = c.get(1)
    if pad is None:
        if len(b) not in STEPS:
            return "copy/content-pad"
    else:
        rest = {k: v for k, v in c.items() if k != 1}
        if not isinstance(pad, bytes) or any(pad) or pad_content(rest) != b:
            return "copy/content-pad"
    t = c[0]
    if t == 0:
        return "content/type"
    for f, rule in [(2, "content/flags"), (3, "content/ttl"), (4, "content/via")]:
        if f in c and not isinstance(c[f], int):
            return rule
        if c.get(f) == 0:
            return "form/default"
    if 5 in c and not isinstance(c[5], str):
        return "content/text"
    man = None
    if 6 in c:
        man, rule = read_manifest(c[6])
        if rule:
            return rule
    if 7 in c and not isinstance(c[7], bytes):
        return "content/data"
    if c.get(3, 1) > 4:
        return "content/ttl"
    if c.get(4, 1) > 2:
        return "content/via"
    if c.get(5) == "":
        return "form/default"
    known = t <= 4
    if t == 1 and 5 not in c:
        return "content/text"
    if t in (2, 3):
        if man is None or (2 in man[2][0]) != (t == 3) or not manifest_ok(man) or (t == 3 and not names_ok(man)):
            return "content/manifest"
        if len(c.get(5, "").encode()) > 256 << 10:
            return "content/text"
    if t == 4:
        d = c.get(7)
        if not isinstance(d, bytes) or not 1 <= len(d) <= 4096:
            return "content/data"
        try:
            dec(d)
        except Bad:
            return "content/data"
    if known and 6 in c and t not in (2, 3):
        return "content/manifest"
    if known and 7 in c and t != 4:
        return "content/data"
    if known and t == 4 and 5 in c:
        return "content/text"
    if not known or c.get(2, 0) & ~1 or any(k < 256 and k not in range(8) for k in c):
        return "keep"
    return "take"


def command_rule(env_b):
    """The rule a command's form breaks (section 6 and wave 4), or "take"."""
    try:
        env = dec(env_b)
    except Bad as e:
        return e.rule
    if not (isinstance(env, list) and len(env) == 2 and all(isinstance(x, bytes) for x in env)):
        return "env/shape"
    if len(env[0]) > 2 << 20:
        return "env/size"
    m = dec(env[0])
    if any(k < 256 and k not in (1, 2, 3, 4, 6, 7, 10, 11, 13, 14, 15) for k in m):
        return "form/critical"
    t = m.get(1)
    if not (isinstance(t, int) and 1 <= t <= 10):
        return "commands/type"
    if t != 3 and len(env[0]) > 64 << 10:
        return "env/size"
    for f, n, rule in [(2, 16, "commands/group"), (3, 32, "commands/signer")]:
        if not (isinstance(m.get(f), bytes) and len(m[f]) == n):
            return rule
    if not (isinstance(m.get(4), int) and m[4] >= 1):
        return "commands/n"
    if not isinstance(m.get(6), int):
        return "commands/time"
    if not (isinstance(m.get(7), int) and m[6] < m[7] <= m[6] + 30000):
        return "commands/expires"
    for f, rule in [(10, "commands/to"), (11, "commands/id")]:
        if not (isinstance(m.get(f), bytes) and len(m[f]) == 16):
            return rule
    if 13 in m and not (isinstance(m[13], bytes) and len(m[13]) == 16):
        return "commands/nonce"
    if m.get(14) == 0:
        return "form/default"
    if 14 in m and not isinstance(m[14], int):
        return "commands/epoch"
    if 15 in m and not (isinstance(m[15], bytes) and len(m[15]) >= 1136):
        return "commands/sealed"
    if (14 in m) != (15 in m):
        return "commands/epoch"
    if 15 in m and t not in (1, 2, 3, 5, 8, 10):
        return "commands/sealed"
    return "take"


def orders_rule(t, b):
    """The rule opened orders of type t break, or "take"."""
    o = dec(b)
    allowed = {1: (10,), 2: (10, 11, 12, 13), 3: (10, 11, 12, 13, 14), 5: (10,), 8: (10,), 10: (10, 11)}.get(t)
    if allowed is None:
        return "commands/type"
    if not isinstance(o, dict) or any(k < 256 and k not in allowed for k in o):
        return "form/critical"
    if t == 1:
        return "take" if o.get(10) in (1, 2) else "orders/mode"
    if t == 2:
        return hub_rule(o)
    if t == 3:
        way, kind = o.get(10), o.get(12)
        if way not in (1, 2) or kind not in (1, 2, 3) or o.get(11, 1) != 1:
            return "orders/paste"
        if kind in (1, 2):
            txt = o.get(13)
            ok = isinstance(txt, str) and 14 not in o and 1 <= len(txt.encode()) <= (4096 if way == 2 else 1 << 20)
        else:
            ok = 13 not in o and isinstance(o.get(14), bytes) and len(o[14]) == 16 and way == 1
        return "take" if ok else "orders/paste"
    if t == 5:
        a = o.get(10)
        ok = (isinstance(a, str) and 1 <= len(a) <= 32 and a[0].isascii() and a[0].islower()
              and all(c.isascii() and (c.islower() or c.isdigit() or c == "-") for c in a))
        return "take" if ok else "orders/action"
    if t == 8:
        return "take" if 10 not in o or (isinstance(o[10], int) and 1 <= o[10] <= 2592000000) else "orders/mute"
    if t == 10:
        name = o.get(10)
        hidden = lambda ch: ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f or 0x2028 <= ord(ch) <= 0x202e or 0x2066 <= ord(ch) <= 0x2069
        if not (isinstance(name, str) and 1 <= len(name.encode()) <= 32 and not any(hidden(ch) for ch in name)):
            return "orders/device"
        if 11 in o:
            a = o[11]
            if not (isinstance(a, bytes) and 1 <= len(a) <= 4096):
                return "orders/device"
            try:
                dec(a)
            except Bad:
                return "orders/device"
        return "take"
    raise ValueError(t)


def _plain(x, most=255):
    hidden = lambda ch: ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f or 0x2028 <= ord(ch) <= 0x202e or 0x2066 <= ord(ch) <= 0x2069
    return isinstance(x, str) and 1 <= len(x.encode()) <= most and not any(hidden(ch) for ch in x)


def hub_rule(o):
    """`hub` orders: 13 off alone, or 10 [endpoint, key 32], 11 forwarders
    (1 to 8 texts, each once), 12 clients (a set of 1 to 256 [ID 16, key
    32, psk 32]); not empty."""
    bad = "orders/hub"
    if 13 in o:
        return "take" if o[13] == 1 and all(k >= 256 or k == 13 for k in o) else bad
    if 10 in o:
        a = o[10]
        if not (isinstance(a, list) and len(a) == 2 and _plain(a[0]) and isinstance(a[1], bytes) and len(a[1]) == 32):
            return bad
    if 11 in o:
        a = o[11]
        if not (isinstance(a, list) and 1 <= len(a) <= 8 and all(_plain(x) for x in a) and len(set(a)) == len(a)):
            return bad
    if 12 in o:
        a = o[12]
        if not (isinstance(a, list) and 1 <= len(a) <= 256):
            return bad
        keys = [enc(x[0] if isinstance(x, list) and x else x) for x in a]
        if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
            return bad
        if not all(isinstance(c, list) and len(c) == 3 and all(isinstance(v, bytes) and len(v) == n for v, n in zip(c, (16, 32, 32))) for c in a):
            return bad
    if all(k >= 256 for k in o):
        return bad
    return "take"


def statement_rule(env_b):
    """A keys statement (section 5): "take", "hold" or the rule."""
    env = dec(env_b)
    body = env[0]
    if len(body) > 2048:
        return "env/size"
    m = dec(body)
    if not (isinstance(m.get(1), int) and m[1] >= 1):
        return "statements/type"
    if not (isinstance(m.get(2), bytes) and len(m[2]) == 16):
        return "statements/group"
    if not (isinstance(m.get(3), bytes) and len(m[3]) == 32):
        return "statements/signer"
    if not (isinstance(m.get(4), int) and m[4] >= 1):
        return "statements/epoch"
    if m[1] != 1 or any(k < 256 and k not in (1, 2, 3, 4, 6, 10) for k in m) or len(env) == 3:
        return "hold"
    if m.get(6) == 0:
        return "form/default"
    if 6 in m and not isinstance(m[6], int):
        return "statements/time"
    if 10 not in m:
        return "statements/seal"
    k = m[10]
    if not (isinstance(k, list) and len(k) == 2 and isinstance(k[0], int) and isinstance(k[1], bytes)):
        return "keys/shape"
    alg, pub = k
    if alg == ES256:
        return "keys/es256" if len(pub) != 65 or pub[0] != 4 else "keys/xwing"
    if alg == XWING:
        return "take" if len(pub) == 1216 else "keys/xwing"
    if alg == X25519:
        return "keys/x25519" if len(pub) != 32 else "keys/xwing"
    return "hold"


def beacon_rule(env_b):
    """The rule a beacon's form breaks (section 9.4), or "take"."""
    env = dec(env_b)
    if len(env[0]) > 512:
        return "env/size"
    m = dec(env[0])
    if any(k < 256 and k not in (1, 2, 3, 4, 6, 10, 11) for k in m):
        return "form/critical"
    if m.get(1) != 1:
        return "beacons/type"
    if not (isinstance(m.get(2), bytes) and len(m[2]) == 16):
        return "beacons/group"
    if not (isinstance(m.get(3), bytes) and len(m[3]) == 32):
        return "beacons/signer"
    if not (isinstance(m.get(4), int) and m[4] >= 1):
        return "beacons/n"
    if not (isinstance(m.get(6), int) and m[6] >= 1):
        return "beacons/time"
    if not (isinstance(m.get(10), bytes) and len(m[10]) == 32):
        return "beacons/digest"
    if not (isinstance(m.get(11), int) and 1 <= m[11] <= 7168):
        return "beacons/count"
    return "take"


def wave4_vectors():
    out = {"labels": {k: LABELS[k] for k in ("keys", "command", "beacon")},
           "tables": {name: [{"n": n, "rule": r, "type": t, "needed": nd} for n, r, t, nd in rows]
                      for name, rows in TABLES4.items()},
           "types": {str(t): name for t, name in MESSAGE_TYPES4.items()}}

    # contents
    png = {1: 3, 2: [{1: 1, 4: 3, 5: sha(b"png")}]}
    tree = {1: 5, 2: [{2: "docs", 3: 1}, {2: "docs/a.txt", 4: 5, 5: sha(b"a")}]}
    cases = [
        ("text", {0: 1, 5: "hello"}),
        ("secret text with a ttl", {0: 1, 2: 1, 3: 1, 5: "hunter2"}),
        ("secret image with its text", {0: 2, 2: 1, 5: "alt", 6: png}),
        ("files from a phone", {0: 3, 4: 1, 6: tree}),
        ("a device's state", {0: 4, 7: enc({1: 21})}),
        ("a secret device state", {0: 4, 2: 1, 7: enc({1: 22})}),
        ("an optional field skipped", {0: 1, 5: "x", 300: 1}),
        ("a type of a later version", {0: 9, 5: "x"}),
        ("a flag of a later version", {0: 1, 2: 2, 5: "x"}),
        ("a critical field of a later version", {0: 1, 5: "x", 40: 1}),
        ("type 0", {0: 0}),
        ("flags 0 written", {0: 1, 2: 0, 5: "x"}),
        ("ttl 5", {0: 1, 3: 5, 5: "x"}),
        ("via 3", {0: 1, 4: 3, 5: "x"}),
        ("text without text", {0: 1}),
        ("empty text", {0: 1, 5: ""}),
        ("text as bytes", {0: 1, 5: b"x"}),
        ("media without a manifest", {0: 2, 5: "x"}),
        ("media with a files manifest", {0: 2, 6: tree}),
        ("files with a media manifest", {0: 3, 6: png}),
        ("manifest on a text", {0: 1, 5: "x", 6: png}),
        ("manifest size not its parts'", {0: 2, 6: {1: 4, 2: png[2]}}),
        ("state on a text", {0: 1, 5: "x", 7: b"\x01"}),
        ("state without data", {0: 4}),
        ("state not one item", {0: 4, 7: b"\x82\x01"}),
        ("state over 4 KiB", {0: 4, 7: enc(bytes(4100))}),
        ("state with text", {0: 4, 5: "x", 7: b"\x01"}),
        ("a flag far beyond the known", {0: 1, 2: (1 << 62) + 1, 5: "x"}),
        ("a later type with a field 6 not a manifest", {0: 5, 6: 1}),
        ("media with one type twice", {0: 2, 6: {1: 6, 2: [{1: 1, 4: 3, 5: sha(b"a")}, {1: 1, 4: 3, 5: sha(b"b")}]}}),
        ("media of nine types", {0: 2, 6: {1: 9, 2: [{1: 1 + i % 4, 4: 1, 5: sha(bytes([i]))} for i in range(9)]}}),
        ("media part without its hash", {0: 2, 6: {1: 3, 2: [{1: 1, 4: 3}]}}),
        ("media part with a folder", {0: 2, 6: {2: [{1: 1, 3: 1}]}}),
        ("manifest with a critical field 3", {0: 2, 6: {1: 3, 2: png[2], 3: 1}}),
        ("manifest size written as 0", {0: 2, 6: {1: 0, 2: png[2]}}),
        ("files with a path up", {0: 3, 6: {1: 5, 2: [{2: "../../.bashrc", 4: 5, 5: sha(b"a")}]}}),
        ("files with a name Windows reserves", {0: 3, 6: {1: 5, 2: [{2: "docs/CON.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a name ending in a dot", {0: 3, 6: {1: 5, 2: [{2: "a.", 4: 5, 5: sha(b"a")}]}}),
        ("files with one path twice as written", {0: 3, 6: {1: 10, 2: [{2: "COM\u00b9", 4: 5, 5: sha(b"a")}, {2: "COM\u00b9_", 4: 5, 5: sha(b"b")}]}}),
        ("files with a file inside a file", {0: 3, 6: {1: 10, 2: [{2: "a", 4: 5, 5: sha(b"a")}, {2: "a/b", 4: 5, 5: sha(b"b")}]}}),
        ("files with a folder that has a size", {0: 3, 6: {1: 5, 2: [{2: "d", 3: 1, 4: 5}]}}),
        ("files named as a device with a superscript", {0: 3, 6: {1: 5, 2: [{2: "lpt\u00b3.log", 4: 5, 5: sha(b"a")}]}}),
        ("files named as a console device", {0: 3, 6: {1: 5, 2: [{2: "d/CONIN$", 4: 5, 5: sha(b"a")}]}}),
        ("files named as COM0 with an extension", {0: 3, 6: {1: 5, 2: [{2: "com0.tar.gz", 4: 5, 5: sha(b"a")}]}}),
        ("files named as a device before spaces", {0: 3, 6: {1: 5, 2: [{2: "NUL  .txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with names one but for case", {0: 3, 6: {1: 10, 2: [{2: "Notes.txt", 4: 5, 5: sha(b"a")}, {2: "notes.TXT", 4: 5, 5: sha(b"b")}]}}),
        ("files with names one but for case beyond ASCII", {0: 3, 6: {1: 10, 2: [{2: "\u00c9T\u00c9", 4: 5, 5: sha(b"a")}, {2: "\u00e9t\u00e9", 4: 5, 5: sha(b"b")}]}}),
        ("files with a file inside a file but for case", {0: 3, 6: {1: 10, 2: [{2: "Read", 4: 5, 5: sha(b"a")}, {2: "read/me", 4: 5, 5: sha(b"b")}]}}),
        ("files with an e and a combining acute", {0: 3, 6: {1: 5, 2: [{2: "cafe\u0301.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a decomposed Hangul syllable", {0: 3, 6: {1: 5, 2: [{2: "\u1112\u1161\u11ab", 4: 5, 5: sha(b"a")}]}}),
        ("files with a name of a kana and its voicing mark", {0: 3, 6: {1: 5, 2: [{2: "\u304b\u3099", 4: 5, 5: sha(b"a")}]}}),
        ("files with a name that reads backwards", {0: 3, 6: {1: 5, 2: [{2: "photo\u202egpj.exe", 4: 5, 5: sha(b"a")}]}}),
        ("files with an isolate in a name", {0: 3, 6: {1: 5, 2: [{2: "a\u2067b", 4: 5, 5: sha(b"a")}]}}),
        ("files with a right-to-left mark in a name", {0: 3, 6: {1: 5, 2: [{2: "a\u200fb", 4: 5, 5: sha(b"a")}]}}),
        ("files with names in NFC and in other scripts", {0: 3, 6: {1: 15, 2: [{2: "caf\u00e9.txt", 4: 5, 5: sha(b"a")}, {2: "\ud55c\uae00", 4: 5, 5: sha(b"b")}, {2: "\u05e9\u05dc\u05d5\u05dd.txt", 4: 5, 5: sha(b"c")}]}}),
        ("files with a Hindi name", {0: 3, 6: {1: 5, 2: [{2: "\u0939\u093f\u0928\u094d\u0926\u0940.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with an Arabic name with harakat", {0: 3, 6: {1: 5, 2: [{2: "\u0643\u064e\u062a\u064e\u0628\u064e.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a Hebrew name with niqqud", {0: 3, 6: {1: 5, 2: [{2: "\u05e9\u05b8\u05c1\u05dc\u05d5\u05b9\u05dd.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a combining mark nothing composes with", {0: 3, 6: {1: 5, 2: [{2: "q\u0301.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with two marks out of canonical order", {0: 3, 6: {1: 5, 2: [{2: "q\u0301\u0323.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with two marks in canonical order", {0: 3, 6: {1: 5, 2: [{2: "q\u0323\u0301.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a mark that composes across another class", {0: 3, 6: {1: 5, 2: [{2: "e\u0316\u0301.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with a mark out of order behind a precomposed letter", {0: 3, 6: {1: 5, 2: [{2: "\u00e2\u0325.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with the NFC of a mark across another class", {0: 3, 6: {1: 5, 2: [{2: "\u00e9\u0316.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files with sigma and final sigma", {0: 3, 6: {1: 10, 2: [{2: "\u03c3.txt", 4: 5, 5: sha(b"a")}, {2: "\u03c2.txt", 4: 5, 5: sha(b"b")}]}}),
        ("files with s and long s", {0: 3, 6: {1: 10, 2: [{2: "s.txt", 4: 5, 5: sha(b"a")}, {2: "\u017f.txt", 4: 5, 5: sha(b"b")}]}}),
        ("files with i and dotless i", {0: 3, 6: {1: 10, 2: [{2: "i.txt", 4: 5, 5: sha(b"a")}, {2: "\u0131.txt", 4: 5, 5: sha(b"b")}]}}),
        ("files with micro and mu", {0: 3, 6: {1: 10, 2: [{2: "\u00b5.txt", 4: 5, 5: sha(b"a")}, {2: "\u03bc.txt", 4: 5, 5: sha(b"b")}]}}),
        ("files with i and dotted capital I", {0: 3, 6: {1: 10, 2: [{2: "i.txt", 4: 5, 5: sha(b"a")}, {2: "\u0130.txt", 4: 5, 5: sha(b"b")}]}}),
        ("files with a precomposed character NFC replaces", {0: 3, 6: {1: 5, 2: [{2: "\u212b.txt", 4: 5, 5: sha(b"a")}]}}),
        ("files named like a device but longer", {0: 3, 6: {1: 10, 2: [{2: "COM10", 4: 5, 5: sha(b"a")}, {2: "console.log", 4: 5, 5: sha(b"b")}]}}),
        ("files of more than 1 GiB", {0: 3, 6: {1: (1 << 30) + 1, 2: [{2: "big", 4: (1 << 30) + 1, 5: sha(b"a")}]}}),
    ]
    contents = []
    for name, c in cases:
        b = pad_content(c)
        contents.append({"name": name, "verdict": content_rule(b), "diag": diag(c), "content": b.hex()})
    bad = bytearray(pad_content({0: 1, 5: "x"}))
    bad[len(bad) // 2] = 1
    contents.append({"name": "padding not zero", "verdict": "copy/content-pad", "content": bytes(bad).hex()})
    out["contents"] = contents

    # commands: the form's rules between fields
    def body(t, extra=None, drop=()):
        m = {1: t, 2: GROUP, 3: ADMIN.hash, 4: 7, 6: T0, 7: T0 + 30000, 10: LAPTOP.id16,
             11: sha(b"cmd", t.to_bytes(2, "big"))[:16]}
        m.update(extra or {})
        for d in drop:
            m.pop(d, None)
        return m

    sealed = fake("sealed orders", 1120 + 16 + 4)
    commands = []
    for name, m in [
        ("mode, sealed", body(1, {14: 2, 15: sealed})),
        ("unmute, no orders", body(9)),
        ("a guarded lock's command with its nonce", body(10, {13: fake("n", 16), 14: 1, 15: sealed})),
        ("type 0", body(0)),
        ("type 11", body(11)),
        ("n 0", body(4, {4: 0})),
        ("no time", body(4, drop=(6,))),
        ("expires at its time", body(4, {7: T0})),
        ("lifetime of 30 s and 1 ms", body(4, {7: T0 + 30001})),
        ("to of 15 bytes", body(4, {10: bytes(15)})),
        ("nonce of 15 bytes", body(4, {13: bytes(15)})),
        ("epoch without sealed", body(1, {14: 2})),
        ("sealed without epoch", body(1, {15: sealed})),
        ("epoch 0 written", body(1, {14: 0, 15: sealed})),
        ("sealed shorter than a seal", body(1, {14: 2, 15: bytes(100)})),
        ("sealed on a type without orders", body(6, {14: 2, 15: sealed})),
        ("field 12 (class, gone)", body(4, {12: 4})),
        ("a critical field of a later version", body(4, {99: 1})),
        ("epoch as bytes", body(1, {14: b"\x02", 15: sealed})),
        ("paste-off of 70 KiB", body(4, {300: bytes(70 << 10)})),
        ("paste of 70 KiB", body(3, {300: bytes(70 << 10)})),
    ]:
        env, b = envelope("command", ADMIN, m)
        commands.append({"name": name, "verdict": command_rule(env), "diag": diag(m), "envelope": env.hex()})
    out["commands"] = commands

    orders = []
    for name, t, o in [
        ("mode own", 1, {10: 2}),
        ("paste typed with enter", 3, {10: 2, 11: 1, 12: 2, 13: "pw\n"}),
        ("paste of a media copy", 3, {10: 1, 12: 3, 14: fake("copy id", 16)}),
        ("action", 5, {10: "lock-screen"}),
        ("mute until unmute", 8, {}),
        ("mute for a minute", 8, {10: 60000}),
        ("device command with arguments", 10, {10: "heat", 11: enc({1: 90})}),
        ("mode 3", 1, {10: 3}),
        ("mode with a later critical field", 1, {10: 1, 11: 1}),
        ("paste without text", 3, {10: 1, 12: 1}),
        ("paste typed over 4 KiB", 3, {10: 2, 12: 1, 13: "x" * 4097}),
        ("paste of media with a text", 3, {10: 1, 12: 3, 13: "x"}),
        ("paste enter 2", 3, {10: 1, 11: 2, 12: 1, 13: "x"}),
        ("action with a capital", 5, {10: "Reboot"}),
        ("action starting with a digit", 5, {10: "1st"}),
        ("mute over 30 days", 8, {10: 2592000001}),
        ("device command with a hidden character", 10, {10: "he‮at"}),
        ("device command with arguments not one item", 10, {10: "heat", 11: b"\x82"}),
        ("hub to use with a forwarder", 2, {10: ["203.0.113.5:51820", fake("hub key", 32)], 11: ["cbb.tools:8764"]}),
        ("hub off", 2, {13: 1}),
        ("hub with its clients", 2, {12: sorted([[fake("c1", 16), fake("k1", 32), fake("p1", 32)], [fake("c2", 16), fake("k2", 32), fake("p2", 32)]], key=lambda c: enc(c[0]))}),
        ("hub empty", 2, {}),
        ("hub off with an endpoint", 2, {13: 1, 10: ["203.0.113.5:51820", fake("hub key", 32)]}),
        ("hub endpoint with a hidden character", 2, {10: ["203.0.113.5\u202e:51820", fake("hub key", 32)]}),
        ("hub forwarder twice", 2, {11: ["cbb.tools:8764", "cbb.tools:8764"]}),
        ("hub clients out of order", 2, {12: sorted([[fake("c1", 16), fake("k1", 32), fake("p1", 32)], [fake("c2", 16), fake("k2", 32), fake("p2", 32)]], key=lambda c: enc(c[0]), reverse=True)}),
        ("orders of a type without orders", 4, {10: 1}),
    ]:
        b = enc(o)
        orders.append({"name": name, "type": t, "verdict": orders_rule(t, b), "orders": b.hex()})
    out["orders"] = orders

    # keys statements: taken, held (a later version wrote them) or refused
    statements = []
    good = fake("seal", 1216)
    for name, signer, m, sig2 in [
        ("a statement of this version", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 6: T0, 10: [XWING, good]}, False),
        ("a critical field of a later version", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [XWING, fake("s5", 1216)], 99: 1}, False),
        ("a type of a later version", LAPTOP, {1: 2, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [XWING, fake("s6", 1216)]}, False),
        ("a type of a later version without a key", LAPTOP, {1: 2, 2: GROUP, 3: LAPTOP.hash, 4: 5}, False),
        ("a type of a later version with another field 10", LAPTOP, {1: 2, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: "x"}, False),
        ("a sealing key of a later algorithm", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [9, fake("s7", 40)]}, False),
        ("no type", LAPTOP, {2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [XWING, good]}, False),
        ("time 0 written", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 6: 0, 10: [XWING, good]}, False),
        ("no sealing key", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5}, False),
        ("an ES256 key to seal with", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: LAPTOP.key}, False),
        ("an X25519 key to seal with", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [X25519, fake("x", 32)]}, False),
        ("an X-Wing key one byte short", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 5, 10: [XWING, good[:-1]]}, False),
        ("epoch 0", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 0, 10: [XWING, good]}, False),
    ]:
        env, b = envelope("keys", signer, m)
        statements.append({"name": name, "verdict": statement_rule(env), "diag": diag(m), "envelope": env.hex()})
    out["statements"] = statements

    # beacons
    beacons = []
    digest = sha(b"a set")
    for name, m in [
        ("an admin's phone saw 12 records", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 12}),
        ("an optional field skipped", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 4, 6: T0, 10: digest, 11: 12, 300: 1}),
        ("type 2", {1: 2, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 12}),
        ("no time", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 10: digest, 11: 12}),
        ("count 0", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 0}),
        ("count over a set", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 7169}),
        ("no count", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest}),
        ("digest of 31 bytes", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest[:31], 11: 12}),
        ("a critical field of a later version", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 12, 12: 1}),
        ("over 512 bytes", {1: 1, 2: GROUP, 3: PHONE.hash, 4: 3, 6: T0, 10: digest, 11: 12, 300: bytes(500)}),
    ]:
        env, b = envelope("beacon", PHONE, m)
        beacons.append({"name": name, "verdict": beacon_rule(env), "diag": diag(m), "envelope": env.hex()})
    out["beacons"] = beacons

    # messages
    good_cmd = dec(bytes.fromhex(commands[0]["envelope"]))
    good_beacon = dec(bytes.fromhex(beacons[0]["envelope"]))
    good_rec = dec(envelope("record", ROOT, {1: 1, 2: GROUP, 3: ROOT.hash, 4: 2, 5: sha(b"prev"), 10: 5000})[0])
    good_rec2 = dec(envelope("record", ROOT, {1: 1, 2: GROUP, 3: ROOT.hash, 4: 2, 5: sha(b"prev"), 10: 6000})[0])
    msgs = []
    for name, m in [
        ("keys with one statement", {0: 7, 2: [dec(envelope("keys", LAPTOP, {1: 1, 2: GROUP, 3: LAPTOP.hash, 4: 1, 10: [XWING, fake("k", 1216)]})[0])]}),
        ("command", {0: 9, 2: good_cmd}),
        ("nonce from a guarded lock", {0: 21, 2: fake("nonce", 16)}),
        ("nonce asked for", {0: 21}),
        ("beacon", {0: 22, 2: good_beacon}),
        ("reseal", {0: 23, 2: fake("copy", 16), 3: 4}),
        ("keys empty", {0: 7, 2: []}),
        ("command without its envelope", {0: 9}),
        ("nonce of 8 bytes", {0: 21, 2: bytes(8)}),
        ("beacon not an envelope", {0: 22, 2: b"x"}),
        ("reseal at epoch 0", {0: 23, 2: fake("copy", 16), 3: 0}),
        ("reseal without its copy", {0: 23, 3: 4}),
        ("roots with a head", {0: 24, 2: [good_rec]}),
        ("roots with the root's fork", {0: 24, 3: [good_rec, good_rec2]}),
        ("roots with a head and the fork", {0: 24, 2: [good_rec], 3: [good_rec, good_rec2]}),
        ("roots with a later field", {0: 24, 2: [good_rec], 300: 1}),
        ("roots fork of one record", {0: 24, 3: [good_rec]}),
        ("roots fork of three records", {0: 24, 3: [good_rec, good_rec2, good_rec]}),
        ("roots with 17 heads", {0: 24, 2: [good_rec] * 17}),
        ("roots head not an envelope", {0: 24, 2: [b"x"]}),
    ]:
        rule = check_map(MESSAGE_TYPES4[m[0]], m)
        f = frame(m)
        msgs.append({"name": name, "t": m[0], "verdict": rule or "take", "message": enc(m).hex(), "frame": f.hex()})
    out["messages"] = msgs
    return out


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    write_unicode(outdir)
    rt, rr, rl = record_vectors()
    st, sr = statement_vectors()
    ct, cr = command_vectors()
    gt, gr, gs, gq = grant_vectors(bytes.fromhex(rt[0]["envelope"]))
    kt, kr = credential_vectors()
    mv, mb, digest, mf = message_vectors(rt)
    files = {
        "profile.json": {"vectors": profile_vectors()},
        "keys.json": keys_table(),
        "records.json": {"label": LABELS["record"], "take": rt, "refuse": rr, "lists": rl},
        "statements.json": {"label": LABELS["keys"], "take": st, "refuse": sr},
        "commands.json": {"label": LABELS["command"], "take": ct, "refuse": cr},
        "grants.json": {"label": LABELS["grant"], "group": GROUP.hex(), "take": gt, "refuse": gr, "copy_senders": gs, "sequences": gq},
        "credentials.json": {"label": LABELS["credential"], "take": kt, "refuse": kr,
                             "recovery": RECOVERY.pub.hex(), "recovery2": RECOVERY2.pub.hex()},
        "frames.json": {"grid": "64, 256, 1024, 4096, 16384, then multiples of 16384",
                        "limits": {"member": 7 << 20, "pairing": 1 << 20, "leaf": 16 << 10,
                                   "welcome": 7 << 20,
                                   "welcome_note": "message 67 is read with the member limit, only "
                                                   "after the code is confirmed; every other pairing "
                                                   "message, and any before the confirm, with the "
                                                   "pairing limit"},
                        "take": mv, "refuse": mb, "refuse_fields": mf,
                        "set_digest_of_records_take": digest},
        "copy.json": copy_vector(),
        "container.json": container_vector(),
    }
    wt, wr, wm = wave3_vectors(rt)
    it, ir = invitation_vectors()
    cdt, cdr = card_vectors()
    files["messages3.json"] = {
        "tables": {name: [{"n": n, "rule": r, "type": t, "needed": nd} for n, r, t, nd in rows]
                   for name, rows in TABLES.items() if name not in TABLES4},
        "types": {str(t): name for t, name in MESSAGE_TYPES.items()},
        "take": wt, "refuse": wr, "maps": wm,
        "invitations": {"prefix": "cbb://join#", "take": it, "refuse": ir},
        "cards": {"label": LABELS["card"], "take": cdt, "refuse": cdr},
        "codes": code_vectors(),
    }
    files["wave4.json"] = wave4_vectors()
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

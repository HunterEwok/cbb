// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The native module's byte helpers (src/main/cpp/der.cpp) on the host:
//   c++ -std=c++17 -I src/main/cpp src/main/cpp/der.cpp src/test/cpp/der_test.cpp -o der_test && ./der_test

#include "der.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

int failures = 0;

void expect(bool ok, const char *what)
{
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

std::vector<uint8_t> bytes(std::initializer_list<int> b)
{
    std::vector<uint8_t> out;
    for (const int x : b)
        out.push_back(uint8_t(x));
    return out;
}

void signatures()
{
    // r with its high bit set takes a zero byte; s with leading zeros
    // drops them.
    uint8_t raw[64];
    std::memset(raw, 0x11, sizeof(raw));
    raw[0] = 0x80;
    raw[32] = 0x00;
    raw[33] = 0x00;
    raw[34] = 0x7f;
    const std::vector<uint8_t> der = keys::derSignature(raw);
    expect(der.size() == 2 + 2 + 33 + 2 + 30, "the DER length");
    expect(der[0] == 0x30 && der[1] == der.size() - 2, "the SEQUENCE");
    expect(der[2] == 0x02 && der[3] == 33 && der[4] == 0x00 && der[5] == 0x80, "r, padded");
    expect(der[37] == 0x02 && der[38] == 30 && der[39] == 0x7f, "s, without its zeros");

    // An integer of zeros keeps one byte.
    std::memset(raw, 0, sizeof(raw));
    raw[63] = 1;
    const std::vector<uint8_t> small = keys::derSignature(raw);
    expect(small == bytes({0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}), "zero r and one s");
}

void points()
{
    // The SubjectPublicKeyInfo header of a P-256 key, then its point.
    std::vector<uint8_t> spki = bytes({0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
                                       0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00});
    std::vector<uint8_t> point(65, 0x22);
    point[0] = 0x04;
    spki.insert(spki.end(), point.begin(), point.end());
    expect(keys::pointOf(spki.data(), spki.size()) == point, "the point of an SPKI");
    expect(keys::pointOf(point.data(), point.size()) == point, "a bare point");
    spki[spki.size() - 66] = 0x01;
    expect(keys::pointOf(spki.data(), spki.size()).empty(), "a BIT STRING with unused bits");
    expect(keys::pointOf(point.data(), 64).empty(), "a short point");
}

} // namespace

int main()
{
    signatures();
    points();
    if (failures)
        return 1;
    std::puts("ok");
    return 0;
}

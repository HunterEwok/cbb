// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "der.h"

namespace keys {

std::vector<uint8_t> pointOf(const uint8_t *spki, size_t len)
{
    // A P-256 SubjectPublicKeyInfo ends with the BIT STRING of the point:
    // 03 42 00 04 X Y, 65 bytes of point after the unused-bits byte.
    if (len >= 65 + 3 && spki[len - 65] == 0x04 && spki[len - 66] == 0x00 && spki[len - 67] == 0x42 && spki[len - 68] == 0x03)
        return std::vector<uint8_t>(spki + len - 65, spki + len);
    // A bare point, as some versions export it.
    if (len == 65 && spki[0] == 0x04)
        return std::vector<uint8_t>(spki, spki + len);
    return {};
}

std::vector<uint8_t> derSignature(const uint8_t *raw)
{
    auto integer = [](const uint8_t *v) {
        size_t i = 0;
        while (i < 31 && v[i] == 0)
            ++i;
        std::vector<uint8_t> out{0x02};
        const bool pad = v[i] & 0x80;
        out.push_back(uint8_t(32 - i + (pad ? 1 : 0)));
        if (pad)
            out.push_back(0);
        out.insert(out.end(), v + i, v + 32);
        return out;
    };
    const std::vector<uint8_t> r = integer(raw);
    const std::vector<uint8_t> s = integer(raw + 32);
    std::vector<uint8_t> out{0x30, uint8_t(r.size() + s.size())};
    out.insert(out.end(), r.begin(), r.end());
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

} // namespace keys

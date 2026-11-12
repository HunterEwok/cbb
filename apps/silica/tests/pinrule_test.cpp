// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The new admin PIN's rule (src/pinrule.h), run on the computer:
//   c++ -std=c++17 -Wall -Wextra -Werror apps/silica/tests/pinrule_test.cpp -o pinrule_test && ./pinrule_test

#include "../src/pinrule.h"

#include <cstdio>
#include <string>

namespace {

int failures = 0;

void expect(const std::string &pin, PinRule::Verdict want)
{
    const PinRule::Verdict got = PinRule::check(pin);
    if (got != want) {
        std::printf("FAIL %s: got %d, want %d\n", pin.c_str(), int(got), int(want));
        ++failures;
    }
}

} // namespace

int main()
{
    using V = PinRule::Verdict;
    // Shorter than six digits, however random.
    for (const char *p : {"", "7", "1234", "8402", "93715"})
        expect(p, V::TooShort);
    expect(std::string(PinRule::maxDigits + 1, '5') + "1", V::TooLong);
    // Digits only: a letter, a space, a non-ASCII digit.
    for (const char *p : {"84a935", "849 351", "8493512x", "\xd9\xa1\xd9\xa2\xd9\xa3\xd9\xa4\xd9\xa5\xd9\xa6"})
        expect(p, V::NotDigits);
    // Repeats, runs, short patterns, doubled and mirrored runs.
    for (const char *p : {"000000", "111111", "999999", "1111111", "123456", "654321", "234567", "890123",
                          "987654", "0123456789", "121212", "123123", "112112", "456456", "12341234",
                          "112233", "998877", "113355", "123321", "321123", "12344321"})
        expect(p, V::TooSimple);
    // Common choices from the keypad and the calendar.
    for (const char *p : {"147258", "159753", "789456", "102030", "696969", "246810", "198585", "200505"})
        expect(p, V::TooSimple);
    // PINs that pass.
    for (const char *p : {"849351", "502718", "730946", "0482917", "38461027", "198573", "200519"})
        expect(p, V::Ok);
    if (failures == 0)
        std::printf("ok\n");
    return failures == 0 ? 0 : 1;
}

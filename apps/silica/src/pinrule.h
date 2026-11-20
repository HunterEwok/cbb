// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#pragma once

// The rule for a new admin PIN on Aurora (docs/apps.md, "The admin PIN on
// Aurora"): at least six digits, digits only, and none that is easy to
// guess (repeats, runs, short patterns, two simple pieces, palindromes,
// counting pairs, dates and a list of common ones), so that the seven tries the phone's secure element allows are
// spent on a PIN that is hard to hit. A PIN chosen before this rule still
// works; the rule applies when a PIN is set or changed. Plain C++ without
// Qt, so that tests/pinrule_test.cpp runs it on any computer.

#include <algorithm>
#include <cstddef>
#include <string>

namespace PinRule {

const std::size_t minDigits = 6;
const std::size_t maxDigits = 64;

enum class Verdict {
    Ok,
    TooShort,  // fewer than minDigits
    TooLong,   // more than maxDigits
    NotDigits, // anything other than 0-9
    TooSimple, // a repeat, a run, a short pattern or a common PIN
};

namespace detail {

// Whether the digits step by the same amount throughout (wrapping 9 to 0),
// as 123456, 987654, 890123 and 135791.
inline bool run(const std::string &pin)
{
    for (int step = 1; step <= 9; ++step) {
        bool all = true;
        for (std::size_t i = 1; i < pin.size() && all; ++i)
            all = (pin[i] - '0') == ((pin[i - 1] - '0') + step) % 10;
        if (all)
            return true;
    }
    return false;
}

// Whether the PIN repeats a block of up to three digits, as 111111,
// 121212 and 123123, or a block of half its length, as 112112.
inline bool periodic(const std::string &pin)
{
    for (std::size_t p = 1; p <= std::max<std::size_t>(3, pin.size() / 2) && p < pin.size(); ++p) {
        if (pin.size() % p != 0)
            continue;
        bool all = true;
        for (std::size_t i = p; i < pin.size() && all; ++i)
            all = pin[i] == pin[i - p];
        if (all)
            return true;
    }
    return false;
}

// Whether each digit comes twice in a row, as 112233 and 998877.
inline bool doubled(const std::string &pin)
{
    if (pin.size() % 2 != 0)
        return false;
    std::string half;
    for (std::size_t i = 0; i < pin.size(); i += 2) {
        if (pin[i] != pin[i + 1])
            return false;
        half += pin[i];
    }
    return run(half) || periodic(half);
}

// Whether the PIN reads the same backwards and its first half is a run,
// as 123321 and 321123.
inline bool mirrored(const std::string &pin)
{
    if (!std::equal(pin.begin(), pin.begin() + long(pin.size() / 2), pin.rbegin()))
        return false;
    return run(pin.substr(0, (pin.size() + 1) / 2));
}

// Whether one digit fills nearly all of the PIN: five or more of six or
// seven, all but two of a longer one, as 000001, 111112 and 900000.
inline bool mostlyOne(const std::string &pin)
{
    std::size_t most = 0;
    for (char d = '0'; d <= '9'; ++d)
        most = std::max<std::size_t>(most, std::size_t(std::count(pin.begin(), pin.end(), d)));
    return pin.size() <= 7 ? most >= 5 : most + 2 >= pin.size();
}

// Whether a piece is simple: three or more digits in a run or all equal,
// or two equal digits.
inline bool simplePiece(const std::string &p)
{
    if (p.size() == 2)
        return p[0] == p[1];
    return p.size() >= 3 && (run(p) || p.find_first_not_of(p[0]) == std::string::npos);
}

// Whether the PIN is two simple pieces, as 111222, 777888, 123400,
// 112345 and 123454 (a run of five and one digit more), or a run with one
// digit before or after it.
inline bool twoPieces(const std::string &pin)
{
    if (run(pin.substr(1)) || run(pin.substr(0, pin.size() - 1)))
        return true;
    for (std::size_t i = 2; i + 2 <= pin.size(); ++i)
        if (simplePiece(pin.substr(0, i)) && simplePiece(pin.substr(i)))
            return true;
    return false;
}

// Whether the PIN reads the same backwards, as 998899 and 135531.
inline bool palindrome(const std::string &pin)
{
    return std::equal(pin.begin(), pin.begin() + long(pin.size() / 2), pin.rbegin());
}

// Whether the PIN is two-digit numbers counting by the same step, as
// 131415, 101112 and 302010.
inline bool countingPairs(const std::string &pin)
{
    if (pin.size() % 2 != 0 || pin.size() < 6)
        return false;
    auto pair = [&pin](std::size_t i) { return (pin[i] - '0') * 10 + (pin[i + 1] - '0'); };
    const int step = pair(2) - pair(0);
    for (std::size_t i = 4; i < pin.size(); i += 2)
        if (pair(i) - pair(i - 2) != step)
            return false;
    return true;
}

inline int number(const std::string &s, std::size_t at, std::size_t n)
{
    int v = 0;
    for (std::size_t i = at; i < at + n; ++i)
        v = v * 10 + (s[i] - '0');
    return v;
}

inline bool validDate(int day, int month)
{
    static const int days[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1];
}

// Whether the PIN is a date: DDMMYY, MMDDYY or YYMMDD for six digits, and
// DDMMYYYY, MMDDYYYY or YYYYMMDD with a year from 1900 to 2099 for eight.
inline bool date(const std::string &pin)
{
    if (pin.size() == 6)
        return validDate(number(pin, 0, 2), number(pin, 2, 2)) || validDate(number(pin, 2, 2), number(pin, 0, 2))
            || validDate(number(pin, 4, 2), number(pin, 2, 2));
    if (pin.size() == 8) {
        auto year = [](int y) { return y >= 1900 && y <= 2099; };
        return (year(number(pin, 4, 4)) && (validDate(number(pin, 0, 2), number(pin, 2, 2)) || validDate(number(pin, 2, 2), number(pin, 0, 2))))
            || (year(number(pin, 0, 4)) && validDate(number(pin, 6, 2), number(pin, 4, 2)));
    }
    return false;
}

// The six-digit PINs people choose most that the rules above do not catch:
// keypad lines and shapes, years and words on the keypad, from published
// PIN-frequency lists.
inline bool common(const std::string &pin)
{
    static const char *const list[] = {
        "102030", "010203", "112358", "131313", "147258", "147852", "147369", "159357", "159753",
        "159951", "741852", "741963", "753951", "789456", "789123", "852456", "951753", "963852",
        "258456", "456123", "123654", "654123", "321654", "147147", "520520", "520131", "131420",
        "696969", "007007", "000007", "100200", "110110", "121314", "123789", "142536", "198700",
        "199000", "200000", "200100", "201020", "123000", "100000", "111000", "123412", "123450",
        "123457", "123458", "123459", "012345", "543210", "098765", "564738", "102938", "080808",
        "202020", "232323", "252525", "282828", "292929", "343434", "454545", "505050", "565656",
        "676767", "787878", "898989", "909090", "112211", "221122", "110011", "001100", "246810",
        "135790", "135791", "246802", "013579", "024680", "142857", "314159", "271828",
    };
    for (const char *p : list)
        if (pin == p)
            return true;
    return false;
}

} // namespace detail

// The verdict on a PIN the user chooses.
inline Verdict check(const std::string &pin)
{
    if (!std::all_of(pin.begin(), pin.end(), [](char c) { return c >= '0' && c <= '9'; }))
        return Verdict::NotDigits;
    if (pin.size() < minDigits)
        return Verdict::TooShort;
    if (pin.size() > maxDigits)
        return Verdict::TooLong;
    if (detail::run(pin) || detail::periodic(pin) || detail::doubled(pin) || detail::mirrored(pin) || detail::common(pin)
        || detail::mostlyOne(pin) || detail::twoPieces(pin) || detail::palindrome(pin) || detail::countingPairs(pin)
        || detail::date(pin))
        return Verdict::TooSimple;
    // A year from 1900 to 2099 twice, or a year and its two last digits
    // again, as 19851985's start or 200520: the first four digits a year
    // and the rest repeating its end.
    if (pin.size() == 6) {
        const std::string year = pin.substr(0, 4);
        const bool isYear = (year.compare(0, 2, "19") == 0 || year.compare(0, 2, "20") == 0);
        if (isYear && pin.substr(4) == year.substr(2))
            return Verdict::TooSimple;
    }
    return Verdict::Ok;
}

} // namespace PinRule

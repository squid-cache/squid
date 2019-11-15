/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "charset.h"
#include "sbuf/SBuf.h"

SBuf
Latin1ToUtf8(const char *in)
{
    SBuf result;

    if (!in)
        return result;

    for (; *in; in++) {
        const auto ch = static_cast<unsigned char>(*in);

        if (ch < 0x80) {
            result.append(ch);
        } else {
            result.append(static_cast<char>((ch >> 6) | 0xc0));
            result.append(static_cast<char>((ch & 0x3f) | 0x80));
        }
    }
    return result;
}

SBuf
Cp1251ToUtf8(const char *in)
{
    static const unsigned char firstByteMark[] = { 0x00, 0x00, 0xC0, 0xE0 };
    static const unsigned unicodevalues[] =
      { 0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
        0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
        0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
        0xFFFD, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
        0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
        0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
        0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
        0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457 };
    SBuf result;

    if (!in)
        return result;

    for (; *in; in++) {
        const auto ch = static_cast<unsigned char>(*in);
        unsigned u = 0;
        size_t bytesToWrite = 0;
        char sequence[4] = {0, 0, 0, 0};

        if (ch < 0x80)
            u = ch;
        else if (ch >= 0xC0 && ch <= 0xFF) // 0x0410..0x044F
            u = 0x0350 + ch;
        else
            u = unicodevalues[ch - 0x80];

        if (u < 0x80)
            bytesToWrite = 1;
        else if (u < 0x800)
            bytesToWrite = 2;
        else
            bytesToWrite = 3;

        switch (bytesToWrite) {
        case 3: sequence[2] = static_cast<char>(u & 0x3f) | 0x80; u >>= 6;               // no break
        case 2: sequence[1] = static_cast<char>(u & 0x3f) | 0x80; u >>= 6;               // no break
        case 1: sequence[0] = static_cast<char>(u)        | firstByteMark[bytesToWrite]; // no break
        }
        result.append(sequence, bytesToWrite);
    }
    return result;
}


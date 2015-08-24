/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SBufAlgos.h"

static std::size_t
lowSBufHash (const SBuf & sbuf, bool caseInsensitive = false) noexcept
{
    //ripped and adapted from hash_string
    const char *s = sbuf.rawContent();
    size_t rv = 0;
    SBuf::size_type len=sbuf.length();
    while (len != 0) {
        rv ^= 271 * (caseInsensitive? xtolower(*s) : *s);
        ++s;
        --len;
    }
    return rv ^ (sbuf.length() * 271);
}

std::size_t
std::hash<SBuf>::operator() (const SBuf & sbuf) const noexcept
{
    return lowSBufHash(sbuf);
}

std::size_t
CaseInsensitiveSBufHash::operator() (const SBuf & sbuf) const noexcept
{
    return lowSBufHash(sbuf, true);
}


/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "ConfigParser.h"
#include "ip/NfMarkConfig.h"
#include "parser/ToInteger.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#include <limits>

Ip::NfMarkConfig
Ip::NfMarkConfig::Parse(const SBuf &token)
{
    Parser::Tokenizer tokenizer(token);

    static const CharacterSet Slash("/", "/");
    SBuf rawMark;
    SBuf rawMask;
    nfmark_t mark = 0;
    nfmark_t mask = 0xffffffff;
    if(tokenizer.token(rawMark, Slash))
        mask = Parser::UnsignedDecimalInteger<nfmark_t>("NfMarkConfig", tokenizer.remaining());
    else
        rawMark = tokenizer.remaining();
    tokenizer.reset(SBuf());

    mark = Parser::UnsignedDecimalInteger<nfmark_t>("NfMarkConfig",  rawMark);
    return Ip::NfMarkConfig(mark, mask);
}

nfmark_t
Ip::NfMarkConfig::applyToMark(nfmark_t m) const
{
    return (m & ~mask) | mark;
}

std::ostream &
Ip::operator <<(std::ostream &os, const NfMarkConfig c)
{
    os << asHex(c.mark);

    if (c.mask != 0xffffffff)
        os << '/' << asHex(c.mask);

    return os;
}


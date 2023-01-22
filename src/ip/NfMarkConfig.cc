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
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#include <limits>

static nfmark_t
getNfmark(Parser::Tokenizer &tokenizer, const SBuf &token)
{
    int64_t number;
    if (!tokenizer.int64(number, 0, false))
        throw TexcHere(ToSBuf("NfMarkConfig: invalid value '", tokenizer.buf(), "' in '", token, "'"));

    if (number > std::numeric_limits<nfmark_t>::max())
        throw TexcHere(ToSBuf("NfMarkConfig: number, ", number, "in '", token, "' is too big"));

    return static_cast<nfmark_t>(number);
}

Ip::NfMarkConfig
Ip::NfMarkConfig::Parse(const SBuf &token)
{
    Parser::Tokenizer tokenizer(token);

    const nfmark_t mark = getNfmark(tokenizer, token);
    const nfmark_t mask = tokenizer.skip('/') ? getNfmark(tokenizer, token) : 0xffffffff;

    if (!tokenizer.atEnd())
        throw TexcHere(ToSBuf("NfMarkConfig: trailing garbage in '", token, "'"));

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


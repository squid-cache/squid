/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "ConnMarkConfig.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#include <limits>

static nfmark_t
getNfmark(Parser::Tokenizer &tokenizer, const SBuf &token)
{
    int64_t number;
    if (!tokenizer.int64(number, 0, false))
        throw TexcHere(ToSBuf("ConnMarkConfig: invalid value '", tokenizer.buf(), "' in '", token, "'"));

    if (number > std::numeric_limits<nfmark_t>::max())
        throw TexcHere(ToSBuf("ConnMarkConfig: number, ", number, "in '", token, "' is too big"));

    return static_cast<nfmark_t>(number);
}

ConnMarkConfig
ConnMarkConfig::Parse(const SBuf &token)
{
    Parser::Tokenizer tokenizer(token);

    const nfmark_t mark = getNfmark(tokenizer, token);
    const nfmark_t mask = tokenizer.skip('/') ? getNfmark(tokenizer, token) : 0xffffffff;

    if (!tokenizer.atEnd())
        throw TexcHere(ToSBuf("ConnMarkConfig: trailing garbage in '", token, "'"));

    return {mark, mask};
}

std::ostream &
operator <<(std::ostream &os, const ConnMarkConfig c)
{
    os << asHex(c.nfmark);

    if (c.nfmask != 0xffffffff)
        os << '/' << asHex(c.nfmask);

    return os;
}

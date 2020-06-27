/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/ResponseParser.h"
#include "parser/Tokenizer.h"

const SBuf Adaptation::Icap::ResponseParser::Icap1magic("ICAP/1.0");

int
Adaptation::Icap::ResponseParser::parseResponseFirstLine()
{
    Tokenizer tok(buf_);

    const CharacterSet &WspDelim = DelimiterCharacters();

    if (msgProtocol_.protocol != AnyP::PROTO_NONE) {
        debugs(74, 6, "continue incremental parse for " << msgProtocol_);
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        // we already found the magic, but not the full line. keep going.
        return parseResponseStatusAndReason(tok, WspDelim);

    } else if (tok.skip(Icap1magic) && tok.skipOne(WspDelim)) {
        debugs(74, 6, "found prefix magic " << Icap1magic);
        msgProtocol_.protocol = AnyP::PROTO_ICAP;
        msgProtocol_.major = 1;
        msgProtocol_.minor = 0;

        // ICAP/1.0 Response status-line parse
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        buf_ = tok.remaining(); // resume checkpoint
        return parseResponseStatusAndReason(tok, WspDelim);

    } else if (buf_.length() < Icap1magic.length() && Icap1magic.startsWith(buf_)) {
        debugs(74, 7, Raw("valid ICAP/1 prefix", buf_.rawContent(), buf_.length()));
        return 0;
    }

    // else, protocol error
    assert(tok.atEnd());
    return -1;
}

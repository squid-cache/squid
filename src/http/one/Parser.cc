/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/Parser.h"
#include "parser/Tokenizer.h"

/// RFC 7230 section 2.6 - 7 magic octets
const SBuf Http::One::Parser::Http1magic("HTTP/1.");

void
Http::One::Parser::clear()
{
    parsingStage_ = HTTP_PARSE_NONE;
    buf_ = NULL;
    msgProtocol_ = AnyP::ProtocolVersion();
    mimeHeaderBlock_.clear();
}

// arbitrary maximum-length for headers which can be found by Http1Parser::getHeaderField()
#define GET_HDR_SZ  1024

// BUG: returns only the first header line with given name,
//      ignores multi-line headers and obs-fold headers
char *
Http::One::Parser::getHeaderField(const char *name)
{
    if (!headerBlockSize() || !name)
        return NULL;

    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const int namelen = strlen(name);

    debugs(25, 5, "looking for " << name);

    // while we can find more LF in the SBuf
    static CharacterSet iso8859Line = CharacterSet("non-LF",'\0','\n'-1) + CharacterSet(NULL, '\n'+1, (unsigned char)0xFF);
    ::Parser::Tokenizer tok(mimeHeaderBlock_);
    SBuf p;
    static const SBuf crlf("\r\n");

    while (tok.prefix(p, iso8859Line)) {
        tok.skipOne(CharacterSet::LF); // move tokenizer past the LF

        // header lines must start with the name (case insensitive)
        if (p.substr(0, namelen).caseCmp(name, namelen))
            continue;

        // then a COLON
        if (p[namelen] != ':')
            continue;

        // drop any trailing *CR sequence
        p.trim(crlf, false, true);

        debugs(25, 5, "checking " << p);
        p.consume(namelen + 1);

        // TODO: optimize SBuf::trim to take CharacterSet directly
        ::Parser::Tokenizer t(p);
        t.skipAll(CharacterSet::WSP);
        p = t.remaining();

        // prevent buffer overrun on char header[];
        p.chop(0, sizeof(header)-1);

        // return the header field-value
        xstrncpy(header, p.rawContent(), p.length()+1);
        debugs(25, 5, "returning " << header);
        return header;
    }

    return NULL;
}


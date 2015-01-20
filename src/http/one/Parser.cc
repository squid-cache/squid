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
#include "mime_header.h"
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

bool
Http::One::Parser::findMimeBlock(const char *which, size_t limit)
{
    if (msgProtocol_.major == 1) {
        /* NOTE: HTTP/0.9 messages do not have a mime header block.
         *       So the rest of the code will need to deal with '0'-byte headers
         *       (ie, none, so don't try parsing em)
         */
        int64_t mimeHeaderBytes = 0;
        // XXX: c_str() reallocates. performance regression.
        if ((mimeHeaderBytes = headersEnd(buf_.c_str(), buf_.length())) == 0) {
            if (buf_.length()+firstLineSize() >= limit) {
                debugs(33, 5, "Too large " << which);
                parseStatusCode = Http::scHeaderTooLarge;
                parsingStage_ = HTTP_PARSE_DONE;
            } else
                debugs(33, 5, "Incomplete " << which << ", waiting for end of headers");
            return false;
        }
        mimeHeaderBlock_ = buf_.consume(mimeHeaderBytes);
        debugs(74, 5, "mime header (0-" << mimeHeaderBytes << ") {" << mimeHeaderBlock_ << "}");

    } else
        debugs(33, 3, "Missing HTTP/1.x identifier");

    // NP: we do not do any further stages here yet so go straight to DONE
    parsingStage_ = HTTP_PARSE_DONE;

    // Squid could handle these headers, but admin does not want to
    if (messageHeaderSize() >= limit) {
        debugs(33, 5, "Too large " << which);
        parseStatusCode = Http::scHeaderTooLarge;
        return false;
    }

    return true;
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


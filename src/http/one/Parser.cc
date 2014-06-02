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
#define GET_HDR_SZ	1024

// BUG: returns only the first header line with given name,
//      ignores multi-line headers and obs-fold headers
char *
Http::One::Parser::getHeaderField(const char *name)
{
    if (!headerBlockSize() || !name)
        return NULL;

    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const int namelen = name ? strlen(name) : 0;

    debugs(25, 5, "looking for '" << name << "'");

    ::Parser::Tokenizer tok(mimeHeaderBlock_);
    SBuf p;
    const SBuf crlf("\r\n");

    // while we can find more LF in the SBuf
    while (tok.prefix(p, CharacterSet::LF)) {
        tok.skip(CharacterSet::LF); // move tokenizer past the LF

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
        t.skip(CharacterSet::WSP);
        p = t.remaining();

        // prevent buffer overrun on char header[];
        p.chop(0, sizeof(header)-1);

        // return the header field-value
        xstrncpy(header, p.rawContent(), p.length());
        debugs(25, 5, "returning: " << header);
        return header;
    }

    return NULL;
}

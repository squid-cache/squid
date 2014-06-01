#include "squid.h"
#include "Debug.h"
#include "http/one/Parser.h"

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

char *
Http::One::Parser::getHeaderField(const char *name)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    const int namelen = name ? strlen(name) : 0;

    if (!headerBlockSize() || !name)
        return NULL;

    debugs(25, 5, "looking for '" << name << "'");

    for (p = mimeHeader().c_str(); *p; p += strcspn(p, "\n\r")) {
        if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
            return NULL;

        while (xisspace(*p))
            ++p;

        if (strncasecmp(p, name, namelen))
            continue;

        if (!xisspace(p[namelen]) && p[namelen] != ':')
            continue;

        int l = strcspn(p, "\n\r") + 1;

        if (l > GET_HDR_SZ)
            l = GET_HDR_SZ;

        xstrncpy(header, p, l);

        debugs(25, 5, "checking '" << header << "'");

        q = header;

        q += namelen;

        if (*q == ':') {
            ++q;
            got = 1;
        }

        while (xisspace(*q)) {
            ++q;
            got = 1;
        }

        if (got) {
            debugs(25, 5, "returning '" << q << "'");
            return q;
        }
    }

    return NULL;
}

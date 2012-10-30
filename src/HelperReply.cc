#include "squid.h"
#include "HelperReply.h"
#include "helper.h"

HelperReply::HelperReply(const char *buf, size_t len) :
        result(HelperReply::Unknown),
        whichServer(NULL)
{
    // check we have something to parse
    if (!buf || len < 1) {
        // for now ensure that legacy handlers are not presented with NULL strings.
        other_.init(1,1);
        other_.terminate();
        return;
    }

    const char *p = buf;

    // optimization: do not consider parsing result code if the response is short.
    // URL-rewriter may return relative URLs or empty response for a large portion
    // of its replies.
    if (len >= 2) {
        // some helper formats (digest auth, URL-rewriter) just send a data string
        // we must also check for the ' ' character after the response token (if anything)
        if (!strncmp(p,"OK",2) && (len == 2 || p[2] == ' ')) {
            result = HelperReply::Okay;
            p+=2;
        } else if (!strncmp(p,"ERR",3) && (len == 3 || p[3] == ' ')) {
            result = HelperReply::Error;
            p+=3;
        } else if (!strncmp(p,"BH",2) && (len == 2 || p[2] == ' ')) {
            result = HelperReply::BrokenHelper;
            p+=2;
        } else if (!strncmp(p,"TT ",3)) {
            // NTLM challenge token
            result = HelperReply::TT;
            p+=3;
        } else if (!strncmp(p,"AF ",3)) {
            // NTLM OK response
            result = HelperReply::AF;
            p+=3;
        } else if (!strncmp(p,"NA ",3)) {
            // NTLM fail-closed ERR response
            result = HelperReply::NA;
            p+=3;
        }

        for (; xisspace(*p); ++p); // skip whitespace
    }

    const mb_size_t blobSize = (buf+len-p);
    other_.init(blobSize+1, blobSize+1);
    other_.append(p, blobSize); // remainders of the line.

    // NULL-terminate so the helper callback handlers do not buffer-overrun
    other_.terminate();
}

std::ostream &
operator <<(std::ostream &os, const HelperReply &r)
{
    os << "{result=";
    switch (r.result) {
    case HelperReply::Okay:
        os << "OK";
        break;
    case HelperReply::Error:
        os << "ERR";
        break;
    case HelperReply::BrokenHelper:
        os << "BH";
        break;
    case HelperReply::TT:
        os << "TT";
        break;
    case HelperReply::AF:
        os << "AF";
        break;
    case HelperReply::NA:
        os << "NA";
        break;
    case HelperReply::Unknown:
        os << "Unknown";
        break;
    }

    if (r.other().hasContent())
        os << ", other: \"" << r.other().content() << '\"';

    os << '}';

    return os;
}

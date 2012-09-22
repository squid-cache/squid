/*
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Amos Jeffries
 */
#include "squid.h"
#include "HelperReply.h"
#include "helper.h"
#include "SquidString.h"

HelperReply::HelperReply(const char *buf, size_t len, bool urlQuoting) :
        result(HelperReply::Unknown),
        whichServer(NULL)
{
    // check we have something to parse
    if (!buf || len < 1)
        return;

    const char *p = buf;

    if (len >= 2) {
        // NOTE: only increment 'p' if a result code is found.
        // some helper formats (digest auth, URL-rewriter) just send a data string
        // we must also check for the ' ' character after the response token here
        if (!strncmp(p,"OK ",3)) {
            result = HelperReply::Okay;
            p+=2;
        } else if (!strncmp(p,"ERR ",4)) {
            result = HelperReply::Error;
            p+=3;
        } else if (!strncmp(p,"BH ",3)) {
            result = HelperReply::BrokenHelper;
            p+=2;
        } else if (!strncmp(p,"TT ",3)) {
            // NTLM challenge token
            result = HelperReply::TT;
            p+=2;
        } else if (!strncmp(p,"AF ",3)) {
            // NTLM OK response
            result = HelperReply::AF;
            p+=2;
        } else if (!strncmp(p,"NA ",3)) {
            // NTLM fail-closed ERR response
            result = HelperReply::NA;
            p+=2;
        }

        for(;xisspace(*p);p++); // skip whitespace
    }

    const mb_size_t blobSize = (buf+len-p);
    other_.init(blobSize, blobSize+1);
    other_.append(p, blobSize); // remainders of the line.

    // NULL-terminate so the helper callback handlers do not buffer-overrun
    other_.terminate();

    bool found;
    do {
        found = false;
        found |= parseKeyValue("tag=", 4, tag);
        found |= parseKeyValue("user=", 5, user);
        found |= parseKeyValue("password=", 9, password);
        found |= parseKeyValue("message=", 8, message);
        found |= parseKeyValue("log=", 8, log);
    } while(found);

    if (urlQuoting) {
        // unescape the reply values
        if (tag.hasContent())
            rfc1738_unescape(tag.buf());
        if (user.hasContent())
            rfc1738_unescape(user.buf());
        if (password.hasContent())
            rfc1738_unescape(password.buf());
        if (message.hasContent())
            rfc1738_unescape(message.buf());
        if (log.hasContent())
            rfc1738_unescape(log.buf());
    }
}

bool
HelperReply::parseKeyValue(const char *key, size_t key_len, MemBuf &value)
{
    if (other().contentSize() > static_cast<mb_size_t>(key_len) && memcmp(other().content(), key, key_len) == 0) {
        // parse the value out of the string. may be double-quoted
        char *tmp = modifiableOther().content() + key_len;
        const char *token = strwordtok(NULL, &tmp);
        value.reset();
        value.append(token,strlen(token));
        const mb_size_t keyPairSize = tmp - other().content();
        modifiableOther().consume(keyPairSize);
        modifiableOther().consumeWhitespace();
        return true;
    }
    return false;
}

std::ostream &
operator <<(std::ostream &os, const HelperReply &r)
{
    os << "{result=";
    switch(r.result)
    {
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

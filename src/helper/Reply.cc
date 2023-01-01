/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#include "squid.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "helper.h"
#include "helper/Reply.h"
#include "rfc1738.h"
#include "SquidString.h"

Helper::Reply::Reply() :
    result(Helper::Unknown)
{
}

bool
Helper::Reply::accumulate(const char *buf, size_t len)
{
    if (other_.isNull())
        other_.init(4*1024, 1*1024*1024);

    if (other_.potentialSpaceSize() < static_cast<mb_size_t>(len))
        return false; // no space left

    other_.append(buf, len);
    return true;
}

void
Helper::Reply::finalize()
{
    debugs(84, 3, "Parsing helper buffer");
    // check we have something to parse
    if (!other_.hasContent()) {
        // empty line response was the old URL-rewriter interface ERR response.
        result = Helper::Error;
        // for now ensure that legacy handlers are not presented with NULL strings.
        debugs(84, 3, "Zero length reply");
        return;
    }

    char *p = other_.content();
    size_t len = other_.contentSize();
    bool sawNA = false;

    // optimization: do not consider parsing result code if the response is short.
    // URL-rewriter may return relative URLs or empty response for a large portion
    // of its replies.
    if (len >= 2) {
        debugs(84, 3, "Buff length is larger than 2");
        // some helper formats (digest auth, URL-rewriter) just send a data string
        // we must also check for the ' ' character after the response token (if anything)
        if (!strncmp(p,"OK",2) && (len == 2 || p[2] == ' ')) {
            debugs(84, 3, "helper Result = OK");
            result = Helper::Okay;
            p+=2;
        } else if (!strncmp(p,"ERR",3) && (len == 3 || p[3] == ' ')) {
            debugs(84, 3, "helper Result = ERR");
            result = Helper::Error;
            p+=3;
        } else if (!strncmp(p,"BH",2) && (len == 2 || p[2] == ' ')) {
            debugs(84, 3, "helper Result = BH");
            result = Helper::BrokenHelper;
            p+=2;
        } else if (!strncmp(p,"TT ",3)) {
            // NTLM challenge token
            result = Helper::TT;
            p+=3;
            // followed by an auth token
            char *w1 = strwordtok(NULL, &p);
            if (w1 != NULL) {
                const char *authToken = w1;
                notes.add("token",authToken);
            } else {
                // token field is mandatory on this response code
                result = Helper::BrokenHelper;
                notes.add("message","Missing 'token' data");
            }

        } else if (!strncmp(p,"AF ",3)) {
            // NTLM/Negotate OK response
            result = Helper::Okay;
            p+=3;
            // followed by:
            //  an optional auth token and user field
            // or, an optional username field
            char *w1 = strwordtok(NULL, &p);
            char *w2 = strwordtok(NULL, &p);
            if (w2 != NULL) {
                // Negotiate "token user"
                const char *authToken = w1;
                notes.add("token",authToken);

                const char *user = w2;
                notes.add("user",user);

            } else if (w1 != NULL) {
                // NTLM "user"
                const char *user = w1;
                notes.add("user",user);
            }
        } else if (!strncmp(p,"NA ",3)) {
            // NTLM fail-closed ERR response
            result = Helper::Error;
            p+=3;
            sawNA=true;
        }

        for (; xisspace(*p); ++p); // skip whitespace
    }

    other_.consume(p - other_.content());
    other_.consumeWhitespacePrefix();

    // Hack for backward-compatibility: Do not parse for kv-pairs on NA response
    if (!sawNA)
        parseResponseKeys();

    // Hack for backward-compatibility: BH and NA used to be a text message...
    if (other_.hasContent() && (sawNA || result == Helper::BrokenHelper)) {
        notes.add("message", other_.content());
        other_.clean();
    }
}

/// restrict key names to alphanumeric, hyphen, underscore characters
static bool
isKeyNameChar(char c)
{
    if (c >= 'a' && c <= 'z')
        return true;

    if (c >= 'A' && c <= 'Z')
        return true;

    if (c >= '0' && c <= '9')
        return true;

    if (c == '-' || c == '_')
        return true;

    // prevent other characters matching the key=value
    return false;
}

void
Helper::Reply::parseResponseKeys()
{
    // parse a "key=value" pair off the 'other()' buffer.
    while (other_.hasContent()) {
        char *p = other_.content();
        const char *key = p;
        while (*p && isKeyNameChar(*p)) ++p;
        if (*p != '=')
            return; // done. Not a key.

        // whitespace between key and value is prohibited.
        // workaround strwordtok() which skips whitespace prefix.
        if (xisspace(*(p+1)))
            return; // done. Not a key.

        *p = '\0';
        ++p;

        // the value may be a quoted string or a token
        const bool urlDecode = (*p != '"'); // check before moving p.
        char *v = strwordtok(NULL, &p);
        if (v != NULL && urlDecode && (p-v) > 2) // 1-octet %-escaped requires 3 bytes
            rfc1738_unescape(v);

        notes.add(key, v ? v : ""); // value can be empty, but must not be NULL

        other_.consume(p - other_.content());
        other_.consumeWhitespacePrefix();
    }
}

const MemBuf &
Helper::Reply::emptyBuf() const
{
    static MemBuf empty;
    if (empty.isNull())
        empty.init(1, 1);
    return empty;
}

std::ostream &
operator <<(std::ostream &os, const Helper::Reply &r)
{
    os << "{result=";
    switch (r.result) {
    case Helper::Okay:
        os << "OK";
        break;
    case Helper::Error:
        os << "ERR";
        break;
    case Helper::BrokenHelper:
        os << "BH";
        break;
    case Helper::TT:
        os << "TT";
        break;
    case Helper::TimedOut:
        os << "Timeout";
        break;
    case Helper::Unknown:
        os << "Unknown";
        break;
    }

    // dump the helper key=pair "notes" list
    if (!r.notes.empty()) {
        os << ", notes={";
        os << r.notes.toString("; ");
        os << "}";
    }

    MemBuf const &o = r.other();
    if (o.hasContent())
        os << ", other: \"" << o.content() << '\"';

    os << '}';

    return os;
}


/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_RFC3986_H
#define SQUID_INCLUDE_RFC3986_H

#include "src/base/CharacterSet.h"

// RFC 1738 URL-encoding character sets
namespace Rfc1738
{
extern const CharacterSet
Unsafe,  // RFC 1738 unsafe set
Reserved, // RFC 1738 Reserved set
Unescaped; // RFC 1738 Unsafe and RFC 5234 CTL
}

// RFC 3986 URL-encoding
namespace Rfc3986
{

extern const CharacterSet
GenDelims,// RFC 3986 gen-delims set
SubDelims,// RFC 3986 sub-delims set
Reserved, // RFC 3986 reserved characters set
Unreserved, // RFC 3986 unreserved characters set
Unescaped, // CTL and unsafe except for percent symbol
All;

// integer representation of hex numeric characters
extern int fromhex[256];

// hex representation of each UTF-8 character
extern const char * const tohex[256];

/** unescape a percent-encoded string
 *
 * API-compatible with std::string and SBuf
 */
template <class String>
String unescape(const String &s)
{
    typename String::size_type pos=s.find('%');
    if (pos == String::npos)
        return s;
    String rv;
    rv.reserve(s.length());
    const auto e=s.end();
    for (auto in = s.begin(); in != e; ++in) {
        if (*in != '%') { // normal case, copy and continue
            rv.push_back(*in);
            continue;
        }
        auto ti = in;
        ++ti;
        if (ti == e) { // String ends in %
            rv.push_back(*in);
            break;
        }
        if (*ti == '%') { //double '%' escaping
            rv.push_back(*in);
            ++in;
            continue;
        }
        const int v1 = fromhex[*ti];
        if (v1 < 0) { // decoding failed at first hextdigit
            rv.push_back(*in);
            continue;
        }
        ++ti;
        if (ti == e) { // String ends in '%[[:hexdigit:]]'
            rv.push_back(*in);
            continue;
        }
        const int v2 = fromhex[*ti];
        if (v2 < 0) { // decoding failed at second hextdigit
            rv.push_back(*in);
            continue;
        }
        const int x = v1 << 4 | v2;
        if (x > 0 && x <= 255) {
            rv.push_back(static_cast<char>(x));
            ++in;
            ++in;
            continue;
        }
        rv.push_back(*in);
    }
    return rv;
}

template <class String>
String escape(const String &s, const CharacterSet &escapeChars = Rfc1738::Unescaped)
{
    String rv;
    bool didEscape = false;
    rv.reserve(s.length()*2); //TODO: optimize arbitrary constant
    for (auto c : s) {
        if (escapeChars[c]) {
            rv.push_back('%');
            const char *hex=tohex[c];
            rv.push_back(hex[0]);
            rv.push_back(hex[1]);
            didEscape = true;
        } else {
            rv.push_back(c);
        }
    }
    if (didEscape)
        return rv;
    else
        return s;
}

} // namespace Rfc3986

#endif /* SQUID_INCLUDE_RFC3986_H */


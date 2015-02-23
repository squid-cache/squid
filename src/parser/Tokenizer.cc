/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 24    SBuf */

#include "squid.h"
#include "Debug.h"
#include "parser/Tokenizer.h"

#include <cerrno>
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#ifndef INT64_MIN
/* Native 64 bit system without strtoll() */
#if defined(LONG_MIN) && (SIZEOF_LONG == 8)
#define INT64_MIN LONG_MIN
#else
/* 32 bit system */
#define INT64_MIN       (-9223372036854775807LL-1LL)
#endif
#endif

#ifndef INT64_MAX
/* Native 64 bit system without strtoll() */
#if defined(LONG_MAX) && (SIZEOF_LONG == 8)
#define INT64_MAX LONG_MAX
#else
/* 32 bit system */
#define INT64_MAX       9223372036854775807LL
#endif
#endif

/// convenience method: consumes up to n bytes, counts, and returns them
SBuf
Parser::Tokenizer::consume(const SBuf::size_type n)
{
    // careful: n may be npos!
    debugs(24, 5, "consuming " << n << " bytes");
    const SBuf result = buf_.consume(n);
    parsed_ += result.length();
    return result;
}

/// convenience method: consume()s up to n bytes and returns their count
SBuf::size_type
Parser::Tokenizer::success(const SBuf::size_type n)
{
    return consume(n).length();
}

bool
Parser::Tokenizer::token(SBuf &returnedToken, const CharacterSet &delimiters)
{
    const Tokenizer saved(*this);
    skipAll(delimiters);
    const SBuf::size_type tokenLen = buf_.findFirstOf(delimiters); // not found = npos => consume to end
    if (tokenLen == SBuf::npos) {
        debugs(24, 8, "no token found for delimiters " << delimiters.name);
        *this = saved;
        return false;
    }
    returnedToken = consume(tokenLen); // cannot be empty
    skipAll(delimiters);
    debugs(24, DBG_DATA, "token found for delimiters " << delimiters.name << ": '" <<
           returnedToken << '\'');
    return true;
}

bool
Parser::Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars, const SBuf::size_type limit)
{
    SBuf::size_type prefixLen = buf_.substr(0,limit).findFirstNotOf(tokenChars);
    if (prefixLen == 0) {
        debugs(24, 8, "no prefix for set " << tokenChars.name);
        return false;
    }
    if (prefixLen == SBuf::npos && (atEnd() || limit == 0)) {
        debugs(24, 8, "no char in set " << tokenChars.name << " while looking for prefix");
        return false;
    }
    if (prefixLen == SBuf::npos && limit > 0) {
        debugs(24, 8, "whole haystack matched");
        prefixLen = limit;
    }
    debugs(24, 8, "found with length " << prefixLen);
    returnedToken = consume(prefixLen); // cannot be empty after the npos check
    return true;
}

bool
Parser::Tokenizer::suffix(SBuf &returnedToken, const CharacterSet &tokenChars, const SBuf::size_type limit)
{
    SBuf span = buf_;

    if (limit < buf_.length())
        span.consume(buf_.length() - limit); // ignore the N prefix characters

    auto i = span.rbegin();
    SBuf::size_type found = 0;
    while (i != span.rend() && tokenChars[*i]) {
        ++i;
        ++found;
    }
    if (!found)
        return false;
    returnedToken = buf_;
    buf_ = returnedToken.consume(buf_.length() - found);
    return true;
}

SBuf::size_type
Parser::Tokenizer::skipAll(const CharacterSet &tokenChars)
{
    const SBuf::size_type prefixLen = buf_.findFirstNotOf(tokenChars);
    if (prefixLen == 0) {
        debugs(24, 8, "no match when trying to skipAll " << tokenChars.name);
        return 0;
    }
    debugs(24, 8, "skipping all in " << tokenChars.name << " len " << prefixLen);
    return success(prefixLen);
}

bool
Parser::Tokenizer::skipOne(const CharacterSet &chars)
{
    if (!buf_.isEmpty() && chars[buf_[0]]) {
        debugs(24, 8, "skipping one-of " << chars.name);
        return success(1);
    }
    debugs(24, 8, "no match while skipping one-of " << chars.name);
    return false;
}

bool
Parser::Tokenizer::skipSuffix(const SBuf &tokenToSkip)
{
    if (buf_.length() < tokenToSkip.length())
        return false;

    SBuf::size_type offset = 0;
    if (tokenToSkip.length() < buf_.length())
        offset = buf_.length() - tokenToSkip.length();

    if (buf_.substr(offset, SBuf::npos).cmp(tokenToSkip) == 0) {
        buf_ = buf_.substr(0,offset);
        return true;
    }
    return false;
}

bool
Parser::Tokenizer::skip(const SBuf &tokenToSkip)
{
    if (buf_.startsWith(tokenToSkip)) {
        debugs(24, 8, "skipping " << tokenToSkip.length());
        return success(tokenToSkip.length());
    }
    debugs(24, 8, "no match, not skipping '" << tokenToSkip << '\'');
    return false;
}

bool
Parser::Tokenizer::skip(const char tokenChar)
{
    if (!buf_.isEmpty() && buf_[0] == tokenChar) {
        debugs(24, 8, "skipping char '" << tokenChar << '\'');
        return success(1);
    }
    debugs(24, 8, "no match, not skipping char '" << tokenChar << '\'');
    return false;
}

/* reworked from compat/strtoll.c */
bool
Parser::Tokenizer::int64(int64_t & result, int base)
{
    if (buf_.isEmpty())
        return false;

    //fixme: account for buf_.size()
    bool neg = false;
    const char *s = buf_.rawContent();
    const char *end = buf_.rawContent() + buf_.length();

    if (*s == '-') {
        neg = true;
        ++s;
    } else if (*s == '+') {
        ++s;
    }
    if (s >= end) return false;
    if (( base == 0 || base == 16) && *s == '0' && (s+1 <= end ) &&
            tolower(*(s+1)) == 'x') {
        s += 2;
        base = 16;
    }
    if (base == 0) {
        if ( *s == '0') {
            base = 8;
            ++s;
        } else {
            base = 10;
        }
    }
    if (s >= end) return false;

    uint64_t cutoff;

    cutoff = neg ? -static_cast<uint64_t>(INT64_MIN) : INT64_MAX;
    const int cutlim = cutoff % static_cast<int64_t>(base);
    cutoff /= static_cast<uint64_t>(base);

    int any = 0, c;
    int64_t acc = 0;
    for (c = *s++; s <= end; c = *s++) {
        if (xisdigit(c)) {
            c -= '0';
        } else if (xisalpha(c)) {
            c -= xisupper(c) ? 'A' - 10 : 'a' - 10;
        } else {
            break;
        }
        if (c >= base)
            break;
        if (any < 0 || static_cast<uint64_t>(acc) > cutoff || (static_cast<uint64_t>(acc) == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }

    if (any == 0) // nothing was parsed
        return false;
    if (any < 0) {
        acc = neg ? INT64_MIN : INT64_MAX;
        errno = ERANGE;
        return false;
    } else if (neg)
        acc = -acc;

    result = acc;
    return success(s - buf_.rawContent() - 1);
}


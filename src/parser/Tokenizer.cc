/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/Tokenizer.h"

#include <cerrno>
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

/// convenience method: consumes up to n bytes, counts, and returns them
SBuf
Parser::Tokenizer::consume(const SBuf::size_type n)
{
    // careful: n may be npos!
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
        *this = saved;
        return false;
    }
    returnedToken = consume(tokenLen); // cannot be empty
    skipAll(delimiters);
    return true;
}

bool
Parser::Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars, const SBuf::size_type limit)
{
    SBuf::size_type prefixLen = buf_.substr(0,limit).findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return false;
    if (prefixLen == SBuf::npos && (atEnd() || limit == 0))
        return false;
    if (prefixLen == SBuf::npos && limit > 0)
        prefixLen = limit;
    returnedToken = consume(prefixLen); // cannot be empty after the npos check
    return true;
}

SBuf::size_type
Parser::Tokenizer::skipAll(const CharacterSet &tokenChars)
{
    const SBuf::size_type prefixLen = buf_.findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return 0;
    return success(prefixLen);
}

bool
Parser::Tokenizer::skipOne(const CharacterSet &chars)
{
    if (!buf_.isEmpty() && chars[buf_[0]])
        return success(1);
    return false;
}

bool
Parser::Tokenizer::skip(const SBuf &tokenToSkip)
{
    if (buf_.startsWith(tokenToSkip))
        return success(tokenToSkip.length());
    return false;
}

bool
Parser::Tokenizer::skip(const char tokenChar)
{
    if (!buf_.isEmpty() && buf_[0] == tokenChar)
        return success(1);
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


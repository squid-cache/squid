/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

/// convenience method: consumes up to n last bytes and returns them
SBuf
Parser::Tokenizer::consumeTrailing(const SBuf::size_type n)
{
    debugs(24, 5, "consuming " << n << " bytes");

    // If n is npos, we consume everything from buf_ (and nothing from result).
    const SBuf::size_type parsed = (n == SBuf::npos) ? buf_.length() : n;

    SBuf result = buf_;
    buf_ = result.consume(buf_.length() - parsed);
    parsed_ += parsed;
    return result;
}

/// convenience method: consumes up to n last bytes and returns their count
SBuf::size_type
Parser::Tokenizer::successTrailing(const SBuf::size_type n)
{
    return consumeTrailing(n).length();
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
    returnedToken = consumeTrailing(found);
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
        debugs(24, 8, "skipping " << tokenToSkip.length());
        return successTrailing(tokenToSkip.length());
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

bool
Parser::Tokenizer::skipOneTrailing(const CharacterSet &skippable)
{
    if (!buf_.isEmpty() && skippable[buf_[buf_.length()-1]]) {
        debugs(24, 8, "skipping one-of " << skippable.name);
        return successTrailing(1);
    }
    debugs(24, 8, "no match while skipping one-of " << skippable.name);
    return false;
}

SBuf::size_type
Parser::Tokenizer::skipAllTrailing(const CharacterSet &skippable)
{
    const SBuf::size_type prefixEnd = buf_.findLastNotOf(skippable);
    const SBuf::size_type prefixLen = prefixEnd == SBuf::npos ?
                                      0 : (prefixEnd + 1);
    const SBuf::size_type suffixLen = buf_.length() - prefixLen;
    if (suffixLen == 0) {
        debugs(24, 8, "no match when trying to skip " << skippable.name);
        return 0;
    }
    debugs(24, 8, "skipping in " << skippable.name << " len " << suffixLen);
    return successTrailing(suffixLen);
}

/* reworked from compat/strtoll.c */
bool
Parser::Tokenizer::int64(int64_t & result, int base, bool allowSign, const SBuf::size_type limit)
{
    if (atEnd() || limit == 0)
        return false;

    const SBuf range(buf_.substr(0,limit));

    //fixme: account for buf_.size()
    bool neg = false;
    const char *s = range.rawContent();
    const char *end = range.rawContent() + range.length();

    if (allowSign) {
        if (*s == '-') {
            neg = true;
            ++s;
        } else if (*s == '+') {
            ++s;
        }
        if (s >= end) return false;
    }
    if (( base == 0 || base == 16) && *s == '0' && (s+1 < end ) &&
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
    do {
        c = *s;
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
    } while (++s < end);

    if (any == 0) // nothing was parsed
        return false;
    if (any < 0) {
        acc = neg ? INT64_MIN : INT64_MAX;
        errno = ERANGE;
        return false;
    } else if (neg)
        acc = -acc;

    result = acc;
    return success(s - range.rawContent());
}


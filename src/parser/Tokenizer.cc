#include "squid.h"
#include "parser/Tokenizer.h"

bool
Parser::Tokenizer::token(SBuf &returnedToken, const CharacterSet &delimiters)
{
    SBuf savebuf(buf_);
    SBuf retval;
    SBuf::size_type tokenLen = 0;
    skip(delimiters);
    // can't use prefix as we're looking for the first char not in delimiters
    tokenLen = buf_.findFirstOf(delimiters); // not found = npos => consume to end
    retval = buf_.consume(tokenLen);
    skip(delimiters);
    returnedToken = retval;
    return true;
}

bool
Parser::Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars, const SBuf::size_type limit)
{
    SBuf::size_type prefixLen = buf_.substr(0,limit).findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return false;
    returnedToken = buf_.consume(prefixLen);
    return true;
}

bool
Parser::Tokenizer::skip(const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = buf_.findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return false;
    buf_.consume(prefixLen);
    return true;
}

bool
Parser::Tokenizer::skip(const SBuf &tokenToSkip)
{
    if (buf_.startsWith(tokenToSkip)) {
        buf_.consume(tokenToSkip.length());
        return true;
    }
    return false;
}

bool
Parser::Tokenizer::skip(const char tokenChar)
{
    if (buf_[0] == tokenChar) {
        buf_.consume(1);
        return true;
    }
    return false;
}

// adapted from compatr/strtoll.c
bool
Parser::Tokenizer::int64 (int64_t & result, int base)
{
    //register uint64_t acc;
    register uint64_t cutoff;
    bool neg = false;
    static SBuf zerox("0x"), zero("0");

    if (buf_.isEmpty())
        return false;

    if (buf_[0] == '-') {
        neg = true;
        buf_.consume(1);
    }
    if (buf_[0] == '+')
        buf_.consume(1);
    if (base == 0) {
        if (buf_.startsWith(zerox))
            base = 16;
        else if (buf_.startsWith(zero))
            base = 8;
        else
            base = 10;
    }
    if (base != 8 && base != 10 && base != 16)
        return false;

    // TODO: finish
    cutoff = neg ? -(uint64_t) INT64_MIN : INT64_MAX;

    // dummy to keep compiler happy. Remove before continuing
    if (neg) result = cutoff;

    return false;
}

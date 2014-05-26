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
    if (buf_.isEmpty())
        return false;

    // API mismatch with strtoll: we don't eat leading space.
    if (xisspace(buf_[0]))
        return false;

    char *eon;
    errno = 0; // reset errno

    int64_t rv = strtoll(buf_.rawContent(), &eon, base);

    if (errno != 0)
        return false;

    buf_.consume(eon - buf_.rawContent()); // consume the parsed chunk
    result = rv;
    return true;

}

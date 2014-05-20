#include "squid.h"
#include "Tokenizer.h"

bool
Parser::Tokenizer::token(SBuf &returnedToken, const CharacterSet &delimiters)
{
    SBuf savebuf(buf_);
    SBuf saveRetVal(returnedToken);
    skip(delimiters);
    if (!prefix(returnedToken,delimiters)) {
        buf_=savebuf;
        returnedToken=saveRetVal;
        return false;
    }
    skip(delimiters);
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

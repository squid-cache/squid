#include "squid.h"
#include "Tokenizer.h"

namespace Parser {

bool
Tokenizer::token(SBuf &returnedToken, const CharacterSet &whitespace)
{
    const SBuf::size_type endOfPreWhiteSpace = buf_.findFirstNotOf(whitespace);
    const SBuf::size_type endOfToken = buf_.findFirstOf(whitespace, endOfPreWhiteSpace);
    if (endOfToken == SBuf::npos)
        return false;
    buf_.consume(endOfPreWhiteSpace);
    returnedToken = buf_.consume(endOfToken - endOfPreWhiteSpace);
    skip(whitespace);
    return true;
}

bool
Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = buf_.findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return false;
    returnedToken = buf_.consume(prefixLen);
    return true;
}

bool
Tokenizer::skip(const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = buf_.findFirstNotOf(tokenChars);
    if (prefixLen == 0)
        return false;
    buf_.consume(prefixLen);
    return true;
}

bool
Tokenizer::skip(const SBuf &tokenToSkip)
{
    if (buf_.startsWith(tokenToSkip)) {
        buf_.consume(tokenToSkip.length());
        return true;
    }
    return false;
}

bool
Tokenizer::skip(const char tokenChar)
{
    if (buf_[0] == tokenChar) {
        buf_.consume(1);
        return true;
    }
    return false;
}
} /* namespace Parser */

#include "squid.h"
#include "Tokenizer.h"

namespace Parser {

SBuf::size_type
Tokenizer::findFirstNotIn(const CharacterSet& tokenChars, SBuf::size_type startAtPos)
{
    SBuf::size_type prefixLen = startAtPos;
    const SBuf::size_type len = buf_.length();
    while (prefixLen < len) {
        if (!tokenChars[buf_[prefixLen]])
            break;
        ++prefixLen;
    }
    return prefixLen;
}

SBuf::size_type
Tokenizer::findFirstIn(const CharacterSet& tokenChars, SBuf::size_type startAtPos)
{
    SBuf::size_type i = startAtPos;
    const SBuf::size_type len = buf_.length();
    bool found = false;
    while (i < len) {
        if (tokenChars[buf_[i]]) {
            found = true;
            break;
        }
        ++i;
    }
    return found ? i : SBuf::npos ;
}

bool
Tokenizer::token(SBuf &returnedToken, const CharacterSet &whitespace)
{
    const SBuf::size_type endOfPreWhiteSpace = findFirstNotIn(whitespace);
    const SBuf::size_type endOfToken = findFirstIn(whitespace, endOfPreWhiteSpace);
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
    SBuf::size_type prefixLen = findFirstNotIn(tokenChars);
    if (prefixLen == 0)
        return false;
    returnedToken = buf_.consume(prefixLen);
    return true;
}

bool
Tokenizer::skip(const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = findFirstNotIn(tokenChars);
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

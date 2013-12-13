#include "squid.h"
#include "Tokenizer.h"

namespace Parser {

SBuf::size_type
Tokenizer::findPrefixLen(const CharacterSet& tokenChars)
{
    SBuf::size_type prefixLen = 0;
    const SBuf::size_type len = buf_.length();
    while (prefixLen < len) {
        if (!tokenChars[buf_[prefixLen]])
            break;
        ++prefixLen;
    }
    return prefixLen;
}

SBuf::size_type
Tokenizer::findFirstOf(const CharacterSet& tokenChars)
{
    SBuf::size_type s = 0;
    const SBuf::size_type len = buf_.length();
    bool found = false;
    while (s < len) {
        if (tokenChars[buf_[prefixLen]]) {
            found = true;
            break;
        }
        ++s;
    }
}

bool
Tokenizer::token(SBuf &returnedToken, const CharacterSet &whitespace)
{
    //TODO
    return false;
}

bool
Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = findPrefixLen(tokenChars);
    if (prefixLen == 0)
        return false;
    returnedToken = buf_.consume(prefixLen);
    return true;
}

bool
Tokenizer::skip(const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = findPrefixLen(tokenChars);
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

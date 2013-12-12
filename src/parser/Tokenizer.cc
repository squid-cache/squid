#include "squid.h"
#include "Tokenizer.h"

namespace Parser {

bool
Tokenizer::token(SBuf &returnedToken, const CharacterSet &whitespace)
{
    //TODO
    return false;
}

bool
Tokenizer::prefix(SBuf &returnedToken, const CharacterSet &tokenChars)
{
    SBuf::size_type prefixLen = 0;
    const SBuf::size_type len=buf_.length();
    while (prefixLen < len) {
        if (!tokenChars[buf_[prefixLen]])
            break;
        ++prefixLen;
    }
    if (prefixLen == 0)
        return false;
    returnedToken = buf_.consume(prefixLen);
    return true;
}

bool
Tokenizer::skip(const CharacterSet &tokenChars)
{
    //TODO
    return false;
}

bool
Tokenizer::skip(const SBuf &tokenToSkip)
{
    //TODO
    return false;
}

bool
Tokenizer::skip(const char tokenChar)
{
    //TODO
    return false;
}

SBuf::size_type
Tokenizer::find_first_in (const CharacterSet &set)
{
    SBuf::size_type rv;
    const SBuf::size_type len=buf_.length();
    for (rv = 0; rv < len; ++rv)
        if (set[buf_[rv]])
            return rv;
    return SBuf::npos;
}

SBuf::size_type
Tokenizer::find_first_not_in (const CharacterSet &set)
{
    return 0;
}

} /* namespace Parser */

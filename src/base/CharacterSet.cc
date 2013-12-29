#include "squid.h"
#include "CharacterSet.h"

CharacterSet &
CharacterSet::operator +=(const CharacterSet &src)
{
    Storage::const_iterator s = src.chars_.begin();
    const Storage::const_iterator e = src.chars_.end();
    Storage::iterator d = chars_.begin();
    while (s != e) {
        if (*s)
            *d = 1;
        ++s;
        ++d;
    }
    return *this;
}

CharacterSet
CharacterSet::operator +(const CharacterSet &src) const
{
    CharacterSet rv(*this);
    rv += src;
    return rv;
}

CharacterSet &
CharacterSet::add(const unsigned char c)
{
    chars_[static_cast<uint8_t>(c)] = 1;
    return *this;
}

CharacterSet &
CharacterSet::addRange(const unsigned char low, const unsigned char high)
{
    assert(low <= high);
    unsigned char c = low;
    while (c <= high) {
        chars_[static_cast<uint8_t>(c)] = 1;
        ++c;
    }
    return *this;
}

CharacterSet::CharacterSet(const char *label, const char * const c)
: name(label == NULL ? "anonymous" : label), chars_(Storage(256,0))
{
    const size_t clen = strlen(c);
    for (size_t i = 0; i < clen; ++i)
        add(c[i]);
}

const CharacterSet
CharacterSet::ALPHA("ALPHA","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
CharacterSet::BIT("BIT","01"),
CharacterSet::CRLF("CRLF","\r\n"),
CharacterSet::DIGIT("DIGIT","0123456789"),
CharacterSet::HEXDIG("HEXDIG","0123456789aAbBcCdDeEfF"),
CharacterSet::WSP("WSP"," \t")
;

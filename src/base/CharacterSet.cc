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
CharacterSet::addRange(const RangeSpec & v)
{
    for (RangeSpec::const_iterator i = v.begin(); i != v.end(); ++i) {
        assert(i->first <= i->second);
        unsigned char c = i->first;
        unsigned char high = i->second;
        while (c <= high) {
            chars_[static_cast<uint8_t>(c)] = 1;
            ++c;
        }
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

CharacterSet::CharacterSet(const char *label, const RangeSpec & ranges)
: CharacterSet(label,"")
{
    addRange(ranges);
}

const CharacterSet
CharacterSet::ALPHA("ALPHA", {{ 'a', 'z' }, { 'A', 'Z'}}),
CharacterSet::BIT("BIT","01"),
CharacterSet::CHAR("CHAR",{{ 1, 127}}),
CharacterSet::CR("CR","\r"),
CharacterSet::CRLF("CRLF","\r\n"),
CharacterSet::DIGIT("DIGIT","0123456789"),
CharacterSet::DQUOTE("DQUOTE","\""),
CharacterSet::HTAB("HTAB","\t"),
CharacterSet::HEXDIG("HEXDIG","0123456789aAbBcCdDeEfF"),
CharacterSet::SP("SP"," "),
CharacterSet::VCHAR("VCHAR",{{ 0x21, 0x7e }} ),
CharacterSet::WSP("WSP"," \t"),
CharacterSet::TCHAR("TCHAR","!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
CharacterSet::SPECIAL("SPECIAL","()<>@,;:\\\"/[]?={}")
//,CharacterSet::QDTEXT("QDTEXT",{{9,9},{0x20,0x21},{0x23,0x5b},{0x5d,0x7e},{0x80,0xff}})
//,CharacterSet::OBSTEXT("OBSTEXT",{{0x80,0xff}})
;

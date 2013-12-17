#include "squid.h"

#include "CharacterSet.h"

const CharacterSet &
CharacterSet::operator +=(const CharacterSet &src)
{
    vector_type::const_iterator s = src.chars_.begin();
    const vector_type::const_iterator e = src.chars_.end();
    vector_type::iterator d = chars_.begin();
    while (s != e) {
        if (*s)
            *d = 1;
        ++s;
        ++d;
    }
    return *this;
}

CharacterSet &
CharacterSet::add(const unsigned char c)
{
    chars_[static_cast<uint8_t>(c)] = 1;
    return *this;
}

CharacterSet::CharacterSet(const char *label, const char * const c)
: name(label == NULL ? "anonymous" : label), chars_(vector_type(256,0))
{
    const size_t clen = strlen(c);
    for (size_t i = 0; i < clen; ++i)
        add(c[i]);
}

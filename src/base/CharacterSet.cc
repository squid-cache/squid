#include "squid.h"

#include "CharacterSet.h"

#include <algorithm>

static bool
isNonZero(uint8_t i) {
    return i!=0;
}

const CharacterSet &
CharacterSet::operator +=(const CharacterSet &src)
{
    std::copy_if(src.chars_.begin(),src.chars_.end(),chars_.begin(),isNonZero);
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

#include "squid.h"

#include "CharacterSet.h"

const CharacterSet &
CharacterSet::operator +=(const CharacterSet &src)
{
    if (src.chars_.size() > chars_.size())
        chars_.reserve(src.chars_.size());

    vector_type::const_iterator s = src.chars_.begin();
    const vector_type::const_iterator e = src.chars_.end();
    vector_type::iterator d = chars_.begin();
    while (s != e) {
        if (*s)
            *d = true;
        ++s;
        ++d;
    }
    return *this;
}

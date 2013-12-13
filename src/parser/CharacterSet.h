#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

namespace Parser {

class CharacterSet
{
public:
    //XXX: use unsigned chars?
    CharacterSet(const char *label, const char * const c) : name(label), chars_(std::vector<bool>(256,false)) {
        size_t clen = strlen(c);
        for (size_t i = 0; i < clen; ++i)
            chars_[static_cast<uint8_t>(c[i])] = true;
    }

    /// whether a given character exists in the set
    bool operator[](char c) const {return chars_[static_cast<uint8_t>(c)];}

    /// add a given char to the character set
    CharacterSet & add(const char c) {chars_[static_cast<uint8_t>(c)] = true; return *this; }

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src) {
        //precondition: src.chars_.size() == chars_.size()
        std::vector<bool>::const_iterator s = src.chars_.begin();
        const std::vector<bool>::const_iterator e = src.chars_.end();
        std::vector<bool>::iterator d = chars_.begin();
        while (s != e) {
            if (*s)
                *d = true;
            ++s;
            ++d;
        }
        return *this;
    }

    /// name of this character set
    const char * name;

private:
    /// characters defined in this set
    std::vector<bool> chars_; //std::vector<bool> is optimized
};

} // namespace Parser

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */

#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

//#include <iostream>
namespace Parser {

class CharacterSet
{
public:
    //XXX: use unsigned chars?
    CharacterSet(const char *label, const char * const c) : name(label) {
        chars_.reserve(256);
        size_t clen = strlen(c);
        for (size_t i = 0; i < clen; ++i)
            chars_[static_cast<uint8_t>(c[i])] = true;
    }

    /// whether a given character exists in the set
    bool operator[](char c) const {return chars_[static_cast<uint8_t>(c)];}

    /// add a given char to the character set
    void add(const char c) {chars_[static_cast<uint8_t>(c)] = true;}

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src) {
        // TODO: iterate src.chars_ vector instead of walking the entire 8-bit space
        for (uint8_t i = 0; i < 256; ++i) {
            if (src.chars_[i]) {
//                std::cout << static_cast<int>(i) << ',';
                chars_[i] = true;
            }
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

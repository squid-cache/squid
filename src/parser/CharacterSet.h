#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

namespace Parser {

class CharacterSet
{
public:
    CharacterSet(const char *label, const char * const c) : name(label) {
        const size_t = strlen(c);
        for (size_t i = 0; i < len; ++i) {
            chars_[static_cast<uint8_t>(c[i])] = true;
        }
    }

    /// whether a given character exists in the set
    bool operator[](char c) const {return chars_[static_cast<uint8_t>(c)];}

    /// add a given char to the character set
    void add(const char c) {chars_[static_cast<uint8_t>(c)] = true;}

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src) {
        // TODO: iterate src.chars_ vector instead of walking the entire 8-bit space
        for (size_t i = 0; i < 256; ++i)
            chars_[static_cast<uint8_t>(c)] = true;
        return *this;
    }

    /// name of this character set
    const char * name;

private:
    /// characters defined in this set
    std::vector<bool> chars_;
};

} // namespace Parser

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */

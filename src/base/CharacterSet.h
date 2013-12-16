#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

/// Optimized set of C chars, with quick membership test and merge support
class CharacterSet
{
public:
    typedef std::vector<uint8_t> vector_type;

    CharacterSet(const char *label, const char * const c)
    : name(label == NULL ? "anonymous" : label), chars_(vector_type(256,0))
    {
        const size_t clen = strlen(c);
        for (size_t i = 0; i < clen; ++i)
            add(c[i]);
    }

    /// whether a given character exists in the set
    bool operator[](unsigned char c) const {return chars_[static_cast<uint8_t>(c)];}

    /// add a given char to the character set.
    CharacterSet & add(const unsigned char c) {chars_[static_cast<uint8_t>(c)] = true; return *this; }

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src) {
        //precondition: src.chars_.size() == chars_.size()
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

    /// optional set label fdebugging (default: "anonymous")
    const char * name;

private:
    /// characters present in this set
   vector_type chars_;
};

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */

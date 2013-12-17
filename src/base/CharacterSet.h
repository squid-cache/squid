#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

/// Optimized set of C chars, with quick membership test and merge support
class CharacterSet
{
public:
    typedef std::vector<uint8_t> vector_type;

    CharacterSet(const char *label, const char * const c);

    /// whether a given character exists in the set
    bool operator[](unsigned char c) const {return chars_[static_cast<uint8_t>(c)] == 1;}

    /// add a given char to the character set.
    CharacterSet & add(const unsigned char c);

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src);

    /// optional set label fdebugging (default: "anonymous")
    const char * name;

private:
    /** characters present in this set.
     *
     * \note guaranteed to be always 256 slots wide, as forced in the
     *  constructor. This assumption is relied upon in operator[], add,
     *  operator+=
     */
   vector_type chars_;
};

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */

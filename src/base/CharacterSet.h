#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <vector>

/// optimized set of C chars, with quick membership test and merge support
class CharacterSet
{
public:
    typedef std::vector<uint8_t> Storage;

    /// define a character set with the given label ("anonymous" if NULL)
    ///  with specified initial contents
    CharacterSet(const char *label, const char * const initial);

    /// define a character set with the given label ("anonymous" if NULL)
    ///  containing characters defined in the supplied ranges
    /// \see addRange
    CharacterSet(const char *label, unsigned char low, unsigned char high);

    /// whether a given character exists in the set
    bool operator[](unsigned char c) const {return chars_[static_cast<uint8_t>(c)] != 0;}

    /// add a given character to the character set
    CharacterSet & add(const unsigned char c);

    /// add a list of character ranges, expressed as pairs [low,high], including both ends
    CharacterSet & addRange(unsigned char low, unsigned char high);

    /// add all characters from the given CharacterSet to this one
    CharacterSet &operator +=(const CharacterSet &src);

    /// return a new CharacterSet containing the union of two sets
    CharacterSet operator +(const CharacterSet &src) const;

    /// optional set label for debugging (default: "anonymous")
    const char * name;

    // common character sets, insipired to RFC5234
    // A-Za-z
    static const CharacterSet ALPHA;
    // 0-1
    static const CharacterSet BIT;
    // carriage return
    static const CharacterSet CR;
    // line feed
    static const CharacterSet LF;
    // double quote
    static const CharacterSet DQUOTE;
    // 0-9
    static const CharacterSet DIGIT;
    // 0-9aAbBcCdDeEfF
    static const CharacterSet HEXDIG;
    // horizontal tab
    static const CharacterSet HTAB;
    // white space
    static const CharacterSet SP;
    // visible (printable) characters
    static const CharacterSet VCHAR;
    // <space><tab>
    static const CharacterSet WSP;
    // character sets from draft httpbis
    // any VCHAR except for SPECIAL
    static const CharacterSet TCHAR;
    // special VCHARs
    static const CharacterSet SPECIAL;
    // qdtext (ready but not enabled as it requires a c++11 constructor)
    //static const CharacterSet QDTEXT;
    // obs-text (ready but not enabled as it requires a c++11 constructor)
    //static const CharacterSet OBSTEXT;

private:
    /** index of characters in this set
     *
     * \note guaranteed to be always 256 slots big, as forced in the
     *  constructor. This assumption is relied upon in operator[], add,
     *  operator+=
     */
    Storage chars_;
};

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */

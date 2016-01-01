/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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

    /// return a new CharacterSet containing characters not in this set
    CharacterSet complement(const char *complementLabel = NULL) const;

    /// change name; handy in const declarations that use operators
    CharacterSet &rename(const char *label) { name = label; return *this; }

    /// optional set label for debugging (default: "anonymous")
    const char * name;

    // common character sets, RFC 5234
    // A-Za-z
    static const CharacterSet ALPHA;
    // 0-1
    static const CharacterSet BIT;
    // carriage return
    static const CharacterSet CR;
    // controls
#if __cplusplus == 201103L
    // ready but disabled as needs C++11 constructor
    //static const CharacterSet CTL;
#endif
    // 0-9
    static const CharacterSet DIGIT;
    // double quote
    static const CharacterSet DQUOTE;
    // 0-9aAbBcCdDeEfF
    static const CharacterSet HEXDIG;
    // horizontal tab
    static const CharacterSet HTAB;
    // line feed
    static const CharacterSet LF;
    // white space
    static const CharacterSet SP;
    // visible (printable) characters
    static const CharacterSet VCHAR;
    // <space><tab>
    static const CharacterSet WSP;

    // HTTP character sets, RFC 7230
    // ctext
#if __cplusplus == 201103L
    // ready but disabled as needs C++11 constructor
    //static const CharacterSet CTEXT;
#endif
    // XXX: maybe field-vchar = VCHAR / obs-text
    // any VCHAR except for SPECIAL
    static const CharacterSet TCHAR;
    // special VCHARs
    static const CharacterSet SPECIAL;
    // qdtext
#if __cplusplus == 201103L
    // ready but disabled as needs C++11 constructor
    //static const CharacterSet QDTEXT;
#endif
    // obs-text
    static const CharacterSet OBSTEXT;

    // HTTP character sets, RFC 7232
    // etagc
#if __cplusplus == 201103L
    // ready but disabled as needs C++11 constructor
    //static const CharacterSet ETAGC;
#endif

    // HTTP character sets, RFC 7235
    // token68 (internal charaters only, excludes '=' terminator)
    static const CharacterSet TOKEN68C;

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


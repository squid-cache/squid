/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <initializer_list>
#include <iosfwd>
#include <vector>

/// optimized set of C chars, with quick membership test and merge support
class CharacterSet
{
public:
    typedef std::vector<uint8_t> Storage;

    /// a character set with a given label and contents
    explicit CharacterSet(const char *label = "anonymous", const char * const chars = "");

    /// define a character set with the given label ("anonymous" if nullptr)
    ///  containing characters defined in the supplied ranges
    /// \see addRange
    CharacterSet(const char *label, unsigned char low, unsigned char high);

    /// define a character set with the given label ("anonymous" if nullptr)
    ///  containing characters defined in the supplied list of low-high ranges
    /// \see addRange
    CharacterSet(const char *label, std::initializer_list<std::pair<uint8_t,uint8_t>> ranges);

    /// whether the set lacks any members
    bool isEmpty() const { return chars_.empty(); }

    /// whether a given character exists in the set
    bool operator[](unsigned char c) const {return chars_[static_cast<uint8_t>(c)] != 0;}

    /// add a given character to the character set
    CharacterSet & add(const unsigned char c);

    /// remove a given character from the character set
    CharacterSet & remove(const unsigned char c);

    /// add a list of character ranges, expressed as pairs [low,high], including both ends
    CharacterSet & addRange(unsigned char low, unsigned char high);

    /// set addition: add to this set all characters that are also in rhs
    CharacterSet &operator +=(const CharacterSet &rhs);

    /// set subtraction: remove all characters that are also in rhs
    CharacterSet &operator -=(const CharacterSet &rhs);

    /// return a new CharacterSet containing characters not in this set
    ///  use the supplied label if provided, default is "complement_of_some_other_set"
    CharacterSet complement(const char *complementLabel = nullptr) const;

    /// change name; handy in const declarations that use operators
    CharacterSet &rename(const char *label) { name = label; return *this; }

    /// \note Ignores label
    bool operator == (const CharacterSet &cs) const { return chars_ == cs.chars_; }
    /// \note Ignores label
    bool operator != (const CharacterSet &cs) const { return !operator==(cs); }

    /// prints all chars in arbitrary order, without any quoting/escaping
    void printChars(std::ostream &os) const;

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
    static const CharacterSet CTL;
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
    static const CharacterSet CTEXT;
    // XXX: maybe field-vchar = VCHAR / obs-text
    // any VCHAR except for SPECIAL
    static const CharacterSet TCHAR;
    // special VCHARs
    static const CharacterSet SPECIAL;
    // qdtext
    static const CharacterSet QDTEXT;
    // obs-text
    static const CharacterSet OBSTEXT;

    // HTTP character sets, RFC 7232
    // etagc
    static const CharacterSet ETAGC;

    // HTTP character sets, RFC 7235
    // token68 (internal characters only, excludes '=' terminator)
    static const CharacterSet TOKEN68C;

private:
    /** index of characters in this set
     *
     * \note guaranteed to be always 256 slots big, as forced in the
     *  constructor. This assumption is relied upon in various methods
     */
    Storage chars_;
};

/** CharacterSet addition
 *
 * \return a new CharacterSet containing all characters present both in lhs
 *  and rhs, labeled as lhs is
 */
CharacterSet
operator+ (CharacterSet lhs, const CharacterSet &rhs);

/** CharacterSet subtraction
 *
 * \return a new CharacterSet containing all characters present in lhs
 *  and not present in rhs, labeled as lhs is
 */
CharacterSet
operator- (CharacterSet lhs, const CharacterSet &rhs);

std::ostream&
operator <<(std::ostream &, const CharacterSet &);

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */


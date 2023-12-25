/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"

#include <algorithm>
#include <iostream>
#include <functional>

CharacterSet &
CharacterSet::operator +=(const CharacterSet &src)
{
    Storage::const_iterator s = src.chars_.begin();
    const Storage::const_iterator e = src.chars_.end();
    Storage::iterator d = chars_.begin();
    while (s != e) {
        if (*s)
            *d = 1;
        ++s;
        ++d;
    }
    return *this;
}

CharacterSet &
CharacterSet::operator -=(const CharacterSet &src)
{
    Storage::const_iterator s = src.chars_.begin();
    const Storage::const_iterator e = src.chars_.end();
    Storage::iterator d = chars_.begin();
    while (s != e) {
        if (*s)
            *d = 0;
        ++s;
        ++d;
    }
    return *this;
}

CharacterSet &
CharacterSet::add(const unsigned char c)
{
    chars_[static_cast<uint8_t>(c)] = 1;
    return *this;
}

CharacterSet &
CharacterSet::remove(const unsigned char c)
{
    chars_[static_cast<uint8_t>(c)] = 0;
    return *this;
}

CharacterSet &
CharacterSet::addRange(unsigned char low, unsigned char high)
{
    //manual loop splitting is needed to cover case where high is 255
    // otherwise low will wrap, resulting in infinite loop
    while (low < high) {
        chars_[static_cast<uint8_t>(low)] = 1;
        ++low;
    }
    chars_[static_cast<uint8_t>(high)] = 1;
    return *this;
}

CharacterSet
CharacterSet::complement(const char *label) const
{
    CharacterSet result((label ? label : "complement_of_some_other_set"), "");
    // negate each of our elements and add them to the result storage
    std::transform(chars_.begin(), chars_.end(), result.chars_.begin(),
                   std::logical_not<Storage::value_type>());
    return result;
}

CharacterSet::CharacterSet(const char *label, const char * const c) :
    name(label ? label: "anonymous"),
    chars_(Storage(256,0))
{
    const size_t clen = strlen(c);
    for (size_t i = 0; i < clen; ++i)
        add(c[i]);
}

CharacterSet::CharacterSet(const char *label, unsigned char low, unsigned char high) :
    name(label ? label: "anonymous"),
    chars_(Storage(256,0))
{
    addRange(low,high);
}

CharacterSet::CharacterSet(const char *label, std::initializer_list<std::pair<uint8_t, uint8_t>> ranges) :
    name(label ? label: "anonymous"),
    chars_(Storage(256,0))
{
    for (auto range: ranges)
        addRange(range.first, range.second);
}

void
CharacterSet::printChars(std::ostream &os) const
{
    for (size_t idx = 0; idx < 256; ++idx) {
        if (chars_[idx])
            os << static_cast<char>(idx);
    }
}

CharacterSet
operator+ (CharacterSet lhs, const CharacterSet &rhs)
{
    lhs += rhs;
    return lhs;
}

CharacterSet
operator- (CharacterSet lhs, const CharacterSet &rhs)
{
    lhs -= rhs;
    return lhs;
}

std::ostream&
operator <<(std::ostream &s, const CharacterSet &c)
{
    s << "CharacterSet(" << c.name << ')';
    return s;
}

const CharacterSet
// RFC 5234
CharacterSet::ALPHA("ALPHA", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
             CharacterSet::BIT("BIT","01"),
             CharacterSet::CR("CR","\r"),
CharacterSet::CTL("CTL", {{0x01,0x1f},{0x7f,0x7f}}),
CharacterSet::DIGIT("DIGIT","0123456789"),
CharacterSet::DQUOTE("DQUOTE","\""),
CharacterSet::HEXDIG("HEXDIG","0123456789aAbBcCdDeEfF"),
CharacterSet::HTAB("HTAB","\t"),
CharacterSet::LF("LF","\n"),
CharacterSet::SP("SP"," "),
CharacterSet::VCHAR("VCHAR", 0x21, 0x7e),
// RFC 7230
CharacterSet::WSP("WSP"," \t"),
CharacterSet::CTEXT("ctext", {{0x09,0x09},{0x20,0x20},{0x2a,0x5b},{0x5d,0x7e},{0x80,0xff}}),
CharacterSet::TCHAR("TCHAR","!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
CharacterSet::SPECIAL("SPECIAL","()<>@,;:\\\"/[]?={}"),
CharacterSet::QDTEXT("QDTEXT", {{0x09,0x09},{0x20,0x21},{0x23,0x5b},{0x5d,0x7e},{0x80,0xff}}),
CharacterSet::OBSTEXT("OBSTEXT",0x80,0xff),
// RFC 7232
CharacterSet::ETAGC("ETAGC", {{0x21,0x21},{0x23,0x7e},{0x80,0xff}}),
// RFC 7235
CharacterSet::TOKEN68C("TOKEN68C","-._~+/0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
;


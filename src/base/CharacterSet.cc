/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CharacterSet.h"

#include <algorithm>
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

CharacterSet
CharacterSet::operator +(const CharacterSet &src) const
{
    CharacterSet rv(*this);
    rv += src;
    return rv;
}

CharacterSet &
CharacterSet::add(const unsigned char c)
{
    chars_[static_cast<uint8_t>(c)] = 1;
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
    name(label == NULL ? "anonymous" : label),
    chars_(Storage(256,0))
{
    const size_t clen = strlen(c);
    for (size_t i = 0; i < clen; ++i)
        add(c[i]);
}

CharacterSet::CharacterSet(const char *label, unsigned char low, unsigned char high) :
    name(label == NULL ? "anonymous" : label),
    chars_(Storage(256,0))
{
    addRange(low,high);
}

const CharacterSet
// RFC 5234
CharacterSet::ALPHA("ALPHA", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
             CharacterSet::BIT("BIT","01"),
             CharacterSet::CR("CR","\r"),
#if __cplusplus == 201103L
//CharacterSet::CTL("CTL",{{0x01,0x1f},{0x7f,0x7f}}),
#endif
             CharacterSet::DIGIT("DIGIT","0123456789"),
             CharacterSet::DQUOTE("DQUOTE","\""),
             CharacterSet::HEXDIG("HEXDIG","0123456789aAbBcCdDeEfF"),
             CharacterSet::HTAB("HTAB","\t"),
             CharacterSet::LF("LF","\n"),
             CharacterSet::SP("SP"," "),
             CharacterSet::VCHAR("VCHAR", 0x21, 0x7e),
// RFC 7230
             CharacterSet::WSP("WSP"," \t"),
#if __cplusplus == 201103L
//CharacterSet::CTEXT("ctext",{{0x09,0x09},{0x20,0x20},{0x2a,0x5b},{0x5d,0x7e},{0x80,0xff}}),
#endif
             CharacterSet::TCHAR("TCHAR","!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
             CharacterSet::SPECIAL("SPECIAL","()<>@,;:\\\"/[]?={}"),
#if __cplusplus == 201103L
//CharacterSet::QDTEXT("QDTEXT",{{0x09,0x09},{0x20,0x21},{0x23,0x5b},{0x5d,0x7e},{0x80,0xff}}),
#endif
             CharacterSet::OBSTEXT("OBSTEXT",0x80,0xff),
// RFC 7232
#if __cplusplus == 201103L
//CharacterSet::ETAGC("ETAGC",{{0x21,0x21},{0x23,0x7e},{0x80,0xff}}),
#endif
// RFC 7235
             CharacterSet::TOKEN68C("TOKEN68C","-._~+/0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
             ;


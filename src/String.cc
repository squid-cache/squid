
/*
 * $Id: String.cc,v 1.17 2003/03/10 04:56:36 robertc Exp $
 *
 * DEBUG: section 67    String
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Store.h"

void
String::initBuf(size_t sz)
{
    buf((char *)memAllocString(sz, &sz));
    assert(sz < 65536);
    size_ = sz;
}

void
String::init(char const *str)
{
    assert(this);

    if (str)
        limitInit(str, strlen(str));
    else
        clean();
}

String::String (char const *aString) : size_(0), len_(0), buf_(NULL)
{
    init (aString);
#if DEBUGSTRINGS

    StringRegistry::Instance().add(this);
#endif
}

String &
String::operator =(char const *aString)
{
    clean();
    init (aString);
    return *this;
}

String &
String::operator = (String const &old)
{
    clean ();

    if (old.len_)
        limitInit (old.buf(), old.len_);

    return *this;
}

void
String::limitInit(const char *str, int len)
{
    assert(this && str);
    initBuf(len + 1);
    len_ = len;
    xmemcpy(buf_, str, len);
    buf_[len] = '\0';
}

String::String (String const &old) : size_(0), len_(0), buf_(NULL)
{
    init (old.buf());
#if DEBUGSTRINGS

    StringRegistry::Instance().add(this);
#endif
}

void
String::clean()
{
    assert(this);

    if (buf())
        memFreeString(size_, buf_);

    len_ = 0;

    size_ = 0;

    buf_ = NULL;
}

String::~String()
{
    clean();
#if DEBUGSTRINGS

    StringRegistry::Instance().remove(this);
#endif
}

void
String::reset(const char *str)
{
    clean();
    init(str);
}

void
String::append(const char *str, int len)
{
    assert(this);
    assert(str && len >= 0);

    if (len_ + len < size_) {
        strncat(buf_, str, len);
        len_ += len;
    } else {
        String snew;
        snew.len_ = len_ + len;
        snew.initBuf(snew.len_ + 1);

        if (buf_)
            xmemcpy(snew.buf_, buf(), len_);

        if (len)
            xmemcpy(snew.buf_ + len_, str, len);

        snew.buf_[snew.len_] = '\0';

        absorb(snew);
    }
}

void
String::append(char const *str)
{
    assert (str);
    append (str, strlen(str));
}

void
String::append (char chr)
{
    char myString[2];
    myString[0]=chr;
    myString[1]='\0';
    append (myString, 1);
}

void
String::append(String const &old)
{
    append (old.buf(), old.len_);
}

void
String::absorb(String &old)
{
    clean();
    size_ = old.size_;
    buf (old.buf_);
    len_ = old.len_;
    old.size_ = 0;
    old.buf_ = NULL;
    old.len_ = 0;
}

void
String::buf(char *newBuf)
{
    assert (buf_ == NULL);
    buf_ = newBuf;
}

#if DEBUGSTRINGS
void
String::stat(StoreEntry *entry) const
{
    storeAppendPrintf(entry, "%p : %d/%d \"%s\"\n",this,len_, size_, buf());
}

StringRegistry &
StringRegistry::Instance()
{
    return Instance_;
}

template <class C>
int
ptrcmp(C const &lhs, C const &rhs)
{
    return lhs - rhs;
}

void
StringRegistry::registerMe()
{
    registered = true;
    cachemgrRegister("strings",
                     "Strings in use in squid", Stat, 0, 1);
}

void

StringRegistry::add
    (String const *entry)
{
    if (!registered)
        registerMe();

    entries.insert(entry, ptrcmp);
}

void

StringRegistry::remove
    (String const *entry)
{
    entries.remove(entry, ptrcmp);
}

StringRegistry StringRegistry::Instance_;

extern size_t memStringCount();

void
StringRegistry::Stat(StoreEntry *entry)
{
    storeAppendPrintf(entry, "%lu entries, %lu reported from MemPool\n", (unsigned long) Instance().entries.elements, (unsigned long) memStringCount());
    Instance().entries.head->walk(Stater, entry);
}

void
StringRegistry::Stater(String const * const & nodedata, void *state)
{
    StoreEntry *entry = (StoreEntry *) state;
    nodedata->stat(entry);
}

#endif

#ifndef _USE_INLINE_
#include "String.cci"
#endif

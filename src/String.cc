
/*
 * $Id: String.cc,v 1.13 2003/02/21 22:50:06 robertc Exp $
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

String const String::Null;

void
String::initBuf(size_t sz)
{
    buf_ = (char *)memAllocString(sz, &sz);
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
        limitInit (old.buf_, old.len_);

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
    init (old.buf_);
}

void
String::clean()
{
    assert(this);

    if (buf_)
        memFreeString(size_, buf_);

    len_ = 0;

    size_ = 0;

    buf_ = NULL;
}

String::~String()
{
    clean();
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
            xmemcpy(snew.buf_, buf_, len_);

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
String::append(String const &old)
{
    append (old.buf_, old.len_);
}

void
String::absorb(String &old)
{
    clean();
    size_ = old.size_;
    buf_ = old.buf_;
    len_ = old.len_;
    old.size_ = 0;
    old.buf_ = NULL;
    old.len_ = 0;
}

#ifndef _USE_INLINE_
#include "String.cci"
#endif

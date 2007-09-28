
/*
 * $Id: SquidString.h,v 1.11 2007/09/28 01:40:50 amosjeffries Exp $
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

#ifndef SQUID_STRING_H
#define SQUID_STRING_H

/* forward decls */

class CacheManager;

#define DEBUGSTRINGS 0
#if DEBUGSTRINGS
#include "splay.h"

class String;

class StringRegistry
{

public:
    static StringRegistry &Instance();

    void add
        (String const *);

    void registerWithCacheManager(CacheManager & manager);

    void remove
        (String const *);

private:
    static OBJH Stat;

    static StringRegistry Instance_;

    static SplayNode<String const *>::SPLAYWALKEE Stater;

    Splay<String const *> entries;

    bool registered;

};

class StoreEntry;
#endif

class String
{

public:
    _SQUID_INLINE_ String();
    String (char const *);
    String (String const &);
    ~String();

    String &operator =(char const *);
    String &operator =(String const &);
    bool operator ==(String const &) const;
    bool operator !=(String const &) const;

    _SQUID_INLINE_ int size() const;
    _SQUID_INLINE_ char const * buf() const;
    void buf(char *);
    void init (char const *);
    void initBuf(size_t sz);
    void limitInit(const char *str, int len);
    void clean();
    void reset(char const *str);
    void append(char const *buf, int len);
    void append(char const *buf);
    void append(char const);
    void append (String const &);
    void absorb(String &old);
    _SQUID_INLINE_ const char * pos(char const *) const;
    _SQUID_INLINE_ const char * pos(char const ch) const;
    _SQUID_INLINE_ const char * rpos(char const ch) const;
    _SQUID_INLINE_ int cmp (char const *) const;
    _SQUID_INLINE_ int cmp (char const *, size_t count) const;
    _SQUID_INLINE_ int cmp (String const &) const;
    _SQUID_INLINE_ int caseCmp (char const *) const;
    _SQUID_INLINE_ int caseCmp (char const *, size_t count) const;

    _SQUID_INLINE_ void set
        (char const *loc, char const ch);

    _SQUID_INLINE_ void cut (size_t newLength);

    _SQUID_INLINE_ void cutPointer (char const *loc);

#if DEBUGSTRINGS

    void stat (StoreEntry *) const;

#endif

private:
    /* never reference these directly! */
    unsigned short int size_; /* buffer size; 64K limit */

    unsigned short int len_;  /* current length  */

    char *buf_;
};

_SQUID_INLINE_ std::ostream & operator<<(std::ostream& os, String const &aString);

#ifdef _USE_INLINE_
#include "String.cci"
#endif

#endif /* SQUID_STRING_H */

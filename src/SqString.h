
/*
 * $Id: SqString.h,v 1.3 2007/05/20 08:29:44 amosjeffries Exp $
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

#ifndef SQSTRING_H
#define SQSTRING_H

/* forward decls */

class CacheManager;

#define DEBUGSTRINGS 0
#if DEBUGSTRINGS
#include "splay.h"

class SqString;

class SqStringRegistry
{

public:
    static StringRegistry &Instance();

    void add
        (SqString const *);

    void registerWithCacheManager(CacheManager & manager);

    void remove
        (SqString const *);

private:
    static OBJH Stat;

    static StringRegistry Instance_;

    static SplayNode<SqString const *>::SPLAYWALKEE Stater;

    Splay<SqString const *> entries;

    bool registered;

};

class StoreEntry;
#endif

class SqString
{

public:

    /* std::string API available */
    _SQUID_INLINE_ SqString();
    SqString (char const *);
    SqString (SqString const &);
    ~SqString();

    SqString &operator =(char const *);
    SqString &operator =(SqString const &);
    bool operator ==(SqString const &) const;
    bool operator !=(SqString const &) const;
    bool operator >=(SqString const &) const;
    bool operator <=(SqString const &) const;
    bool operator >(SqString const &) const;
    bool operator <(SqString const &) const;

    _SQUID_INLINE_ int size() const;
    _SQUID_INLINE_ char const * c_str() const;

    const char& operator [](unsigned int) const;
    char& operator [](unsigned int);

    void clear();

    void append(char const *buf, int len);
    void append(char const *buf);
    void append(char const);
    void append(SqString const &);

    _SQUID_INLINE_ bool empty() const;
    _SQUID_INLINE_ int compare(char const *) const;
    _SQUID_INLINE_ int compare(char const *, size_t count) const;
    _SQUID_INLINE_ int compare(SqString const &) const;

/* Custom Squid Operations available */
    /// Super-efficient string assignment. Moves internal content from one object to another.
    /// then resets the initial pobject to empty.
    _SQUID_INLINE_ void absorb(SqString &old);
    _SQUID_INLINE_ const char * pos(char const *) const;
    _SQUID_INLINE_ const char * pos(char const ch) const;
    _SQUID_INLINE_ const char * rpos(char const ch) const;

    _SQUID_INLINE_ void set
        (char const *loc, char const ch);

    _SQUID_INLINE_ void cut (size_t newLength);

    _SQUID_INLINE_ void cutPointer (char const *loc);

#if DEBUGSTRINGS

    void stat (StoreEntry *) const;

#endif

    void limitInit(const char *str, unsigned int len);
private:
    void initBuf(size_t sz);
    void init (char const *);

    /* never reference these directly! */
    unsigned short int size_;	/* buffer size; 64K limit */

    unsigned short int len_;	/* current length  */

    char *buf_;
};

#ifdef _USE_INLINE_
#include "SqString.cci"
#endif

#endif /* SQSTRING_H */


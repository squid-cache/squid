/*
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

#if HAVE_OSTREAM
#include <ostream>
#endif

/* squid string placeholder (for printf) */
#ifndef SQUIDSTRINGPH
#define SQUIDSTRINGPH "%.*s"
#define SQUIDSTRINGPRINT(s) (s).psize(),(s).rawBuf()
#endif /* SQUIDSTRINGPH */

#define DEBUGSTRINGS 0
#if DEBUGSTRINGS
#include "splay.h"

class String;

class StringRegistry
{

public:
    static StringRegistry &Instance();

    void add(String const *);

    StringRegistry();

    void remove(String const *);

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
    String(char const *);
    String(String const &);
    ~String();

    typedef size_t size_type; //storage size intentionally unspecified
    const static size_type npos = static_cast<size_type>(-1);

    String &operator =(char const *);
    String &operator =(String const &);
    bool operator ==(String const &) const;
    bool operator !=(String const &) const;

    /**
     * Retrieve a single character in the string.
     \param pos	Position of character to retrieve.
     */
    _SQUID_INLINE_ char operator [](unsigned int pos) const;

    _SQUID_INLINE_ size_type size() const;
    /// variant of size() suited to be used for printf-alikes.
    /// throws when size() > MAXINT
    int psize() const;

    /**
     * \retval true the String has some contents
     */
    _SQUID_INLINE_ bool defined() const;
    /**
     * \retval true the String does not hold any contents
     */
    _SQUID_INLINE_ bool undefined() const;
    /**
     * Returns a raw pointer to the underlying backing store. The caller has been
     * verified not to make any assumptions about null-termination
     */
    _SQUID_INLINE_ char const * rawBuf() const;
    /**
     * Returns a raw pointer to the underlying backing store.
     * The caller requires it to be null-terminated.
     */
    _SQUID_INLINE_ char const * termedBuf() const;
    void limitInit(const char *str, int len); // TODO: rename to assign()
    void clean();
    void reset(char const *str);
    void append(char const *buf, int len);
    void append(char const *buf);
    void append(char const);
    void append(String const &);
    void absorb(String &old);
    const char * pos(char const *aString) const;
    const char * pos(char const ch) const;
    ///offset from string start of the first occurrence of ch
    /// returns String::npos if ch is not found
    size_type find(char const ch) const;
    size_type find(char const *aString) const;
    const char * rpos(char const ch) const;
    size_type rfind(char const ch) const;
    _SQUID_INLINE_ int cmp(char const *) const;
    _SQUID_INLINE_ int cmp(char const *, size_type count) const;
    _SQUID_INLINE_ int cmp(String const &) const;
    _SQUID_INLINE_ int caseCmp(char const *) const;
    _SQUID_INLINE_ int caseCmp(char const *, size_type count) const;
    _SQUID_INLINE_ int caseCmp(String const &) const;

    String substr(size_type from, size_type to) const;

    _SQUID_INLINE_ void cut(size_type newLength);

#if DEBUGSTRINGS
    void stat(StoreEntry *) const;
#endif

private:
    void allocAndFill(const char *str, int len);
    void allocBuffer(size_type sz);
    void setBuffer(char *buf, size_type sz);

    _SQUID_INLINE_ bool nilCmp(bool, bool, int &) const;

    /* never reference these directly! */
    size_type size_; /* buffer size; 64K limit */

    size_type len_;  /* current length  */

    char *buf_;

    _SQUID_INLINE_ void set(char const *loc, char const ch);
    _SQUID_INLINE_ void cutPointer(char const *loc);

};

_SQUID_INLINE_ std::ostream & operator<<(std::ostream& os, String const &aString);

_SQUID_INLINE_ bool operator<(const String &a, const String &b);

#if _USE_INLINE_
#include "String.cci"
#endif

const char *checkNullString(const char *p);
int stringHasWhitespace(const char *);
int stringHasCntl(const char *);
char *strwordtok(char *buf, char **t);

#endif /* SQUID_STRING_H */

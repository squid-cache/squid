
/*
 * $Id: String.cc,v 1.22 2006/09/28 07:33:59 adrian Exp $
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
    PROF_start(StringInitBuf);
    buf((char *)memAllocString(sz, &sz));
    assert(sz < 65536);
    size_ = sz;
    PROF_stop(StringInitBuf);
}

void
String::init(char const *str)
{
    assert(this);

    PROF_start(StringInit);
    if (str)
        limitInit(str, strlen(str));
    else
        clean();
    PROF_stop(StringInit);
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

bool
String::operator == (String const &that) const
{
    if (0 == this->cmp(that))
        return true;

    return false;
}

bool
String::operator != (String const &that) const
{
    if (0 == this->cmp(that))
        return false;

    return true;
}

void
String::limitInit(const char *str, int len)
{
    PROF_start(StringLimitInit);
    assert(this && str);
    initBuf(len + 1);
    len_ = len;
    xmemcpy(buf_, str, len);
    buf_[len] = '\0';
    PROF_stop(StringLimitInit);
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
    PROF_start(StringClean);
    assert(this);

    if (buf())
        memFreeString(size_, buf_);

    len_ = 0;

    size_ = 0;

    buf_ = NULL;
    PROF_stop(StringClean);
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
    PROF_start(StringReset);
    clean();
    init(str);
    PROF_stop(StringReset);
}

void
String::append(const char *str, int len)
{
    assert(this);
    assert(str && len >= 0);

    PROF_start(StringAppend);
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
    PROF_stop(StringAppend);
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
StringRegistry::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("strings",
                           "Strings in use in squid", Stat, 0, 1);
}

void

StringRegistry::add
    (String const *entry)
{
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

/* TODO: move onto String */
int
stringHasWhitespace(const char *s)
{
    return strpbrk(s, w_space) != NULL;
}

/* TODO: move onto String */
int
stringHasCntl(const char *s)
{
    unsigned char c;

    while ((c = (unsigned char) *s++) != '\0') {
        if (c <= 0x1f)
            return 1;

        if (c >= 0x7f && c <= 0x9f)
            return 1;
    }

    return 0;
}

/*
 * Similar to strtok, but has some rudimentary knowledge
 * of quoting
 */
char *
strwordtok(char *buf, char **t)
{
    unsigned char *word = NULL;
    unsigned char *p = (unsigned char *) buf;
    unsigned char *d;
    unsigned char ch;
    int quoted = 0;

    if (!p)
        p = (unsigned char *) *t;

    if (!p)
        goto error;

    while (*p && isspace(*p))
        p++;

    if (!*p)
        goto error;

    word = d = p;

    while ((ch = *p)) {
        switch (ch) {

        case '\\':
            p++;

            switch (*p) {

            case 'n':
                ch = '\n';

                break;

            case 'r':
                ch = '\r';

                break;

            default:
                ch = *p;

                break;

            }

            *d++ = ch;

            if (ch)
                p++;

            break;

        case '"':
            quoted = !quoted;

            p++;

            break;

        default:
            if (!quoted && isspace(*p)) {
                p++;
                goto done;
            }

            *d++ = *p++;
            break;
        }
    }

done:
    *d++ = '\0';

error:
    *t = (char *) p;
    return (char *) word;
}

const char *
checkNullString(const char *p)
{
    return p ? p : "(NULL)";
}

#ifndef _USE_INLINE_
#include "String.cci"
#endif

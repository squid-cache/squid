
/*
 * $Id: SqString.cc,v 1.3 2007/05/19 06:31:00 amosjeffries Exp $
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
#include "SqString.h"
#include "Store.h"

void
SqString::initBuf(size_t sz)
{
    PROF_start(StringInitBuf);
    clear();
    buf_ = (char *)memAllocString(sz, &sz);
    assert(sz < 65536);
    size_ = sz;
    PROF_stop(StringInitBuf);
}

void
SqString::limitInit(const char *str, int len)
{
    PROF_start(StringLimitInit);
    assert(this && str);
    initBuf(len + 1);
    len_ = len;
    xmemcpy(buf_, str, len);
    buf_[len] = '\0';
    PROF_stop(StringLimitInit);
}

void
SqString::init(char const *str)
{
    assert(this);

    PROF_start(StringInit);

    if (str)
        limitInit(str, strlen(str));
    else
        clear();
    PROF_stop(StringInit);
}

void
SqString::clear()
{
    PROF_start(StringClean);
    assert(this);

    if (buf_)
        memFreeString(size_, buf_);

    len_ = 0;
    size_ = 0;
    buf_ = NULL;
    PROF_stop(StringClean);
}

SqString::~SqString()
{
    clear();
#if DEBUGSTRINGS

    SqStringRegistry::Instance().remove(this);
#endif
}

SqString::SqString (char const *aString)
{
    memset(this, 0, sizeof(SqString));

    init(aString);
#if DEBUGSTRINGS

    SqStringRegistry::Instance().add(this);
#endif
}

SqString &
SqString::operator =(char const *aString)
{
    assert(this);
    init(aString);
    return *this;
}

SqString &
SqString::operator = (SqString const &old)
{
    if (old.size())
        limitInit(old.c_str(), old.size());
    else
        clear();

    return *this;
}

bool
SqString::operator == (SqString const &that) const
{
    return (this->compare(that) == 0);
}

bool
SqString::operator != (SqString const &that) const
{
    return (this->compare(that) != 0);
}

bool
SqString::operator >= (SqString const &that) const
{
    return (this->compare(that) >= 0);
}

bool
SqString::operator <= (SqString const &that) const
{
    return (this->compare(that) <= 0);
}

bool
SqString::operator > (SqString const &that) const
{
    return (this->compare(that) > 0);
}

bool
SqString::operator < (SqString const &that) const
{
    return (this->compare(that) < 0);
}

SqString::SqString (SqString const &old)
{
    memset(this, 0, sizeof(SqString));

    init (old.c_str());
#if DEBUGSTRINGS

    SqStringRegistry::Instance().add(this);
#endif
}

void
SqString::append(const char *str, int len)
{
    assert(this);

    PROF_start(StringAppend);

    if(len < 1 || str == NULL)
        return;

    if (len_ + len < size_) {
        strncat(buf_, str, len);
        len_ += len;
    } else {
        unsigned int ssz = len_ + len;
        unsigned int bsz = len_ + len + 1;
        char* tmp = (char *)memAllocString(ssz, &bsz);
        assert(bsz < 65536);

        if (buf_)
            xmemcpy(tmp, buf_, len_);

        if (len)
            xmemcpy(tmp + len_, str, len);

        tmp[ssz + 1] = '\0';

        clear();

        size_ = bsz;
        len_ = ssz;
        buf_ = tmp;
        tmp = NULL;
    }
    PROF_stop(StringAppend);
}

void
SqString::append(char const *str)
{
    if(!str) return;
    append (str, strlen(str));
}

void
SqString::append (char chr)
{
    char myString[2];
    myString[0]=chr;
    myString[1]='\0';
    append (myString, 1);
}

void
SqString::append(SqString const &old)
{
    append (old.c_str(), old.len_);
}

const char&
SqString::operator [](unsigned int pos) const
{
    assert(pos < size_ );

    return buf_[pos];
}

char&
SqString::operator [](unsigned int pos)
{
    assert(pos < size_ );

    return buf_[pos];
}

#if DEBUGSTRINGS
void
SqString::stat(StoreEntry *entry) const
{
    storeAppendPrintf(entry, "%p : %d/%d \"%s\"\n",this,len_, size_, c_str());
}

SqStringRegistry &
SqStringRegistry::Instance()
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
SqStringRegistry::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("strings",
                           "Strings in use in squid", Stat, 0, 1);
}

void
SqStringRegistry::add(SqString const *entry)
{
    entries.insert(entry, ptrcmp);
}

void
SqStringRegistry::remove(SqString const *entry)
{
    entries.remove(entry, ptrcmp);
}

SqStringRegistry SqStringRegistry::Instance_;

extern size_t memStringCount();

void
SqStringRegistry::Stat(StoreEntry *entry)
{
    storeAppendPrintf(entry, "%lu entries, %lu reported from MemPool\n", (unsigned long) Instance().entries.elements, (unsigned long) memStringCount());
    Instance().entries.head->walk(Stater, entry);
}

void
SqStringRegistry::Stater(SqString const * const & nodedata, void *state)
{
    StoreEntry *entry = (StoreEntry *) state;
    nodedata->stat(entry);
}

#endif

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

    while (*p && xisspace(*p))
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
            if (!quoted && xisspace(*p)) {
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

#ifndef _USE_INLINE_
#include "SqString.cci"
#endif

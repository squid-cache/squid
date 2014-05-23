/*
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
#ifndef SQUID_WORDLIST_H
#define SQUID_WORDLIST_H

#include "globals.h"
#include "MemPool.h"
#include "profiler/Profiler.h"
#include "SBufList.h"

/** A list of C-strings
 *
 * \deprecated use SBufList instead
 */
class wordlist
{
public:
    MEMPROXY_CLASS(wordlist);
    char *key;
    wordlist *next;
};

MEMPROXY_CLASS_INLINE(wordlist);

class MemBuf;

/** Add a null-terminated c-string to a wordlist
 *
 * \deprecated use SBufList.push_back(SBuf(word)) instead
 */
const char *wordlistAdd(wordlist **, const char *);

/** Concatenate a wordlist
 *
 * \deprecated use SBufListContainerJoin(SBuf()) from SBufAlgos.h instead
 */
void wordlistCat(const wordlist *, MemBuf *);

/** append a wordlist to another
 *
 * \deprecated use SBufList.merge(otherwordlist) instead
 */
void wordlistAddWl(wordlist **, wordlist *);

/** Concatenate the words in a wordlist
 *
 * \deprecated use SBufListContainerJoin(SBuf()) from SBufAlgos.h instead
 */
void wordlistJoin(wordlist **, wordlist **);

/// duplicate a wordlist
wordlist *wordlistDup(const wordlist *);

/// destroy a wordlist
void wordlistDestroy(wordlist **);

/// convert a wordlist to a SBufList
SBufList ToSBufList(wordlist *);

#endif /* SQUID_WORDLIST_H */

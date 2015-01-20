/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_WORDLIST_H
#define SQUID_WORDLIST_H

#include "globals.h"
#include "profiler/Profiler.h"
#include "SBufList.h"

/** A list of C-strings
 *
 * \deprecated use SBufList instead
 */
class wordlist
{
    MEMPROXY_CLASS(wordlist);

public:
    char *key;
    wordlist *next;
};

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


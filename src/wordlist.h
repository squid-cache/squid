/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_WORDLIST_H
#define SQUID_SRC_WORDLIST_H

#include "globals.h"
#include "sbuf/List.h"

/** A list of C-strings
 *
 * \deprecated use SBufList instead
 */
class wordlist
{
    MEMPROXY_CLASS(wordlist);
    friend char *wordlistChopHead(wordlist **);

public:
    wordlist() : key(nullptr), next(nullptr) {}
    // create a new wordlist node, with a copy of k as key
    explicit wordlist(const char *k) : key(xstrdup(k)), next(nullptr) {}

    wordlist(const wordlist &) = delete;
    wordlist &operator=(const wordlist &) = delete;

    char *key;
    wordlist *next;

private:
    // does not free data members.
    ~wordlist() = default;
};

class MemBuf;

/** Add a null-terminated c-string to a wordlist
 *
 * \deprecated use SBufList.push_back(SBuf(word)) instead
 */
const char *wordlistAdd(wordlist **, const char *);

/** Concatenate a wordlist
 *
 * \deprecated use SBufListContainerJoin(SBuf()) from sbuf/Algorithms.h instead
 */
void wordlistCat(const wordlist *, MemBuf *);

/// destroy a wordlist
void wordlistDestroy(wordlist **);

/**  Remove and destroy the first element while preserving and returning its key
 *
 * \note the returned key must be freed by the caller using safe_free
 * \note wl is altered so that it points to the second element
 * \return nullptr if pointed-to wordlist is nullptr.
 */
char *wordlistChopHead(wordlist **);

/// convert a wordlist to a SBufList
SBufList ToSBufList(wordlist *);

#endif /* SQUID_SRC_WORDLIST_H */


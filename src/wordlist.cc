/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "MemBuf.h"
#include "wordlist.h"

void
wordlistDestroy(wordlist ** list)
{
    while (*list != nullptr) {
        const char *k = wordlistChopHead(list);
        safe_free(k);
    }
}

const char *
wordlistAdd(wordlist ** list, const char *key)
{
    while (*list)
        list = &(*list)->next;

    *list = new wordlist(key);
    return (*list)->key;
}

void
wordlistCat(const wordlist * w, MemBuf * mb)
{
    while (NULL != w) {
        mb->appendf("%s\n", w->key);
        w = w->next;
    }
}

SBufList
ToSBufList(wordlist *wl)
{
    SBufList rv;
    while (wl != NULL) {
        rv.push_back(SBuf(wl->key));
        wl = wl->next;
    }
    return rv;
}

char *
wordlistChopHead(wordlist **wl)
{
    if (*wl == nullptr)
        return nullptr;

    wordlist *w = *wl;
    char *rv = w->key;
    *wl = w->next;
    delete w;
    return rv;
}


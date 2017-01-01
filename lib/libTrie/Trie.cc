/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Trie.h"
#include "TrieCharTransform.h"
#include "TrieNode.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

Trie::Trie(TrieCharTransform *aTransform) : head(0) , transform(aTransform)
{}

Trie::~Trie()
{
    delete head;
    delete transform;
}

bool
Trie::add(char const *aString, size_t theLength, void *privatedata)
{
    if (!privatedata)
        return false;

    if (head) {
        if (find(aString, theLength))
            return false;

        return head->add(aString, theLength, privatedata, transform);
    }

    head = new TrieNode;

    return head->add(aString, theLength, privatedata, transform);
}


/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "TrieCharTransform.h"
#include "TrieNode.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

TrieNode::TrieNode() : _privateData(NULL)
{
    for (int i = 0; i < 256; ++i)
        internal[i] = NULL;
}

TrieNode::~TrieNode()
{
    for (int i = 0; i < 256; ++i)
        delete internal[i];
}

/* as for find */
bool
TrieNode::add(char const *aString, size_t theLength, void *privatedata, TrieCharTransform *transform)
{
    /* We trust that privatedata and existant keys have already been checked */

    if (theLength) {
        int index = transform ? (*transform)(*aString): *aString;

        if (!internal[index])
            internal[index] = new TrieNode;

        return internal[index]->add(aString + 1, theLength - 1, privatedata, transform);
    } else {
        /* terminal node */

        if (_privateData)
            return false;

        _privateData = privatedata;

        return true;
    }
}


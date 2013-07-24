/*
 * Copyright (c) 2002,2003 Robert Collins <rbtcollins@hotmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "TrieNode.h"
#include "TrieCharTransform.h"
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

#if !_USE_INLINE_
#include "TrieNode.cci"
#endif

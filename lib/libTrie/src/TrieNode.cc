/*
 * Copyright (c) 2002 Robert Collins <rbtcollins@hotmail.com>
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

#include "TrieNode.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>

TrieNode::TrieNode ()
{
    for (int i = 0; i < 256; ++i)
        internal[i] = NULL;
}

TrieNode::~TrieNode ()
{
    for (int i = 0; i < 256; ++i)
        delete internal[i];
}

/* as for find */
bool

TrieNode::add
    (char const *aString, size_t theLength, void *privatedata)
{
    /* We trust that privatedata and existant keys have already been checked */

    if (theLength) {
        int index;

        if (internal[*aString])
            index = *aString;
        else if (internal[tolower(*aString)])
            index = tolower (*aString);
        else {
            index = *aString;
            internal[index] = new TrieNode;
        }

        internal[index]->add
        (aString + 1, theLength - 1, privatedata);
    } else {
        /* terminal node */

        if (_privateData)
            return false;

        _privateData = privatedata;

        return true;
    }
}

#ifndef _USE_INLINE_
#include "TrieNode.cci"
#endif


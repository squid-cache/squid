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
#include "Trie.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "TrieNode.h"
#include "TrieCharTransform.h"

#if !_USE_INLINE_
#include "Trie.cci"
#endif

Trie::Trie(TrieCharTransform *aTransform) : head(0) , transform(aTransform)
{}

extern "C" void *TrieCreate()
{
    return new Trie;
}

Trie::~Trie()
{
    delete head;
    delete transform;
}

extern "C" void TrieDestroy(void *aTrie)
{
    delete (Trie *)aTrie;
}

extern "C" void *TrieFind(void *aTrie, char const *aString, size_t theLength)
{
    return ((Trie *)aTrie)->find(aString, theLength);
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

extern "C" int TrieAdd(void *aTrie, char const *aString, size_t theLength, void *privatedata)
{

    return ((Trie *)aTrie)->add(aString, theLength, privatedata);
}

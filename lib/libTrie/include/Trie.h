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

#ifndef   LIBTRIE_SQUID_H
#define   LIBTRIE_SQUID_H

/* This is the header for libTrie.
 * libTrie provides both C and C++ 
 * bindings. libtrie itself is written in C++.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/* C bindings */
#ifndef   __cplusplus

/* TODO: provide parameterisation for C bindings */
void *TrieCreate (void);
void TrieDestroy (void *);
void *TrieFind (void *, char const *, size_t);
int TrieAdd (void *, char const *, size_t, void *);

/* C++ bindings */
#else

/* MinGW needs NULL definition */
#ifndef NULL
#define NULL 0
#endif

class TrieCharTransform;

class TrieNode;

/* TODO: parameterize this to be more generic -
* i.e. M-ary internal node sizes etc
*/

class Trie
{

public:
    Trie(TrieCharTransform *aTransform = 0);
    ~Trie();
    Trie (Trie const &);
    Trie &operator= (Trie const &);

    /* Find an exact match in the trie.
    * If found, return the private data.
    * If not found, return NULL.
    */
    _SQUID_INLINE_ void *find (char const *, size_t);
    /* find any element of the trie in the buffer from the
    * beginning thereof
    */
    _SQUID_INLINE_ void *findPrefix (char const *, size_t);

    /* Add a string.
    * returns false if the string is already
    * present or cannot be added.
    */

    bool add
        (char const *, size_t, void *);

private:
    TrieNode *head;

    /* transfor each 8 bits in the element */
    TrieCharTransform *transform;
};

#endif /* __cplusplus */

#ifdef _USE_INLINE_
#include "Trie.cci"
#endif

#endif /* LIBTRIE_SQUID_H */

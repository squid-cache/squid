/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   LIBTRIE_TRIENODE_H
#define   LIBTRIE_TRIENODE_H

#include "TrieCharTransform.h"

#include <sys/types.h>
#include <utility>

/* TODO: parameterize this to be more generic -
* i.e. M-ary internal node sizes etc
*/

class TrieNode
{

public:
    TrieNode();
    ~TrieNode();
    TrieNode(TrieNode const &);
    TrieNode &operator= (TrieNode const &);

    /* Find a string.
    * If found, return the private data.
    * If not found, return NULL.
    */
    inline void *find (char const *, size_t, TrieCharTransform *, bool const prefix) const;

    /* Add a string.
    * returns false if the string is already
    * present or can't be added.
    */

    bool add (char const *, size_t, void *, TrieCharTransform *);

private:
    /* 256-way Trie */
    /* The char index into internal is an
    * 8-bit prefix to a string in the trie.
    * internal[0] is the terminal node for
    * a string and may not be used
    */
    TrieNode * internal[256];

    /* If a string ends here, non NULL */
    void *_privateData;
};

/* recursive. TODO? make iterative */
void *
TrieNode::find (char const *aString, size_t theLength, TrieCharTransform *transform, bool const prefix) const
{
    if (theLength) {
        int index = -1;
        unsigned char pos = transform ? (*transform) (*aString) : *aString;

        if (internal[pos])
            index = pos;

        if (index > -1) {
            void *result;
            result = internal[index]->find(aString + 1, theLength - 1, transform, prefix);

            if (result)
                return result;
        }

        if (prefix)
            return _privateData;

        return NULL;
    } else {
        /* terminal node */
        return _privateData;
    }
}
#endif /* LIBTRIE_TRIENODE_H */


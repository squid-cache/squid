/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   LIBTRIE_TRIECHARTRANSFORM_H
#define   LIBTRIE_TRIECHARTRANSFORM_H

/* This is an internal header for libTrie.
 * libTrie provides both limited C and full C++
 * bindings.
 * libTrie itself is written in C++.
 * For C bindings see Trie.h
 */

/* C bindings */
#ifndef   __cplusplus

/* C++ bindings */
#else
#include <sys/types.h>
#include <utility>
#include <ctype.h>

/* TODO: parameterize this to be more generic -
* i.e. M-ary internal node sizes etc
*/

class TrieCharTransform
{

public:
    virtual ~TrieCharTransform() {}

    virtual char operator () (char const) const = 0;
};

class TrieCaseless : public TrieCharTransform
{
    virtual char operator () (char const aChar) const {return tolower(aChar);}
};

#endif /* __cplusplus */

#endif /* LIBTRIE_TRIECHARTRANSFORM_H */


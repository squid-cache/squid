/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LIB_LIBTRIE_TRIECHARTRANSFORM_H
#define SQUID_LIB_LIBTRIE_TRIECHARTRANSFORM_H

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
#include <cctype>
#include <sys/types.h>
#include <utility>

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
    char operator () (char const aChar) const override {return tolower(aChar);}
};

#endif /* __cplusplus */

#endif /* SQUID_LIB_LIBTRIE_TRIECHARTRANSFORM_H */


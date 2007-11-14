/*
 * Copyright (c) 2003 Robert Collins <rbtcollins@hotmail.com>
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

#ifndef   LIBTRIE_TRIECHARTRANSFORM_H
#define   LIBTRIE_TRIECHARTRANSFORM_H

/* This is an internal header for libTrie.
 * libTrie provides both limited C and full C++ 
 * bindings. 
 * libTrie itself is written in C++.
 * For C bindings see Trie.h
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

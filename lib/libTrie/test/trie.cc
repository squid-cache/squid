/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "libTrie/Trie.h"
#include "libTrie/TrieCharTransform.h"

#include <iostream>

bool
CaseSensitiveCheck()
{
    Trie aTrie;

    if (!aTrie.add ("User-Agent", 10, (void *)1)) {
        std::cerr << "Could not add User-Agent" << std::endl;
        return 1;
    }

    if (aTrie.add ("User-Agent", 10, (void *)2)) {
        std::cerr << "Could add duplicate User-Agent" << std::endl;
        return 1;
    }

    if (!aTrie.add ("Alphabet", 8, (void *)3)) {
        std::cerr << "Could not add Alphabet" << std::endl;
        return 1;
    }

    if (!aTrie.add ("Uprefix", 8, (void *)3)) {
        std::cerr << "Could not add Uprefix" << std::endl;
        return 1;
    }

    if (aTrie.find ("User-Agent", 10) != (void *)1) {
        std::cerr << "Could not find User-Agent" << std::endl;
        return 1;
    }

    if (aTrie.find ("user-agent", 10) == (void *)1) {
        std::cerr << "found user-agent" << std::endl;
        return 1;
    }

    if (aTrie.findPrefix("User-AgentFoo" , 13) != (void *)1) {
        std::cerr << "Could not find User prefix" << std::endl;
        return 1;
    }

    if (aTrie.findPrefix("user-agentFoo" , 13) == (void *)1) {
        std::cerr << "found user prefix" << std::endl;
        return 1;
    }

    return 0;
}

bool
CaseInsensitiveCheck()
{
    Trie aTrie(new TrieCaseless);

    if (!aTrie.add ("User-Agent", 10, (void *)1)) {
        std::cerr << "Could not add User-Agent" << std::endl;
        return 1;
    }

    if (aTrie.add ("user-agent", 10, (void *)2)) {
        std::cerr << "Could add duplicate User-Agent" << std::endl;
        return 1;
    }

    if (!aTrie.add ("Alphabet", 8, (void *)3)) {
        std::cerr << "Could not add Alphabet" << std::endl;
        return 1;
    }

    if (!aTrie.add ("uprefix", 8, (void *)3)) {
        std::cerr << "Could not add uprefix" << std::endl;
        return 1;
    }

    if (aTrie.find ("User-Agent", 10) != (void *)1) {
        std::cerr << "Could not find User-Agent" << std::endl;
        return 1;
    }

    if (aTrie.find ("user-agent", 10) != (void *)1) {
        std::cerr << "Could not find user-agent" << std::endl;
        return 1;
    }

    if (aTrie.findPrefix("User-AgentFoo" , 13) != (void *)1) {
        std::cerr << "Could not find User prefix" << std::endl;
        return 1;
    }

    if (aTrie.findPrefix("user-agentFoo" , 13) != (void *)1) {
        std::cerr << "Could not find user prefix" << std::endl;
        return 1;
    }

    return 0;
}

int main (int argc, char **argv)
{
    if (CaseSensitiveCheck()) {
        std::cerr << "Case sensitive check failure." << std::endl;
        return 1;
    }

    if (CaseInsensitiveCheck()) {
        std::cerr << "Case in-sensitive check failure." << std::endl;
        return 1;
    }

    return 0;
}


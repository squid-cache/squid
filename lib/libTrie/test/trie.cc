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

#include "Trie.h"
#include "TrieCharTransform.h"
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

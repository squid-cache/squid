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

#include "Trie.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
    void *aTrie = TrieCreate();
    if (!TrieAdd (aTrie, "User-Agent", 10, (void *)1)) {
	fprintf(stderr,"Could not add User-Agent\n");
	return 1;
    }
    if (TrieAdd (aTrie, "User-Agent", 10, (void *)2)) {
	fprintf(stderr, "Could add duplicate User-Agent\n");
	return 1;
    }
    if (TrieFind (aTrie, "User-Agent", 10) != (void *)1) {
	fprintf(stderr, "Could not find User-Agent\n");
	return 1;
    }
    TrieDestroy (aTrie);
    return 0;
}

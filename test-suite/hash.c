
/*
 * $Id: hash.c,v 1.1 1998/02/27 07:17:22 kostas Exp $
 *
 * DEBUG: section 0     Hash Tables
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/time.h>
#include <strings.h>
#include "hash.h"
static int hash_unlink(hash_table *, hash_link *, int);

/*
 *  hash_url() - Returns a well-distributed hash function for URLs.
 *  The best way is to sum up the last half of the string.
 *  Adapted from code written by Mic Bowman.  -Darren
 *  Generates a standard deviation = 15.73
 */
unsigned int
hash_url(const void *data, unsigned int size)
{
    const char *s = data;
    unsigned int i, j, n;
    j = strlen(s);
    for (i = j / 2, n = 0; i < j; i++)
	n ^= 271 * (unsigned) s[i];
    i = n ^ (j * 271);
    return i % size;
}

unsigned int
hash_string(const void *data, unsigned int size)
{
    const char *s = data;
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
	j++;
	n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);
    return i % size;
}

/* the following 4 functions were adapted from
 *    usr/src/lib/libc/db/hash_func.c, 4.4 BSD lite */

/*
 * HASH FUNCTIONS
 *
 * Assume that we've already split the bucket to which this key hashes,
 * calculate that bucket, and check that in fact we did already split it.
 *
 * This came from ejb's hsearch.
 */

#define PRIME1		37
#define PRIME2		1048583

/* Hash function from Chris Torek. */
unsigned int
hash4(const void *data, unsigned int size)
{
    const char *key = data;
    size_t loop;
    unsigned int h;
    size_t len;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

    h = 0;
    len = strlen(key);
    loop = (len + 8 - 1) >> 3;
    switch (len & (8 - 1)) {
    case 0:
	do {
	    HASH4;
	    /* FALLTHROUGH */
    case 7:
	    HASH4;
	    /* FALLTHROUGH */
    case 6:
	    HASH4;
	    /* FALLTHROUGH */
    case 5:
	    HASH4;
	    /* FALLTHROUGH */
    case 4:
	    HASH4;
	    /* FALLTHROUGH */
    case 3:
	    HASH4;
	    /* FALLTHROUGH */
    case 2:
	    HASH4;
	    /* FALLTHROUGH */
    case 1:
	    HASH4;
	} while (--loop);
    }
    return h % size;
}

/*
 *  hash_create - creates a new hash table, uses the cmp_func
 *  to compare keys.  Returns the identification for the hash table;
 *  otherwise returns a negative number on error.
 */
hash_table *
hash_create(HASHCMP * cmp_func, int hash_sz, HASHHASH * hash_func)
{
    hash_table *hid = calloc(1, sizeof(hash_table));
    if (!hash_sz)
	hid->size = (unsigned int) DEFAULT_HASH_SIZE;
    else
	hid->size = (unsigned int) hash_sz;
    /* allocate and null the buckets */
    hid->buckets = calloc(hid->size, sizeof(hash_link *));
    hid->cmp = cmp_func;
    hid->hash = hash_func;
    hid->current_ptr = NULL;
    hid->current_slot = 0;
    return hid;
}

/*
 *  hash_insert - inserts the given item 'item' under the given key 'k'
 *  into the hash table 'hid'.  Returns non-zero on error; otherwise,
 *  returns 0 and inserts the item.
 *
 *  It does not copy any data into the hash table, only pointers.
 */
void
hash_insert(hash_table * hid, const char *k, void *item)
{
    int i;
    hash_link *new;
    assert(k != NULL);
    /* Add to the given hash table 'hid' */
    new = calloc(1, sizeof(hash_link));
    new->item = item;
    new->key = (char *) k;
    i = hid->hash(k, hid->size);
    new->next = hid->buckets[i];
    hid->buckets[i] = new;
}

/*
 *  hash_join - joins a hash_link under its key lnk->key
 *  into the hash table 'hid'.  
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
void
hash_join(hash_table * hid, hash_link * lnk)
{
    int i;
    i = hid->hash(lnk->key, hid->size);
    lnk->next = hid->buckets[i];
    hid->buckets[i] = lnk;
}

/*
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_lookup(hash_table * hid, const void *k)
{
    hash_link *walker;
    int b;
    assert(k != NULL);
    b = hid->hash(k, hid->size);
    for (walker = hid->buckets[b]; walker != NULL; walker = walker->next) {
	if ((hid->cmp) (k, walker->key) == 0)
	    return (walker);
	assert(walker != walker->next);
    }
    return NULL;
}

/*
 *  hash_first - returns the first item in the hash table 'hid'.
 *  Otherwise, returns NULL on error.
 */
hash_link *
hash_first(hash_table * hid)
{
    int i;

    for (i = 0; i < hid->size; i++) {
	hid->current_slot = i;
	if (hid->buckets[i] != NULL)
	    return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;
}

/*
 *  hash_next - returns the next item in the hash table 'hid'.
 *  Otherwise, returns NULL on error or end of list.  
 *
 *  MUST call hash_first() before hash_next().
 */
hash_link *
hash_next(hash_table * hid)
{
    int i;

    if (hid->current_ptr != NULL) {
	hid->current_ptr = hid->current_ptr->next;
	if (hid->current_ptr != NULL)
	    return (hid->current_ptr);	/* next item */
    }
    /* find next bucket */
    for (i = hid->current_slot + 1; i < hid->size; i++) {
	hid->current_slot = i;
	if (hid->buckets[i] != NULL)
	    return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;		/* end of list */
}

int
hash_delete(hash_table * hid, const char *key)
{
    return hash_delete_link(hid, hash_lookup(hid, key));
}

/*
 *  hash_delete_link - deletes the given hash_link node from the 
 *  hash table 'hid'. If FreeLink then free the given hash_link.
 *
 *  On success, it returns 0 and deletes the link; otherwise, 
 *  returns non-zero on error.
 */
static int
hash_unlink(hash_table * hid, hash_link * hl, int FreeLink)
{
    hash_link *walker, *prev;
    int i;
    if (hl == NULL)
	return -1;
    i = hid->hash(hl->key, hid->size);
    for (prev = NULL, walker = hid->buckets[i];
	walker != NULL; prev = walker, walker = walker->next) {
	if (walker == hl) {
	    if (prev == NULL) {	/* it's the head */
		hid->buckets[i] = walker->next;
	    } else {
		prev->next = walker->next;	/* skip it */
	    }
	    /* fix walker state if needed */
	    if (walker == hid->current_ptr)
		hid->current_ptr = walker->next;
	    if (FreeLink) {
		if (walker)
		free(walker);
	    }
	    return 0;
	}
    }
    return 1;
}

/* take link off and free link node */
int
hash_delete_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 1));
}

/* take link off only */
int
hash_remove_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 0));
}

/*
 *  hash_get_bucket - returns the head item of the bucket 
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_get_bucket(hash_table * hid, unsigned int bucket)
{
    if (bucket >= hid->size)
	return NULL;
    return (hid->buckets[bucket]);
}


void
hashFreeMemory(hash_table * hid)
{
	if (hid->buckets);
    free(hid->buckets);
	if (hid)
    free(hid);
}


#ifdef USE_HASH_DRIVER
/*
 *  hash-driver - Run with a big file as stdin to insert each line into the
 *  hash table, then prints the whole hash table, then deletes a random item,
 *  and prints the table again...
 */
int
main(void)
{
    hash_table *hid;
    int i;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    LOCAL_ARRAY(char, todelete, BUFSIZ);
    hash_link *walker = NULL;

    todelete[0] = '\0';
    printf("init\n");

    printf("creating hash table\n");
    if ((hid = hash_create(strcmp, 229, hash_string)) < 0) {
	printf("hash_create error.\n");
	exit(1);
    }
    printf("done creating hash table: %d\n", hid);

    while (fgets(buf, BUFSIZ, stdin)) {
	buf[strlen(buf) - 1] = '\0';
	printf("Inserting '%s' for item %p to hash table: %d\n",
	    buf, buf, hid);
	hash_insert(hid, xstrdup(buf), (void *) 0x12345678);
	if (random() % 17 == 0)
	    strcpy(todelete, buf);
    }

    printf("walking hash table...\n");
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
	printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
	    walker->item);
    }
    printf("done walking hash table...\n");

    if (todelete[0]) {
	printf("deleting %s from %d\n", todelete, hid);
	if (hash_delete(hid, todelete))
	    printf("hash_delete error\n");
    }
    printf("walking hash table...\n");
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
	printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
	    walker->item);
    }
    printf("done walking hash table...\n");


    printf("driver finished.\n");
    exit(0);
}
#endif
void assert(int a) {

}


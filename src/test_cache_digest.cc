/*
 * $Id: test_cache_digest.cc,v 1.1 1998/03/30 20:42:42 rousskov Exp $
 *
 * AUTHOR: Alex Rousskov
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
 * Test-suite for playing with cache digests
 */

#include "squid.h"

typedef struct {
    const char *name;
    hash_table *hash;
    CacheDigest *digest;
    int count;          /* #currently cached entries */
    int scanned_count;  /* #scanned entries */
    int bad_add_count;  /* #duplicate adds */
    int bad_del_count;  /* #dels with no prior add */
} CacheIndex;


typedef struct _CacheEntry {
    const cache_key *key;
    struct _CacheEntry *next;
    /* storeSwapLogData s; */
    unsigned char key_arr[MD5_DIGEST_CHARS];
} CacheEntry;


/* copied from url.c */
const char *RequestMethodStr[] =
{
    "NONE",
    "GET",
    "POST",
    "PUT",
    "HEAD",
    "CONNECT",
    "TRACE",
    "PURGE"
};


static int cacheIndexScanCleanPrefix(CacheIndex *idx, const char *fname, FILE *file);


static CacheEntry *
cacheEntryCreate(const storeSwapLogData *s)
{
    CacheEntry *e = xcalloc(1, sizeof(CacheEntry));
    assert(s);
    /* e->s = *s; */
    xmemcpy(e->key_arr, s->key, MD5_DIGEST_CHARS);
    e->key = &e->key_arr[0];
    return e;
}

static void
cacheEntryDestroy(CacheEntry *e)
{
    assert(e);
    xfree(e);
}

static CacheIndex *
cacheIndexCreate(const char *name)
{
    CacheIndex *idx;
    if (!name || !strlen(name))
	return NULL;

    idx = xcalloc(1, sizeof(CacheIndex));
    idx->name = name;
    idx->hash = hash_create(storeKeyHashCmp, 2e6, storeKeyHashHash);

    return idx;
}

static void
cacheIndexDestroy(CacheIndex *idx)
{
    hash_link *hashr = NULL;
    if (idx) {
	/* destroy hash list contents */
	for (hashr = hash_first(idx->hash); hashr; hashr = hash_next(idx->hash)) {
	    hash_remove_link(idx->hash, hashr);
	    cacheEntryDestroy((CacheEntry*)hashr);
	}
	/* destroy the hash table itself */
	hashFreeMemory(idx->hash);
	if (idx->digest)
	    cacheDigestDestroy(idx->digest);
	xfree(idx);
    }
}

/* makes digest based on currently hashed entries */
static void
cacheIndexInitDigest(CacheIndex *idx)
{
    hash_link *hashr = NULL;
    struct timeval t_start, t_end;
    assert(idx && !idx->digest);
    fprintf(stderr, "%s: init-ing digest with %d entries\n", idx->name, idx->count);
    idx->digest = cacheDigestCreate(idx->count); /* no "fat" */
    gettimeofday(&t_start, NULL);
    for (hashr = hash_first(idx->hash); hashr; hashr = hash_next(idx->hash)) {
	cacheDigestAdd(idx->digest, hashr->key);
    }
    gettimeofday(&t_end, NULL);
    assert(idx->digest->count == idx->count);
    fprintf(stderr, "%s: init-ed  digest with %d entries\n", 
	idx->name, idx->digest->count);
    fprintf(stderr, "%s: init took: %f sec, %f sec/M\n",
	idx->name,
	tvSubDsec(t_start, t_end),
	(double)1e6*tvSubDsec(t_start, t_end)/idx->count);
}

static int
cacheIndexAddLog(CacheIndex *idx, const char *fname)
{
    FILE *file;
    int scanned_count = 0;
    assert(idx);
    assert(fname && strlen(fname));

    file = fopen(fname, "r");
    if (!file) {
	fprintf(stderr, "cannot open %s: %s\n", fname, strerror(errno));
	return 0;
    }
    scanned_count = cacheIndexScanCleanPrefix(idx, fname, file);
    fclose(file);
    return scanned_count;
}

static void
cacheIndexInitReport(CacheIndex *idx)
{
    assert(idx);
    fprintf(stderr, "%s: bad swap_add:  %d\n",
	idx->name, idx->bad_add_count);
    fprintf(stderr, "%s: bad swap_del:  %d\n", 
	idx->name, idx->bad_del_count);
    fprintf(stderr, "%s: scanned lines: %d\n", 
	idx->name, idx->scanned_count);
}

#if 0
static int
cacheIndexGetLogEntry(CacheIndex *idx, storeSwapLogData *s)
{
    if (!idx->has_log_entry)
	cacheIndexStepLogEntry();
    if (idx->has_log_entry) {
	*s = idx->log_entry_buf;
	return 1;
    }
    return 0;
}

static int
cacheIndexStepLogEntry(CacheIndex *idx)
{
    if (fread(&idx->log_entry_buf, sizeof(idx->log_entry_buf), 1, idx->log) == 1) {
	int op = (int) idx->log_entry_buf.op;
	idx->scanned_count++;
	idx->has_log_entry = 1;
	if (op != SWAP_LOG_ADD && op != SWAP_LOG_DEL) {
	    fprintf(stderr, "%s:%d: unknown swap log action %d\n", idx->log_fname, idx->scanned_count, op);
	    exit(-3);
	}
    } else
	idx->has_log_entry = 0;
}

static int
cacheIndexScan(CacheIndex *idx, const char *fname, FILE *file)
{
    int count = 0;
    int del_count = 0;
    storeSwapLogData s;
    fprintf(stderr, "%s scanning\n", fname);
    while (fread(&s, sizeof(s), 1, file) == 1) {
	count++;
	idx->scanned_count++;
	if (s.op == SWAP_LOG_ADD) {
	    CacheEntry *olde = (CacheEntry *) hash_lookup(idx->hash, s.key);
	    if (olde) {
		idx->bad_add_count++;
	    } else {
		CacheEntry *e = cacheEntryCreate(&s);
		hash_join(idx->hash, (hash_link*) e);
		idx->count++;
	    }
	} else
	if (s.op == SWAP_LOG_DEL) {
	    CacheEntry *olde = (CacheEntry *) hash_lookup(idx->hash, s.key);
	    if (!olde)
		idx->bad_del_count++;
	    else {
		assert(idx->count);
		hash_remove_link(idx->hash, (hash_link*) olde);
		cacheEntryDestroy(olde);
		idx->count--;
	    }
	    del_count++;
	} else {
	    fprintf(stderr, "%s:%d: unknown swap log action\n", fname, count);
	    exit(-3);
	}
    }
    fprintf(stderr, "%s scanned %d entries, alloc: %d bytes\n",
	fname, count, 
	(int)(count*sizeof(CacheEntry)));
    return count;
}
#endif

static int
cacheIndexScanCleanPrefix(CacheIndex *idx, const char *fname, FILE *file)
{
    int count = 0;
    storeSwapLogData s;
    fprintf(stderr, "%s scanning\n", fname);
    while (fread(&s, sizeof(s), 1, file) == 1) {
	count++;
	idx->scanned_count++;
	if (s.op == SWAP_LOG_ADD) {
	    CacheEntry *olde = (CacheEntry *) hash_lookup(idx->hash, s.key);
	    if (olde) {
		idx->bad_add_count++;
	    } else {
		CacheEntry *e = cacheEntryCreate(&s);
		hash_join(idx->hash, (hash_link*) e);
		idx->count++;
	    }
	} else
	if (s.op == SWAP_LOG_DEL) {
	    break;
	} else {
	    fprintf(stderr, "%s:%d: unknown swap log action\n", fname, count);
	    exit(-3);
	}
    }
    fprintf(stderr, "%s scanned %d entries, alloc: %d bytes\n",
	fname, count, 
	(int)(count*sizeof(CacheEntry)));
    return count;
}

static int
usage(const char *prg_name)
{
    fprintf(stderr, "usage: %s <access_log> <swap_state> ...\n",
	prg_name);
    return -1;
}

int
main(int argc, char *argv[])
{
    CacheIndex *they = NULL;
    int i;

    if (argc < 3)
	return usage(argv[0]);

    they = cacheIndexCreate("they");
    for (i = 2; i < argc; ++i) {
	cacheIndexAddLog(they, argv[i]);
    }
    cacheIndexInitDigest(they);
    cacheIndexInitReport(they);

    cacheIndexDestroy(they);

    return 1;
}

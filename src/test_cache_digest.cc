/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Test-suite for playing with cache digests
 */

#include "squid.h"
#include "CacheDigest.h"
#include "store_key_md5.h"

#include <cerrno>

typedef struct {
    int query_count;
    int true_hit_count;
    int true_miss_count;
    int false_hit_count;
    int false_miss_count;
} CacheQueryStats;

typedef struct _Cache Cache;

struct _Cache {
    const char *name;
    hash_table *hash;
    CacheDigest *digest;
    Cache *peer;
    CacheQueryStats qstats;
    int count;          /* #currently cached entries */
    int req_count;      /* #requests to this cache */
    int bad_add_count;      /* #duplicate adds */
    int bad_del_count;      /* #dels with no prior add */
};

typedef struct _CacheEntry {
    const cache_key *key;

    struct _CacheEntry *next;
    unsigned char key_arr[SQUID_MD5_DIGEST_LENGTH];
    /* storeSwapLogData s; */
} CacheEntry;

/* parsed access log entry */

typedef struct {
    cache_key key[SQUID_MD5_DIGEST_LENGTH];
    time_t timestamp;
    short int use_icp;      /* true/false */
} RawAccessLogEntry;

typedef enum {
    frError = -2, frMore = -1, frEof = 0, frOk = 1
} fr_result;

typedef struct _FileIterator FileIterator;
typedef fr_result(*FI_READER) (FileIterator * fi);

struct _FileIterator {
    const char *fname;
    FILE *file;
    time_t inner_time;      /* timestamp of the current entry */
    time_t time_offset;     /* to adjust time set by reader */
    int line_count;     /* number of lines scanned */
    int bad_line_count;     /* number of parsing errors */
    int time_warp_count;    /* number of out-of-order entries in the file */
    FI_READER reader;       /* reads next entry and updates inner_time */
    void *entry;        /* buffer for the current entry, freed with xfree() */
};

/* globals */
static time_t cur_time = -1;    /* timestamp of the current log entry */

/* copied from url.c */
static HttpRequestMethod
methodStrToId(const char *s)
{
    if (strcasecmp(s, "GET") == 0) {
        return METHOD_GET;
    } else if (strcasecmp(s, "POST") == 0) {
        return METHOD_POST;
    } else if (strcasecmp(s, "PUT") == 0) {
        return METHOD_PUT;
    } else if (strcasecmp(s, "HEAD") == 0) {
        return METHOD_HEAD;
    } else if (strcasecmp(s, "CONNECT") == 0) {
        return METHOD_CONNECT;
    } else if (strcasecmp(s, "TRACE") == 0) {
        return METHOD_TRACE;
    } else if (strcasecmp(s, "PURGE") == 0) {
        return METHOD_PURGE;
    }

    return METHOD_NONE;
}

/* FileIterator */

static void fileIteratorAdvance(FileIterator * fi);

static FileIterator *
fileIteratorCreate(const char *fname, FI_READER reader)
{
    FileIterator *fi = (FileIterator *)xcalloc(1, sizeof(FileIterator));
    assert(fname && reader);
    fi->fname = fname;
    fi->reader = reader;
    fi->file = fopen(fname, "r");

    if (!fi->file) {
        fprintf(stderr, "cannot open %s: %s\n", fname, strerror(errno));
        return NULL;
    } else
        fprintf(stderr, "opened %s\n", fname);

    fileIteratorAdvance(fi);

    return fi;
}

static void
fileIteratorDestroy(FileIterator * fi)
{
    assert(fi);

    if (fi->file) {
        fclose(fi->file);
        fprintf(stderr, "closed %s\n", fi->fname);
    }

    xfree(fi->entry);
    xfree(fi);
}

static void
fileIteratorSetCurTime(FileIterator * fi, time_t ct)
{
    assert(fi);
    assert(fi->inner_time > 0);
    fi->time_offset = ct - fi->inner_time;
}

static void
fileIteratorAdvance(FileIterator * fi)
{
    int res;
    assert(fi);

    do {
        const time_t last_time = fi->inner_time;
        fi->inner_time = -1;
        res = fi->reader(fi);
        ++ fi->line_count;

        if (fi->inner_time < 0)
            fi->inner_time = last_time;
        else
            fi->inner_time += fi->time_offset;

        if (res == frError)
            ++ fi->bad_line_count;
        else if (res == frEof) {
            fprintf(stderr, "exhausted %s (%d entries) at %s",
                    fi->fname, fi->line_count, ctime(&fi->inner_time));
            fi->inner_time = -1;
        } else if (fi->inner_time < last_time) {
            assert(last_time >= 0);
            ++ fi->time_warp_count;
            fi->inner_time = last_time;
        }

        /* report progress */
        if (!(fi->line_count % 50000))
            fprintf(stderr, "%s scanned %d K entries (%d bad) at %s",
                    fi->fname, fi->line_count / 1000, fi->bad_line_count,
                    ctime(&fi->inner_time));
    } while (res < 0);
}

/* CacheEntry */

static CacheEntry *
cacheEntryCreate(const storeSwapLogData * s)
{
    CacheEntry *e = (CacheEntry *)xcalloc(1, sizeof(CacheEntry));
    assert(s);
    /* e->s = *s; */
    memcpy(e->key_arr, s->key, SQUID_MD5_DIGEST_LENGTH);
    e->key = &e->key_arr[0];
    return e;
}

static void
cacheEntryDestroy(CacheEntry * e)
{
    assert(e);
    xfree(e);
}

/* Cache */

static Cache *
cacheCreate(const char *name)
{
    Cache *c;
    assert(name && strlen(name));
    c = (Cache *)xcalloc(1, sizeof(Cache));
    c->name = name;
    c->hash = hash_create(storeKeyHashCmp, (int)2e6, storeKeyHashHash);
    return c;
}

static void
cacheDestroy(Cache * cache)
{
    CacheEntry *e = NULL;
    hash_table *hash;
    assert(cache);
    hash = cache->hash;
    /* destroy hash table contents */
    hash_first(hash);

    while ((e = (CacheEntry *)hash_next(hash))) {
        hash_remove_link(hash, (hash_link *) e);
        cacheEntryDestroy(e);
    }

    /* destroy the hash table itself */
    hashFreeMemory(hash);

    delete cache->digest;
    xfree(cache);
}

/* re-digests currently hashed entries */
static void
cacheResetDigest(Cache * cache)
{
    CacheEntry *e = NULL;
    hash_table *hash;

    struct timeval t_start, t_end;

    assert(cache);
    fprintf(stderr, "%s: init-ing digest with %d entries\n", cache->name, cache->count);

    hash = cache->hash;

    delete cache->digest;
    cache->digest = new CacheDigest(cache->count + 1, 6);

    if (!cache->count)
        return;

    gettimeofday(&t_start, NULL);

    hash_first(hash);

    while ((e = (CacheEntry *)hash_next(hash))) {
        cache->digest->add(e->key);
    }

    gettimeofday(&t_end, NULL);
    assert(cache->digest->count == cache->count);
    fprintf(stderr, "%s: init-ed  digest with %d entries\n",
            cache->name, cache->digest->count);
    fprintf(stderr, "%s: init took: %f sec, %f sec/M\n",
            cache->name,
            tvSubDsec(t_start, t_end),
            (double) 1e6 * tvSubDsec(t_start, t_end) / cache->count);
    /* check how long it takes to traverse the hash */
    gettimeofday(&t_start, NULL);
    hash_first(hash);

    for (e = (CacheEntry *)hash_next(hash); e; e = (CacheEntry *)hash_next(hash)) {}

    gettimeofday(&t_end, NULL);
    fprintf(stderr, "%s: hash scan took: %f sec, %f sec/M\n",
            cache->name,
            tvSubDsec(t_start, t_end),
            (double) 1e6 * tvSubDsec(t_start, t_end) / cache->count);
}

static void
cacheQueryPeer(Cache * cache, const cache_key * key)
{
    const int peer_has_it = hash_lookup(cache->peer->hash, key) != NULL;
    const int we_think_we_have_it = cache->digest->test(key);

    ++ cache->qstats.query_count;

    if (peer_has_it) {
        if (we_think_we_have_it)
            ++ cache->qstats.true_hit_count;
        else
            ++ cache->qstats.false_miss_count;
    } else {
        if (we_think_we_have_it)
            ++ cache->qstats.false_hit_count;
        else
            ++ cache->qstats.true_miss_count;
    }
}

static void
cacheQueryReport(Cache * cache, CacheQueryStats * stats)
{
    fprintf(stdout, "%s: peer queries: %d (%d%%)\n",
            cache->name,
            stats->query_count, xpercentInt(stats->query_count, cache->req_count)
           );
    fprintf(stdout, "%s: t-hit: %d (%d%%) t-miss: %d (%d%%) t-*: %d (%d%%)\n",
            cache->name,
            stats->true_hit_count, xpercentInt(stats->true_hit_count, stats->query_count),
            stats->true_miss_count, xpercentInt(stats->true_miss_count, stats->query_count),
            stats->true_hit_count + stats->true_miss_count,
            xpercentInt(stats->true_hit_count + stats->true_miss_count, stats->query_count)
           );
    fprintf(stdout, "%s: f-hit: %d (%d%%) f-miss: %d (%d%%) f-*: %d (%d%%)\n",
            cache->name,
            stats->false_hit_count, xpercentInt(stats->false_hit_count, stats->query_count),
            stats->false_miss_count, xpercentInt(stats->false_miss_count, stats->query_count),
            stats->false_hit_count + stats->false_miss_count,
            xpercentInt(stats->false_hit_count + stats->false_miss_count, stats->query_count)
           );
}

static void
cacheReport(Cache * cache)
{
    fprintf(stdout, "%s: entries: %d reqs: %d bad-add: %d bad-del: %d\n",
            cache->name, cache->count, cache->req_count,
            cache->bad_add_count, cache->bad_del_count);

}

static void
cacheFetch(Cache * cache, const RawAccessLogEntry * e)
{
    assert(e);
    ++ cache->req_count;

    if (e->use_icp)
        cacheQueryPeer(cache, e->key);
}

static fr_result
swapStateReader(FileIterator * fi)
{
    storeSwapLogData *entry;

    if (!fi->entry)
        fi->entry = xcalloc(1, sizeof(storeSwapLogData));

    entry = (storeSwapLogData *)fi->entry;

    if (fread(entry, sizeof(*entry), 1, fi->file) != 1)
        return frEof;

    fi->inner_time = entry->lastref;

    if (entry->op != SWAP_LOG_ADD && entry->op != SWAP_LOG_DEL) {
        fprintf(stderr, "%s:%d: unknown swap log action\n", fi->fname, fi->line_count);
        exit(-3);
    }

    return frOk;
}

static fr_result
accessLogReader(FileIterator * fi)
{
    static char buf[4096];
    RawAccessLogEntry *entry;
    char *url;
    char *method;
    HttpRequestMethod method_id = METHOD_NONE;
    char *hier = NULL;

    assert(fi);

    if (!fi->entry)
        fi->entry = xcalloc(1, sizeof(RawAccessLogEntry));
    else
        memset(fi->entry, 0, sizeof(RawAccessLogEntry));

    entry = (RawAccessLogEntry*)fi->entry;

    if (!fgets(buf, sizeof(buf), fi->file))
        return frEof;       /* eof */

    entry->timestamp = fi->inner_time = (time_t) atoi(buf);

    url = strstr(buf, "://");

    hier = url ? strstr(url, " - ") : NULL;

    if (!url || !hier) {
        /*fprintf(stderr, "%s:%d: strange access log entry '%s'\n",
         * fname, scanned_count, buf); */
        return frError;
    }

    method = url;

    while (!xisdigit(*method)) {
        if (*method == ' ')
            *method = '\0';

        --method;
    }

    method += 2;
    method_id = methodStrToId(method);

    if (method_id == METHOD_NONE) {
        /*fprintf(stderr, "%s:%d: invalid method %s in '%s'\n",
         * fname, scanned_count, method, buf); */
        return frError;
    }

    while (*url)
        --url;

    ++url;

    *hier = '\0';

    hier += 3;

    *strchr(hier, '/') = '\0';

    /*fprintf(stdout, "%s:%d: %s %s %s\n",
     * fname, count, method, url, hier); */
    entry->use_icp = strcmp(hier, "NONE");

    /* no ICP lookup for these status codes */
    /*      strcmp(hier, "NONE") &&
     * strcmp(hier, "DIRECT") &&
     * strcmp(hier, "FIREWALL_IP_DIRECT") &&
     * strcmp(hier, "LOCAL_IP_DIRECT") &&
     * strcmp(hier, "NO_DIRECT_FAIL") &&
     * strcmp(hier, "NO_PARENT_DIRECT") &&
     * strcmp(hier, "SINGLE_PARENT") &&
     * strcmp(hier, "PASSTHROUGH_PARENT") &&
     * strcmp(hier, "SSL_PARENT_MISS") &&
     * strcmp(hier, "DEFAULT_PARENT");
     */
    memcpy(entry->key, storeKeyPublic(url, method_id), sizeof(entry->key));

    /*fprintf(stdout, "%s:%d: %s %s %s %s\n",
     * fname, count, method, storeKeyText(entry->key), url, hier); */
    return frOk;
}

static void
cachePurge(Cache * cache, storeSwapLogData * s, int update_digest)
{
    CacheEntry *olde = (CacheEntry *) hash_lookup(cache->hash, s->key);

    if (!olde) {
        ++ cache->bad_del_count;
    } else {
        assert(cache->count);
        hash_remove_link(cache->hash, (hash_link *) olde);

        if (update_digest)
            cache->digest->remove(s->key);

        cacheEntryDestroy(olde);

        -- cache->count;
    }
}

static void
cacheStore(Cache * cache, storeSwapLogData * s, int update_digest)
{
    CacheEntry *olde = (CacheEntry *) hash_lookup(cache->hash, s->key);

    if (olde) {
        ++ cache->bad_add_count;
    } else {
        CacheEntry *e = cacheEntryCreate(s);
        hash_join(cache->hash, (hash_link *)&e->key);
        ++ cache->count;

        if (update_digest)
            cache->digest->add(e->key);
    }
}

static void
cacheUpdateStore(Cache * cache, storeSwapLogData * s, int update_digest)
{
    switch (s->op) {

    case SWAP_LOG_ADD:
        cacheStore(cache, s, update_digest);
        break;

    case SWAP_LOG_DEL:
        cachePurge(cache, s, update_digest);
        break;

    default:
        assert(0);
    }
}

static int
usage(const char *prg_name)
{
    fprintf(stderr, "usage: %s <access_log> <swap_state> ...\n",
            prg_name);
    return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
    FileIterator **fis = NULL;
    const int fi_count = argc - 1;
    int active_fi_count = 0;
    time_t ready_time;
    Cache *them, *us;
    int i;

    if (argc < 3)
        return usage(argv[0]);

    them = cacheCreate("them");

    us = cacheCreate("us");

    them->peer = us;

    us->peer = them;

    fis = (FileIterator **)xcalloc(fi_count, sizeof(FileIterator *));

    /* init iterators with files */
    fis[0] = fileIteratorCreate(argv[1], accessLogReader);

    for (i = 2; i < argc; ++i)
        fis[i - 1] = fileIteratorCreate(argv[i], swapStateReader);

    /* check that all files were found */
    for (i = 0; i < fi_count; ++i)
        if (!fis[i])
            return -2;

    /* read prefix to get start-up contents of the peer cache */
    ready_time = -1;

    for (i = 1; i < fi_count; ++i) {
        FileIterator *fi = fis[i];

        while (fi->inner_time > 0) {
            if (((storeSwapLogData *) fi->entry)->op == SWAP_LOG_DEL) {
                cachePurge(them, (storeSwapLogData *)fi->entry, 0);

                if (ready_time < 0)
                    ready_time = fi->inner_time;
            } else {
                if (ready_time > 0 && fi->inner_time > ready_time)
                    break;

                cacheStore(them, (storeSwapLogData *)fi->entry, 0);
            }

            fileIteratorAdvance(fi);
        }
    }

    /* digest peer cache content */
    cacheResetDigest(them);

    us->digest = them->digest->clone();

    /* shift the time in access log to match ready_time */
    fileIteratorSetCurTime(fis[0], ready_time);

    /* iterate, use the iterator with the smallest positive inner_time */
    cur_time = -1;

    do {
        int next_i = -1;
        time_t next_time = -1;
        active_fi_count = 0;

        for (i = 0; i < fi_count; ++i) {
            if (fis[i]->inner_time >= 0) {
                if (!active_fi_count || fis[i]->inner_time < next_time) {
                    next_i = i;
                    next_time = fis[i]->inner_time;
                }

                ++active_fi_count;
            }
        }

        if (next_i >= 0) {
            cur_time = next_time;
            /*fprintf(stderr, "%2d time: %d %s", next_i, (int)cur_time, ctime(&cur_time)); */

            if (next_i == 0)
                cacheFetch(us, (RawAccessLogEntry *)fis[next_i]->entry);
            else
                cacheUpdateStore(them, (storeSwapLogData *)fis[next_i]->entry, 1);

            fileIteratorAdvance(fis[next_i]);
        }
    } while (active_fi_count);

    /* report */
    cacheReport(them);

    cacheReport(us);

    cacheQueryReport(us, &us->qstats);

    /* clean */
    for (i = 0; i < argc - 1; ++i) {
        fileIteratorDestroy(fis[i]);
    }

    xfree(fis);
    cacheDestroy(them);
    cacheDestroy(us);
    return EXIT_SUCCESS;
}


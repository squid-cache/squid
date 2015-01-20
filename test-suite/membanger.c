/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "hash.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

static hash_table *mem_table = NULL;
static hash_link *mem_entry;
struct rusage myusage;

#ifdef WITH_LIB
#include "Mem.h"
#include <assert.h>
extern void sizeToPoolInit();
extern MemPool *sizeToPool(size_t size);
#endif
extern char *malloc_options;
void my_free(char *, int, void *);

FILE *fp;
char *fn;
int initsiz;
int maxsiz;
int minchunk;
HASHCMP ptrcmp;
char mbuf[256];
char abuf[32];
char *p;

int size;
void *addr;
int amt;

int i;
int a;
int run_stats = 0;
void *my_xmalloc(size_t);
void *my_xcalloc(int, size_t);
int my_xfree(void *);

#define xmalloc my_xmalloc
#define xcalloc my_xcalloc
#define xfree my_xfree

int *size2id_array[2];
int size2id_len = 0;
int size2id_alloc = 0;

typedef struct {
    char orig_ptr[32];
    void *my_ptr;
#ifdef WITH_LIB
    MemPool *pool;
#endif
    int size;
} memitem;

struct {
    int mallocs, frees, callocs, reallocs;
} mstat;

memitem *mi;
void size2id(size_t, memitem *);
void badformat();
void init_stats(), print_stats();
void my_hash_insert(hash_table * h, const char *k, memitem * item);
static void *xmemAlloc(memitem * item);
static void xmemFree(memitem * item);

int
ptrcmp(const void *a, const void *b)
{
    return (strcmp(a, b));
}

main(int argc, char **argv)
{
    char c;
    extern char *optarg;
    malloc_options = "A";
    a = 0;
    while ((c = getopt(argc, argv, "f:i:M:l:m:r:N")) != -1) {
        switch (c) {
        case 'N':
            mem_pools_on = 0;
            break;
        case 'r':
            run_stats = atoi(optarg);
            break;
        case 'f':
            fn = xstrdup(optarg);
            fp = fopen(fn, "r");
            break;
        case 'i':
            initsiz = atoi(optarg);
            break;
        case 'l':
            mem_max_size = atoi(optarg) * 1024 * 1024;
            break;
        case 'M':
            maxsiz = atoi(optarg);
            break;
        case 'm':
            minchunk = atoi(optarg);
            break;
        default:
            fprintf(stderr,
                    "Usage: %s -f file -M maxsiz -i initsiz -m minchunk", argv[0]);
            exit(1);
        }

    }
    if (!fp) {
        fprintf(stderr,
                "%s pummels %s\n%s . o O ( You't supply a valid tracefile.)\n",
                argv[0], getenv("USER"), argv[0]);
        exit(1);
    }
#ifdef WITH_LIB
    sizeToPoolInit();
#endif
    mem_table = hash_create(ptrcmp, 229, hash4);    /* small hash table */
    init_stats();
    while (fgets(mbuf, 256, fp) != NULL) {
        if (run_stats > 0 && (++a) % run_stats == 0)
            print_stats();
        p = NULL;
        switch (mbuf[0]) {
        case 'm':       /* malloc */
            p = strtok(&mbuf[2], ":");
            if (!p)
                badformat();
            size = atoi(p);
            p = strtok(NULL, "\n");
            if (!p)
                badformat();
            mi = malloc(sizeof(memitem));
            strcpy(mi->orig_ptr, p);
            mi->size = size;
            size2id(size, mi);
            mi->my_ptr = xmemAlloc(mi);     /* (void *)xmalloc(size); */
            assert(mi->my_ptr);
            my_hash_insert(mem_table, mi->orig_ptr, mi);
            mstat.mallocs++;
            break;
        case 'c':       /* calloc */
            p = strtok(&mbuf[2], ":");
            if (!p)
                badformat();
            amt = atoi(p);
            p = strtok(NULL, ":");
            if (!p)
                badformat();
            size = atoi(p);
            p = strtok(NULL, "\n");
            if (!p)
                badformat();
            mi = malloc(sizeof(memitem));
            strcpy(mi->orig_ptr, p);
            size2id(size, mi);
            mi->size = amt * size;
            mi->my_ptr = xmemAlloc(mi);     /*(void *)xmalloc(amt*size); */
            assert(mi->my_ptr);
            my_hash_insert(mem_table, mi->orig_ptr, mi);
            mstat.callocs++;
            break;
        case 'r':
            p = strtok(&mbuf[2], ":");
            if (!p)
                badformat();
            strcpy(abuf, p);
            p = strtok(NULL, ":");
            if (!p)
                badformat();
            mem_entry = hash_lookup(mem_table, p);
            if (mem_entry == NULL) {
                fprintf(stderr, "invalid realloc (%s)!\n", p);
                break;
            }
            mi = (memitem *) (mem_entry->item);
            assert(mi->pool);
            assert(mi->my_ptr);
            xmemFree(mi);   /* xfree(mi->my_ptr); */
            size2id(atoi(p), mi);   /* we don't need it here I guess? */
            strcpy(mi->orig_ptr, abuf);
            p = strtok(NULL, "\n");
            if (!p)
                badformat();
            mi->my_ptr = xmemAlloc(mi);     /* (char *)xmalloc(atoi(p)); */
            assert(mi->my_ptr);
            mstat.reallocs++;
            break;
        case 'f':
            p = strtok(&mbuf[2], "\n");
            mem_entry = hash_lookup(mem_table, p);
            if (mem_entry == NULL) {
                if (p[0] != '0')
                    fprintf(stderr, "invalid free (%s) at line %d!\n", p, a);
                break;
            }
            mi = (memitem *) (mem_entry->item);
            assert(mi->pool);
            assert(mi->my_ptr);
            xmemFree(mi);   /* xfree(mi->my_ptr); */
            hash_unlink(mem_table, mem_entry, 1);
            free(mi);
            mstat.frees++;
            break;
        default:
            fprintf(stderr, "%s pummels %s.bad.format\n", argv[0], fn);
            exit(1);
        }

    }
    fclose(fp);
    print_stats();
}

void *
my_xmalloc(size_t a)
{
    return NULL;
}

void *
my_xcalloc(int a, size_t b)
{
    return NULL;
}

int
my_xfree(void *p)
{
    return 0;
}
void
init_stats()
{

}

void
print_stats()
{
#ifdef WITH_LIB
    memReport(stdout);
#endif
    getrusage(RUSAGE_SELF, &myusage);
    printf("m/c/f/r=%d/%d/%d/%d\n", mstat.mallocs, mstat.callocs,
           mstat.frees, mstat.reallocs);
#if 0
    printf("types                 : %d\n", size2id_len);
#endif
    printf("user time used        : %d.%d\n", (int) myusage.ru_utime.tv_sec,
           (int) myusage.ru_utime.tv_usec);
    printf("system time used      : %d.%d\n", (int) myusage.ru_stime.tv_sec,
           (int) myusage.ru_stime.tv_usec);
    printf("max resident set size : %d\n", (int) myusage.ru_maxrss);
    printf("page faults           : %d\n", (int) myusage.ru_majflt);
}

void
size2id(size_t sz, memitem * mi)
{
#ifdef WITH_LIB
    mi->pool = sizeToPool(sz);
    assert(mi->pool);
#endif
    return;
}

void
badformat()
{
    fprintf(stderr, "pummel.bad.format\n");
    exit(1);
}

/* unused code, saved for parts */
const char *
make_nam(int id, int size)
{
    const char *buf = malloc(30);   /* argh */
    snprintf((char *)buf, sizeof(buf)-1, "pl:%d/%d", id, size);
    return buf;
}

void
my_hash_insert(hash_table * h, const char *k, memitem * item)
{
    memitem *l;
    assert(item->pool);
    assert(item->my_ptr);
    hash_insert(h, k, item);
}

static void *
xmemAlloc(memitem * item)
{
    extern MemPool *StringPool;
    assert(item && item->pool);
    if (StringPool == item->pool)
        return memStringAlloc(item->pool, item->size);
    else
        return memAlloc(item->pool);
}

static void
xmemFree(memitem * item)
{
    extern MemPool *StringPool;
    assert(item && item->pool);
    if (StringPool == item->pool)
        return memStringFree(item->pool, item->my_ptr, item->size);
    else
        return memFree(item->pool, item->my_ptr);
}

void
my_free(char *file, int line, void *ptr)
{
#if 0
    fprintf(stderr, "{%s:%d:%p", file, line, ptr);
#endif
    free(ptr);
#if 0
    fprintf(stderr, "}\n");
#endif
}


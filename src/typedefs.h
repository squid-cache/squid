/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "enums.h"

#ifndef SQUID_TYPEDEFS_H
#define SQUID_TYPEDEFS_H

typedef struct {
    size_t bytes;
    size_t kb;
} kb_t;

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);    /* disk write CB */

#include "anyp/ProtocolType.h"
class CachePeer;
typedef void IRCB(CachePeer *, peer_t, AnyP::ProtocolType, void *, void *data);

/* in wordlist.h */

class wordlist;
typedef void UH(void *data, wordlist *);

/**
 * READ_HANDLER functions return < 0 if, and only if, they fail with an error.
 * On error, they must pass back an error code in 'errno'.
 */
typedef int READ_HANDLER(int, char *, int);


typedef int QS(const void *, const void *); /* qsort */
typedef void STABH(void *);
class StoreEntry;

/* MD5 cache keys */
typedef unsigned char cache_key;

/*Use uint64_t to store miliseconds*/
typedef uint64_t time_msec_t;
#endif /* SQUID_TYPEDEFS_H */


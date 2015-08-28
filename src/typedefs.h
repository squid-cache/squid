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

typedef int32_t sfileno;
typedef signed int sdirno;

typedef uint32_t nfmark_t;
typedef unsigned char tos_t;

typedef struct {
    size_t bytes;
    size_t kb;
} kb_t;

typedef struct _CommWriteStateData CommWriteStateData;

#if SQUID_SNMP
#include "cache_snmp.h"
typedef variable_list *(oid_ParseFn) (variable_list *, snint *);
#endif

typedef void FREE(void *);
typedef void PF(int, void *);

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);    /* disk write CB */

namespace Dns
{
class LookupDetails;
}
typedef void FQDNH(const char *, const Dns::LookupDetails &details, void *);

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

/* in case we want to change it later */
typedef ssize_t mb_size_t;

/*Use uint64_t to store miliseconds*/
typedef uint64_t time_msec_t;
#endif /* SQUID_TYPEDEFS_H */


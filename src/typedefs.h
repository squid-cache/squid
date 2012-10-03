/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "enums.h"
#include "rfc1035.h"

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
#include "snmp_vars.h"
#include "cache_snmp.h"
typedef variable_list *(oid_ParseFn) (variable_list *, snint *);
#endif

typedef void FREE(void *);
typedef void CBDUNL(void *);
typedef void FOCB(void *, int fd, int errcode);
typedef void PF(int, void *);

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);	/* disk write CB */
typedef void DOCB(int, int errflag, void *data);	/* disk open CB */
typedef void DCCB(int, int errflag, void *data);	/* disk close CB */
typedef void DUCB(int errflag, void *data);	/* disk unlink CB */
typedef void DTCB(int errflag, void *data);	/* disk trunc CB */

class DnsLookupDetails;
typedef void FQDNH(const char *, const DnsLookupDetails &details, void *);
typedef void IDCB(const char *ident, void *data);

#include "anyp/ProtocolType.h"
class CachePeer;
typedef void IRCB(CachePeer *, peer_t, AnyP::ProtocolType, void *, void *data);

typedef void RH(void *data, char *);
/* in wordlist.h */

class wordlist;
typedef void UH(void *data, wordlist *);
typedef int READ_HANDLER(int, char *, int);
typedef int WRITE_HANDLER(int, const char *, int);

typedef int QS(const void *, const void *);	/* qsort */
typedef void STABH(void *);
typedef void ERCB(int fd, void *, size_t);
class StoreEntry;
typedef void OBJH(StoreEntry *);
typedef void SIGHDLR(int sig);
typedef void STVLDCB(void *, int, int);
typedef void HLPCB(void *, char *buf);
typedef int HLPSAVAIL(void *);
typedef void HLPSONEQ(void *);
typedef void HLPCMDOPTS(int *argc, char **argv);
typedef void IDNSCB(void *, const rfc1035_rr *, int, const char *);

/* MD5 cache keys */
typedef unsigned char cache_key;

/* in case we want to change it later */
typedef ssize_t mb_size_t;

typedef int STDIRSELECT(const StoreEntry *);

/*Use uint64_t to store miliseconds*/
typedef uint64_t time_msec_t;
#endif /* SQUID_TYPEDEFS_H */

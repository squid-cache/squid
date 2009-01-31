
/*
 * $Id$
 *
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

#ifndef   SQUID_PEERDIGEST_H
#define   SQUID_PEERDIGEST_H

#include "squid.h"

#if USE_CACHE_DIGESTS

#include "cbdata.h"

struct _Version {
    short int current;		/* current version */
    short int required;		/* minimal version that can safely handle current version */
};

/* digest control block; used for transmission and storage */

class StoreDigestCBlock
{
public:
    Version ver;
    int capacity;
    int count;
    int del_count;
    int mask_size;
    unsigned char bits_per_entry;
    unsigned char hash_func_count;
    short int reserved_short;
    int reserved[32 - 6];
};

struct _DigestFetchState {
    PeerDigest *pd;
    StoreEntry *entry;
    StoreEntry *old_entry;
    store_client *sc;
    store_client *old_sc;
    HttpRequest *request;
    int offset;
    int mask_offset;
    time_t start_time;
    time_t resp_time;
    time_t expires;

    struct {
        int msg;
        int bytes;
    }

    sent, recv;
    char buf[SM_PAGE_SIZE];
    ssize_t bufofs;
    digest_read_state_t state;
};

class PeerDigest
{

public:
    void *operator new (size_t);
    void operator delete(void *);

    struct peer *peer;          /**< pointer back to peer structure, argh */
    CacheDigest *cd;            /**< actual digest structure */
    String host;                /**< copy of peer->host */
    const char *req_result;     /**< text status of the last request */

    struct {
        unsigned int needed:1;          /**< there were requests for this digest */
        unsigned int usable:1;          /**< can be used for lookups */
        unsigned int requested:1;       /**< in process of receiving [fresh] digest */
    } flags;

    struct {
        /* all times are absolute unless augmented with _delay */
        time_t initialized;	/* creation */
        time_t needed;		/* first lookup/use by a peer */
        time_t next_check;	/* next scheduled check/refresh event */
        time_t retry_delay;	/* delay before re-checking _invalid_ digest */
        time_t requested;	/* requested a fresh copy of a digest */
        time_t req_delay;	/* last request response time */
        time_t received;	/* received the current copy of a digest */
        time_t disabled;	/* disabled for good */
    } times;

    struct {
        cd_guess_stats guess;
        int used_count;

        struct {
            int msgs;
            kb_t kbytes;
        } sent, recv;
    } stats;

private:
    CBDATA_CLASS(PeerDigest);
};

extern const Version CacheDigestVer;

#endif /* USE_CACHE_DIGESTS */

#endif /* SQUID_PEERDIGEST_H */

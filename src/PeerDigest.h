/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_PEERDIGEST_H
#define   SQUID_PEERDIGEST_H

#if USE_CACHE_DIGESTS

#include "cbdata.h"
/* for CacheDigestGuessStats */
#include "StatCounters.h"

class Version
{
public:
    short int current;      /* current version */
    short int required;     /* minimal version that can safely handle current version */
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

class HttpRequest;
class PeerDigest;
class store_client;

class DigestFetchState
{
public:
    PeerDigest *pd;
    StoreEntry *entry;
    StoreEntry *old_entry;
    store_client *sc;
    store_client *old_sc;
    HttpRequest *request;
    int offset;
    uint32_t mask_offset;
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
    CachePeer *peer;          /**< pointer back to peer structure, argh */
    CacheDigest *cd;            /**< actual digest structure */
    String host;                /**< copy of peer->host */
    const char *req_result;     /**< text status of the last request */

    struct {
        bool needed;          /**< there were requests for this digest */
        bool usable;          /**< can be used for lookups */
        bool requested;       /**< in process of receiving [fresh] digest */
    } flags;

    struct {
        /* all times are absolute unless augmented with _delay */
        time_t initialized; /* creation */
        time_t needed;      /* first lookup/use by a peer */
        time_t next_check;  /* next scheduled check/refresh event */
        time_t retry_delay; /* delay before re-checking _invalid_ digest */
        time_t requested;   /* requested a fresh copy of a digest */
        time_t req_delay;   /* last request response time */
        time_t received;    /* received the current copy of a digest */
        time_t disabled;    /* disabled for good */
    } times;

    struct {
        CacheDigestGuessStats guess;
        int used_count;

        struct {
            int msgs;
            kb_t kbytes;
        } sent, recv;
    } stats;

private:
    CBDATA_CLASS2(PeerDigest);
};

extern const Version CacheDigestVer;

PeerDigest *peerDigestCreate(CachePeer * p);
void peerDigestNeeded(PeerDigest * pd);
void peerDigestNotePeerGone(PeerDigest * pd);
void peerDigestStatsReport(const PeerDigest * pd, StoreEntry * e);

#endif /* USE_CACHE_DIGESTS */

#endif /* SQUID_PEERDIGEST_H */


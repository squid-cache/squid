
/*
 * $Id: MemObject.h,v 1.4 2003/03/04 01:40:25 robertc Exp $
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

#ifndef SQUID_MEMOBJECT_H
#define SQUID_MEMOBJECT_H

#include "StoreIOBuffer.h"
#include "stmem.h"
#include "CommRead.h"

typedef void STMCB (void *data, StoreIOBuffer wroteBuffer);

class store_client;
#if DELAY_POOLS
#include "DelayId.h"
#endif

class MemObject
{

public:
    static size_t inUseCount();

    void dump() const;
    void *operator new (size_t);
    void operator delete (void *);
    MemObject(char const *, char const *);
    ~MemObject();

    void write(StoreIOBuffer, STMCB *, void *);
    void unlinkRequest();
    HttpReply const *getReply() const;
    void stat (StoreEntry *s) const;
    off_t endOffset () const;
    size_t size() const;
    void reset();
    off_t lowestMemReaderOffset() const;
    bool readAheadPolicyCanRead() const;
    void addClient(store_client *);
    /* XXX belongs in MemObject::swapout, once swaphdrsz is managed
     * better
     */
    size_t objectBytesOnDisk() const;
    off_t policyLowestOffsetToKeep() const;
    void trimSwappable();
    void trimUnSwappable();
    bool isContiguous() const;
    int mostBytesWanted(int max) const;
    void setNoDelay(bool const newValue);
#if DELAY_POOLS

    DelayId mostBytesAllowed() const;
#endif


#if URL_CHECKSUM_DEBUG

    void checkUrlChecksum() const;
#endif

    method_t method;
    char *url;
    mem_hdr data_hdr;
    off_t inmem_lo;
    dlink_list clients;
    int nclients;

    struct
    {
        off_t queue_offset;     /* relative to in-mem data */
        mem_node *memnode;      /* which node we're currently paging out */
        StoreIOState::Pointer sio;
    }

    swapout;
    /* Read only - this reply must be preserved by store clients */
    /* The original reply. possibly with updated metadata. */
    request_t *request;

    struct timeval start_ping;
    IRCB *ping_reply_callback;
    void *ircb_data;
    int fd;                     /* FD of client creating this entry */

    struct
    {
        STABH *callback;
        void *data;
    }

    abort;
    char *log_url;
    RemovalPolicyNode repl;
    int id;
    ssize_t object_sz;
    size_t swap_hdr_sz;
#if URL_CHECKSUM_DEBUG

    unsigned int chksum;
#endif

    const char *vary_headers;

    void delayRead(DeferredRead const &);
    void kickReads();

private:
    static MemPool *pool;

    /* Read only - this reply must be preserved by store clients */
    /* The original reply. possibly with updated metadata. */
    HttpReply const *_reply;
    DeferredReadManager deferredReads;
};

#endif /* SQUID_MEMOBJECT_H */

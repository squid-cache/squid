
/*
 * $Id: StoreClient.h,v 1.3 2002/10/14 07:35:00 hno Exp $
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

#ifndef SQUID_STORECLIENT_H
#define SQUID_STORECLIENT_H

#include "StoreIOBuffer.h"

typedef void STCB(void *, StoreIOBuffer);	/* store callback */

#ifdef __cplusplus
class _StoreEntry;
#endif

#ifdef __cplusplus
class StoreClient {
public:
  virtual ~StoreClient () {}
  virtual void created (_StoreEntry *newEntry) = 0;
};
#endif

/* keep track each client receiving data from that particular StoreEntry */
struct _store_client {
    int type;
    off_t cmp_offset;
    STCB *callback;
    void *callback_data;
#if STORE_CLIENT_LIST_DEBUG
    void *owner;
#endif
    StoreEntry *entry;		/* ptr to the parent StoreEntry, argh! */
    storeIOState *swapin_sio;
    struct {
	unsigned int disk_io_pending:1;
	unsigned int store_copying:1;
	unsigned int copy_event_pending:1;
    } flags;
#if DELAY_POOLS
    delay_id delayId;
#endif
    dlink_node node;
    /* Below here is private - do no alter outside storeClient calls */
    StoreIOBuffer copyInto;
#ifdef __cplusplus
#endif
};

SQUIDCEXTERN void storeClientCopy(store_client *, StoreEntry *, StoreIOBuffer, STCB *, void *);
SQUIDCEXTERN void storeClientDumpStats(store_client * thisClient, StoreEntry * output, int clientNumber);

#endif /* SQUID_STORECLIENT_H */

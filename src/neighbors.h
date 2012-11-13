/*
 * DEBUG: section 15    Neighbor Routines
 * AUTHOR: Harvest Derived
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

#ifndef SQUID_NEIGHBORS_H_
#define SQUID_NEIGHBORS_H_

#include "enums.h"
#include "ICP.h"
#include "lookup_t.h"

class HttpRequest;
class HttpRequestMethod;
class CachePeer;
class StoreEntry;

CachePeer *getFirstPeer(void);
CachePeer *getFirstUpParent(HttpRequest *);
CachePeer *getNextPeer(CachePeer *);
CachePeer *getSingleParent(HttpRequest *);
int neighborsCount(HttpRequest *);
int neighborsUdpPing(HttpRequest *,
                     StoreEntry *,
                     IRCB * callback,
                     void *data,
                     int *exprep,
                     int *timeout);
void neighborAddAcl(const char *, const char *);

void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
void neighborAdd(const char *, const char *, int, int, int, int, int);
void neighbors_init(void);
#if USE_HTCP
void neighborsHtcpClear(StoreEntry *, const char *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif
CachePeer *peerFindByName(const char *);
CachePeer *peerFindByNameAndPort(const char *, unsigned short);
CachePeer *getDefaultParent(HttpRequest * request);
CachePeer *getRoundRobinParent(HttpRequest * request);
CachePeer *getWeightedRoundRobinParent(HttpRequest * request);
void peerClearRRStart(void);
void peerClearRR(void);
lookup_t peerDigestLookup(CachePeer * p, HttpRequest * request);
CachePeer *neighborsDigestSelect(HttpRequest * request);
void peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup);
void peerNoteDigestGone(CachePeer * p);
int neighborUp(const CachePeer * e);
CBDUNL peerDestroy;
const char *neighborTypeStr(const CachePeer * e);
peer_t neighborType(const CachePeer *, const HttpRequest *);
void peerConnectFailed(CachePeer *);
void peerConnectSucceded(CachePeer *);
void dump_peer_options(StoreEntry *, CachePeer *);
int peerHTTPOkay(const CachePeer *, HttpRequest *);

CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

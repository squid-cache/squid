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

extern CachePeer *getFirstPeer(void);
extern CachePeer *getFirstUpParent(HttpRequest *);
extern CachePeer *getNextPeer(CachePeer *);
extern CachePeer *getSingleParent(HttpRequest *);
extern int neighborsCount(HttpRequest *);
extern int neighborsUdpPing(HttpRequest *,
                                  StoreEntry *,
                                  IRCB * callback,
                                  void *data,
                                  int *exprep,
                                  int *timeout);
extern void neighborAddAcl(const char *, const char *);

extern void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
extern void neighborAdd(const char *, const char *, int, int, int, int, int);
extern void neighbors_init(void);
#if USE_HTCP
extern void neighborsHtcpClear(StoreEntry *, const char *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif
extern CachePeer *peerFindByName(const char *);
extern CachePeer *peerFindByNameAndPort(const char *, unsigned short);
extern CachePeer *getDefaultParent(HttpRequest * request);
extern CachePeer *getRoundRobinParent(HttpRequest * request);
extern CachePeer *getWeightedRoundRobinParent(HttpRequest * request);
extern void peerClearRRStart(void);
extern void peerClearRR(void);
extern lookup_t peerDigestLookup(CachePeer * p, HttpRequest * request);
extern CachePeer *neighborsDigestSelect(HttpRequest * request);
extern void peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup);
extern void peerNoteDigestGone(CachePeer * p);
extern int neighborUp(const CachePeer * e);
extern CBDUNL peerDestroy;
extern const char *neighborTypeStr(const CachePeer * e);
extern peer_t neighborType(const CachePeer *, const HttpRequest *);
extern void peerConnectFailed(CachePeer *);
extern void peerConnectSucceded(CachePeer *);
extern void dump_peer_options(StoreEntry *, CachePeer *);
extern int peerHTTPOkay(const CachePeer *, HttpRequest *);

extern CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

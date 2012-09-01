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
class peer;
class StoreEntry;

extern peer *getFirstPeer(void);
extern peer *getFirstUpParent(HttpRequest *);
extern peer *getNextPeer(peer *);
extern peer *getSingleParent(HttpRequest *);
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
extern peer *peerFindByName(const char *);
extern peer *peerFindByNameAndPort(const char *, unsigned short);
extern peer *getDefaultParent(HttpRequest * request);
extern peer *getRoundRobinParent(HttpRequest * request);
extern peer *getWeightedRoundRobinParent(HttpRequest * request);
extern void peerClearRRStart(void);
extern void peerClearRR(void);
extern lookup_t peerDigestLookup(peer * p, HttpRequest * request);
extern peer *neighborsDigestSelect(HttpRequest * request);
extern void peerNoteDigestLookup(HttpRequest * request, peer * p, lookup_t lookup);
extern void peerNoteDigestGone(peer * p);
extern int neighborUp(const peer * e);
extern CBDUNL peerDestroy;
extern const char *neighborTypeStr(const peer * e);
extern peer_t neighborType(const peer *, const HttpRequest *);
extern void peerConnectFailed(peer *);
extern void peerConnectSucceded(peer *);
extern void dump_peer_options(StoreEntry *, peer *);
extern int peerHTTPOkay(const peer *, HttpRequest *);

extern peer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

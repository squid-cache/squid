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
#include "HttpRequestMethod.h"
#include "lookup_t.h"
#include "ip/Address.h"
#include "typedefs.h"

class HttpRequest;
class peer;
class StoreEntry;

SQUIDCEXTERN peer *getFirstPeer(void);
SQUIDCEXTERN peer *getFirstUpParent(HttpRequest *);
SQUIDCEXTERN peer *getNextPeer(peer *);
SQUIDCEXTERN peer *getSingleParent(HttpRequest *);
SQUIDCEXTERN int neighborsCount(HttpRequest *);
SQUIDCEXTERN int neighborsUdpPing(HttpRequest *,
                                  StoreEntry *,
                                  IRCB * callback,
                                  void *data,
                                  int *exprep,
                                  int *timeout);
SQUIDCEXTERN void neighborAddAcl(const char *, const char *);

SQUIDCEXTERN void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
SQUIDCEXTERN void neighborAdd(const char *, const char *, int, int, int, int, int);
SQUIDCEXTERN void neighbors_init(void);
#if USE_HTCP
SQUIDCEXTERN void neighborsHtcpClear(StoreEntry *, const char *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif
SQUIDCEXTERN peer *peerFindByName(const char *);
SQUIDCEXTERN peer *peerFindByNameAndPort(const char *, unsigned short);
SQUIDCEXTERN peer *getDefaultParent(HttpRequest * request);
SQUIDCEXTERN peer *getRoundRobinParent(HttpRequest * request);
SQUIDCEXTERN peer *getWeightedRoundRobinParent(HttpRequest * request);
SQUIDCEXTERN void peerClearRRStart(void);
SQUIDCEXTERN void peerClearRR(void);
SQUIDCEXTERN lookup_t peerDigestLookup(peer * p, HttpRequest * request);
SQUIDCEXTERN peer *neighborsDigestSelect(HttpRequest * request);
SQUIDCEXTERN void peerNoteDigestLookup(HttpRequest * request, peer * p, lookup_t lookup);
SQUIDCEXTERN void peerNoteDigestGone(peer * p);
SQUIDCEXTERN int neighborUp(const peer * e);
SQUIDCEXTERN CBDUNL peerDestroy;
SQUIDCEXTERN const char *neighborTypeStr(const peer * e);
SQUIDCEXTERN peer_t neighborType(const peer *, const HttpRequest *);
SQUIDCEXTERN void peerConnectFailed(peer *);
SQUIDCEXTERN void peerConnectSucceded(peer *);
SQUIDCEXTERN void dump_peer_options(StoreEntry *, peer *);
SQUIDCEXTERN int peerHTTPOkay(const peer *, HttpRequest *);

SQUIDCEXTERN peer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 15    Neighbor Routines */

#ifndef SQUID_NEIGHBORS_H_
#define SQUID_NEIGHBORS_H_

#include "enums.h"
#include "ICP.h"
#include "lookup_t.h"
#include "typedefs.h" //for IRCB

class HttpRequest;
class HttpRequestMethod;
class CachePeer;
class StoreEntry;
class URL;

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
const char *neighborTypeStr(const CachePeer * e);
peer_t neighborType(const CachePeer *, const URL &);
void peerConnectFailed(CachePeer *);
void peerConnectSucceded(CachePeer *);
void dump_peer_options(StoreEntry *, CachePeer *);
int peerHTTPOkay(const CachePeer *, HttpRequest *);

/// Whether we can open new connections to the peer (e.g., despite max-conn)
bool peerCanOpenMore(const CachePeer *p);
/// Whether the peer has idle or standby connections that can be used now
bool peerHasConnAvailable(const CachePeer *p);
/// Notifies peer of an associated connection closure.
void peerConnClosed(CachePeer *p);

CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */


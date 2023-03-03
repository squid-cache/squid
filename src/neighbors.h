/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 15    Neighbor Routines */

#ifndef SQUID_NEIGHBORS_H_
#define SQUID_NEIGHBORS_H_

#include "anyp/forward.h"
#include "enums.h"
#include "ICP.h"
#include "lookup_t.h"
#include "typedefs.h" //for IRCB

class HttpRequest;
class HttpRequestMethod;
class CachePeer;
class StoreEntry;
class PeerSelector;

CachePeer *getFirstPeer(void);
CachePeer *getFirstUpParent(PeerSelector *);
CachePeer *getNextPeer(CachePeer *);
CachePeer *getSingleParent(PeerSelector *);
int neighborsCount(PeerSelector *);
int neighborsUdpPing(HttpRequest *,
                     StoreEntry *,
                     IRCB * callback,
                     PeerSelector *ps,
                     int *exprep,
                     int *timeout);
void neighborAddAcl(const char *, const char *);

void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
void neighborAdd(const char *, const char *, int, int, int, int, int);
void neighbors_init(void);
#if USE_HTCP
void neighborsHtcpClear(StoreEntry *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif

/// cache_peer with a given name (or nil)
CachePeer *findCachePeerByName(const char *);

CachePeer *getDefaultParent(PeerSelector*);
CachePeer *getRoundRobinParent(PeerSelector*);
CachePeer *getWeightedRoundRobinParent(PeerSelector*);
void peerClearRRStart(void);
void peerClearRR(void);

// TODO: Move, together with its many dependencies and callers, into CachePeer.
/// Updates protocol-agnostic CachePeer state after an indication of a
/// successful contact with the given cache_peer.
void peerAlive(CachePeer *);

lookup_t peerDigestLookup(CachePeer * p, PeerSelector *);
CachePeer *neighborsDigestSelect(PeerSelector *);
void peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup);
void peerNoteDigestGone(CachePeer * p);
int neighborUp(const CachePeer * e);
const char *neighborTypeStr(const CachePeer * e);
peer_t neighborType(const CachePeer *, const AnyP::Uri &);
void dump_peer_options(StoreEntry *, CachePeer *);
int peerHTTPOkay(const CachePeer *, PeerSelector *);

/// \returns max(1, timeout)
time_t positiveTimeout(const time_t timeout);

/// Whether we can open new connections to the peer (e.g., despite max-conn)
bool peerCanOpenMore(const CachePeer *p);
/// Whether the peer has idle or standby connections that can be used now
bool peerHasConnAvailable(const CachePeer *p);
/// Notifies peer of an associated connection closure.
void peerConnClosed(CachePeer *p);

CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */


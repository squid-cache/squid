/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer user hash based selection */

#ifndef SQUID_PEER_USERHASH_H_
#define SQUID_PEER_USERHASH_H_

class CachePeer;
class HttpRequest;
class PeerSelector;

void peerUserHashInit(void);
CachePeer * peerUserHashSelectParent(PeerSelector *);

#endif /* SQUID_PEER_USERHASH_H_ */


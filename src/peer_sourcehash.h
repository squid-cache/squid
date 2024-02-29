/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#ifndef SQUID_SRC_PEER_SOURCEHASH_H
#define SQUID_SRC_PEER_SOURCEHASH_H

class CachePeer;
class PeerSelector;

void peerSourceHashInit(void);
CachePeer * peerSourceHashSelectParent(PeerSelector*);

#endif /* SQUID_SRC_PEER_SOURCEHASH_H */


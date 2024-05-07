/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTSTREAMFORWARD_H
#define SQUID_SRC_CLIENTSTREAMFORWARD_H

#include "enums.h" /* for clientStream_status_t */

class Lock;
template <class C> class RefCount;

typedef RefCount<Lock> ClientStreamData;

/* Callbacks for ClientStreams API */

class clientStreamNode;
class ClientHttpRequest;
class HttpReply;
class StoreIOBuffer;

/// client stream read callback
typedef void CSCB(clientStreamNode *, ClientHttpRequest *, HttpReply *, StoreIOBuffer);

/// client stream read
typedef void CSR(clientStreamNode *, ClientHttpRequest *);

/// client stream detach
typedef void CSD(clientStreamNode *, ClientHttpRequest *);

typedef clientStream_status_t CSS(clientStreamNode *, ClientHttpRequest *);

#endif /* SQUID_SRC_CLIENTSTREAMFORWARD_H */


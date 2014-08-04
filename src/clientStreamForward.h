#ifndef SQUID_CLIENTSTREAM_FORWARD_H
#define SQUID_CLIENTSTREAM_FORWARD_H

#include "enums.h"

class Lock;
template <class C> class RefCount;

/// \ingroup ClientStreamAPI
typedef RefCount<Lock> ClientStreamData;

/* Callbacks for ClientStreams API */

class clientStreamNode;
class ClientHttpRequest;
class HttpReply;
class StoreIOBuffer;

/* client stream read callback */
/// \ingroup ClientStreamAPI
typedef void CSCB(clientStreamNode *, ClientHttpRequest *, HttpReply *, StoreIOBuffer);

/* client stream read */
/// \ingroup ClientStreamAPI
typedef void CSR(clientStreamNode *, ClientHttpRequest *);

/* client stream detach */
/// \ingroup ClientStreamAPI
typedef void CSD(clientStreamNode *, ClientHttpRequest *);

/// \ingroup ClientStreamAPI
typedef clientStream_status_t CSS(clientStreamNode *, ClientHttpRequest *);

#endif /* SQUID_CLIENTSTREAM_FORWARD_H */


/*
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

#ifndef SQUID_CLIENTSTREAM_H
#define SQUID_CLIENTSTREAM_H

#include "base/RefCount.h"
#include "dlink.h"
#include "StoreIOBuffer.h"

/**
 \defgroup ClientStreamAPI Client Streams API
 \ingroup Components
 \section Introduction Introduction
 \par
 *    A ClientStream implements a unidirectional, non-blocking,
 *    pull pipeline. They allow code to be inserted into the
 *    reply logic on an as-needed basis. For instance,
 *    transfer-encoding logic is only needed when sending a
 *    HTTP/1.1 reply.
 *
 \par
 *    Each node consists of four methods - read, callback, detach, and status,
 *    along with the stream housekeeping variables (a dlink node and pointer
 *    to the head of the list), context data for the node, and read request
 *    parameters - readbuf, readlen and readoff (in the body).
 *
 \par
 *    clientStream is the basic unit for scheduling, and the clientStreamRead()
 *    and clientStreamCallback() calls allow for deferred scheduled activity if
 *    desired.
 *
 \section OperationTheory    Theory on stream operation
 \par
 \li    Something creates a pipeline. At a minimum it needs a head with a
 *      status method and a read method, and a tail with a callback method
 *      and a valid initial read request.
 \li    Other nodes may be added into the pipeline.
 \li    The tail-1th node's read method is called.
 *
 \par
 *    For each node going up the pipeline, the node either:
 \li             satisfies the read request, or
 \li             inserts a new node above it and calls clientStreamRead(), or
 \li             calls clientStreamRead()
 \todo DOCS: make the above list nested.
 *
 \par
 *    There is no requirement for the Read parameters from different
 *    nodes to have any correspondence, as long as the callbacks provided are
 *    correct.
 *
 \section WhatsInANode Whats in a node
 *
 \todo ClientStreams: These details should really be codified as a class which all ClientStream nodes inherit from.
 *
 \par	Each node must have:
 \li	read method - to allow loose coupling in the pipeline. (The reader may
                      therefore change if the pipeline is altered, even mid-flow).
 \li	callback method - likewise.
 \li	status method - likewise.
 \li	detach method - used to ensure all resources are cleaned up properly.
 \li	dlink head pointer - to allow list inserts and deletes from within a node.
 \li	context data - to allow the called back nodes to maintain their private information.
 \li	read request parameters - For two reasons:
 \li		To allow a node to determine the requested data offset, length and target buffer dynamically. Again, this is to promote loose coupling.
 \li		Because of the callback nature of squid, every node would have to keep these parameters in their context anyway, so this reduces programmer overhead.
 */

/// \ingroup ClientStreamAPI
typedef RefCount<Lock> ClientStreamData;

class clientStreamNode;
class ClientHttpRequest;
class HttpReply;

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

/// \ingroup ClientStreamAPI
class clientStreamNode
{

public:
    clientStreamNode *prev() const;
    clientStreamNode *next() const;
    void removeFromStream();
    dlink_node node;
    dlink_list *head;		/* sucks I know, but hey, the interface is limited */
    CSR *readfunc;
    CSCB *callback;
    CSD *detach;		/* tell this node the next one downstream wants no more data */
    CSS *status;
    ClientStreamData data;			/* Context for the node */
    StoreIOBuffer readBuffer;	/* what, where and how much this node wants */
};

/// \ingroup ClientStreamAPI
void clientStreamInit(dlink_list *, CSR *, CSD *, CSS *, ClientStreamData, CSCB *, CSD *, ClientStreamData, StoreIOBuffer tailBuffer);

/// \ingroup ClientStreamAPI
void clientStreamInsertHead(dlink_list *, CSR *, CSCB *, CSD *, CSS *, ClientStreamData);

/// \ingroup ClientStreamAPI
clientStreamNode *clientStreamNew(CSR *, CSCB *, CSD *, CSS *, ClientStreamData);

/**
 \ingroup ClientStreamAPI
 *
 * Call back the next node the in chain with it's requested data.
 * Return data to the next node in the stream.
 * The data may be returned immediately, or may be delayed for a later scheduling cycle.
 *
 \param thisObject	'this' reference for the client stream
 \param http		Superset of request data, being winnowed down over time. MUST NOT be NULL.
 \param rep		Not NULL on the first call back only. Ownership is passed down the pipeline.
 			Each node may alter the reply if appropriate.
 \param replyBuffer	- buffer, length - where and how much.
 */
void clientStreamCallback(clientStreamNode *thisObject, ClientHttpRequest *http, HttpReply *rep, StoreIOBuffer replyBuffer);

/**
 \ingroup ClientStreamAPI
 *
 * Triggers a read of data that satisfies the httpClientRequest
 * metainformation and (if appropriate) the offset,length and buffer
 * parameters.
 *
 \param thisObject	'this' reference for the client stream
 \param http		Superset of request data, being winnowed down over time. MUST NOT be NULL.
 \param readBuffer	- offset, length, buffer - what, how much and where.
 */
void clientStreamRead(clientStreamNode *thisObject, ClientHttpRequest *http, StoreIOBuffer readBuffer);

/**
 \ingroup ClientStreamAPI
 *
 * Removes this node from a clientStream. The stream infrastructure handles the removal.
 * This node MUST have cleaned up all context data, UNLESS scheduled callbacks will take care of that.
 * Informs the prev node in the list of this nodes detachment.
 *
 \param thisObject	'this' reference for the client stream
 \param http		MUST NOT be NULL.
 */
void clientStreamDetach(clientStreamNode *thisObject, ClientHttpRequest *http);

/**
 \ingroup ClientStreamAPI
 *
 * Detachs the tail of the stream. CURRENTLY DOES NOT clean up the tail node data -
 * this must be done separately. Thus Abort may ONLY be called by the tail node.
 *
 \param thisObject	'this' reference for the client stream
 \param http		MUST NOT be NULL.
 */
void clientStreamAbort(clientStreamNode *thisObject, ClientHttpRequest *http);

/**
 \ingroup ClientStreamAPI
 *
 * Allows nodes to query the upstream nodes for :
 \li	stream ABORTS - request cancelled for some reason. upstream will not accept further reads().
 \li	stream COMPLETION - upstream has completed and will not accept further reads().
 \li	stream UNPLANNED COMPLETION - upstream has completed, but not at a pre-planned location (used for keepalive checking), and will not accept further reads().
 \li	stream NONE - no special status, further reads permitted.
 *
 \param thisObject	'this' reference for the client stream
 \param http		MUST NOT be NULL.
 */
clientStream_status_t clientStreamStatus(clientStreamNode *thisObject, ClientHttpRequest *http);

#endif /* SQUID_CLIENTSTREAM_H */

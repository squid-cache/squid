
/*
 * $Id: clientStream.cc,v 1.13 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 87    Client-side Stream routines.
 * AUTHOR: Robert Collins
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
 *  along with thisObject program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/*
 * A client Stream is a uni directional pipe, with the usual non-blocking
 * asynchronous approach present elsewhere in squid.
 *
 * Each pipe node has a data push function, and a data request function.
 * This limits flexability - the data flow is no longer assembled at each
 * step. 
 *
 * An alternative approach is to pass each node in the pipe the call-
 * back to use on each IO call. This allows the callbacks to be changed 
 * very easily by a participating node, but requires more maintenance 
 * in each node (store the call  back to the msot recent IO request in 
 * the nodes context.) Such an approach also prevents dynamically 
 * changing the pipeline from outside without an additional interface
 * method to extract the callback and context from the next node.
 *
 * One important characteristic of the stream is that the readfunc
 * on the terminating node, and the callback on the first node
 * will be NULL, and never used.
 */

#include "squid.h"
#include "clientStream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "client_side_request.h"

CBDATA_TYPE(clientStreamNode);

/*
 * TODO: rather than each node undeleting the next, have a clientStreamDelete
 * that walks the list
 */

/*
 * clientStream quick notes:
 *
 * Each node including the HEAD of the clientStream has a cbdataReference
 * held by the stream. Freeing the stream then removes that reference
 * and cbdataFrees every node.
 * Any node with other References, and all nodes downstream will only 
 * free when those references are released.
 * Stream nodes MAY hold references to the data member of the node. 
 *
 * Specifically - on creation no reference is made. 
 * If you pass a data variable to a node, give it an initial reference.
 * If the data member is non-null on FREE, cbdataFree WILL be called.
 * This you must never call cbdataFree on your own context without
 * explicitly setting the stream node data member to NULL and
 * cbdataReferenceDone'ing it.
 *
 * No data member may hold a reference to it's stream node.
 * The stream guarantees that DETACH will be called before
 * freeing the node, alowing data members to cleanup.
 * 
 * If a node's data holds a reference to something that needs to
 * free the stream a circular reference list will occur.
 * This results no data being freed until that reference is removed.
 * One way to accomplish thisObject is to explicitly remove the
 * data from your own node before freeing the stream.
 *
 * (i.e. 
 * mycontext = thisObject->data;
 * thisObject->data = NULL;
 * clientStreamFree (thisObject->head);
 * mycontext = NULL;
 * return;
 */

/* Local functions */
static FREE clientStreamFree;

clientStreamNode *
clientStreamNew(CSR * readfunc, CSCB * callback, CSD * detach, CSS * status,
                ClientStreamData data)
{
    clientStreamNode *temp;
    CBDATA_INIT_TYPE_FREECB(clientStreamNode, clientStreamFree);
    temp = cbdataAlloc(clientStreamNode);
    temp->readfunc = readfunc;
    temp->callback = callback;
    temp->detach = detach;
    temp->status = status;
    temp->data = data;
    return temp;
}

/*
 * Initialise a client Stream.
 * list is the stream
 * func is the read function for the head
 * callback is the callback for the tail
 * tailbuf and taillen are the initial buffer and length for the tail.
 */
void
clientStreamInit(dlink_list * list, CSR * func, CSD * rdetach, CSS * readstatus,
                 ClientStreamData readdata, CSCB * callback, CSD * cdetach, ClientStreamData callbackdata,
                 StoreIOBuffer tailBuffer)
{
    clientStreamNode *temp = clientStreamNew(func, NULL, rdetach, readstatus,
                             readdata);
    dlinkAdd(cbdataReference(temp), &temp->node, list);
    temp->head = list;
    clientStreamInsertHead(list, NULL, callback, cdetach, NULL, callbackdata);
    temp = (clientStreamNode *)list->tail->data;
    temp->readBuffer = tailBuffer;
}

/*
 * Doesn't actually insert at head. Instead it inserts one *after*
 * head. This is because HEAD is a special node, as is tail
 * This function is not suitable for inserting the real HEAD.
 */
void
clientStreamInsertHead(dlink_list * list, CSR * func, CSCB * callback,
                       CSD * detach, CSS * status, ClientStreamData data)
{

    /* test preconditions */
    assert(list != NULL);
    assert(list->head);
    clientStreamNode *temp = clientStreamNew(func, callback, detach, status, data);
    temp->head = list;
    debugs(87, 3, "clientStreamInsertHead: Inserted node " << temp <<
           " with data " << data.getRaw() << " after head");

    if (list->head->next)
        temp->readBuffer = ((clientStreamNode *)list->head->next->data)->readBuffer;

    dlinkAddAfter(cbdataReference(temp), &temp->node, list->head, list);
}

/*
 * Callback the next node the in chain with it's requested data
 */
void
clientStreamCallback(clientStreamNode * thisObject, ClientHttpRequest * http,
                     HttpReply * rep, StoreIOBuffer replyBuffer)
{
    clientStreamNode *next;
    assert(thisObject && http && thisObject->node.next);
    next = thisObject->next();

    debugs(87, 3, "clientStreamCallback: Calling " << next->callback << " with cbdata " << 
           next->data.getRaw() << " from node " << thisObject);
    next->callback(next, http, rep, replyBuffer);
}

/*
 * Call the previous node in the chain to read some data
 */
void
clientStreamRead(clientStreamNode * thisObject, ClientHttpRequest * http,
                 StoreIOBuffer readBuffer)
{
    /* place the parameters on the 'stack' */
    clientStreamNode *prev;
    assert(thisObject && http && thisObject->prev());
    prev = thisObject->prev();

    debugs(87, 3, "clientStreamRead: Calling " << prev->readfunc <<
           " with cbdata " << prev->data.getRaw() << " from node " << thisObject);
    thisObject->readBuffer = readBuffer;
    prev->readfunc(prev, http);
}

/*
 * Detach from the stream - only allowed for terminal members
 */
void
clientStreamDetach(clientStreamNode * thisObject, ClientHttpRequest * http)
{
    clientStreamNode *temp = thisObject;

    assert(thisObject->node.next == NULL);
    debugs(87, 3, "clientStreamDetach: Detaching node " << thisObject);
    /* And clean up thisObject node */
    /* ESI TODO: push refcount class through to head */
    clientStreamNode *prev = NULL;

    if (thisObject->prev())
        prev = cbdataReference(thisObject->prev());

    thisObject->removeFromStream();

    cbdataReferenceDone(temp);

    cbdataFree(thisObject);

    /* and tell the prev that the detach has occured */
    /*
     * We do it in thisObject order so that the detaching node is always
     * at the end of the list
     */

    if (prev) {
        debugs(87, 3, "clientStreamDetach: Calling " << prev->detach << " with cbdata " << prev->data.getRaw());

        if (cbdataReferenceValid(prev))
            prev->detach(prev, http);

        cbdataReferenceDone(prev);
    }
}

/*
 * Abort the stream - detach every node in the pipeline.
 */
void
clientStreamAbort(clientStreamNode * thisObject, ClientHttpRequest * http)
{
    dlink_list *list;

    assert(thisObject != NULL);
    assert(http != NULL);
    list = thisObject->head;
    debugs(87, 3, "clientStreamAbort: Aborting stream with tail " << list->tail);

    if (list->tail) {
        clientStreamDetach((clientStreamNode *)list->tail->data, http);
    }
}

/*
 * Call the upstream node to find it's status 
 */
clientStream_status_t
clientStreamStatus(clientStreamNode * thisObject, ClientHttpRequest * http)
{
    clientStreamNode *prev;
    assert(thisObject && http && thisObject->node.prev);
    prev = (clientStreamNode *)thisObject->node.prev->data;
    return prev->status(prev, http);
}

/* Local function bodies */
void
clientStreamNode::removeFromStream()
{
    if (head)
        dlinkDelete(&node, head);

    head = NULL;
}

void
clientStreamFree(void *foo)
{
    clientStreamNode *thisObject = (clientStreamNode *)foo;

    debugs(87, 3, "Freeing clientStreamNode " << thisObject);

    thisObject->removeFromStream();
    thisObject->data = NULL;
}

clientStreamNode *
clientStreamNode::prev() const
{
    if (node.prev)
        return (clientStreamNode *)node.prev->data;
    else
        return NULL;
}

clientStreamNode *
clientStreamNode::next() const
{
    if (node.next)
        return (clientStreamNode *)node.next->data;
    else
        return NULL;
}

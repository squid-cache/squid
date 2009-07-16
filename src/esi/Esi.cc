/*
 * DEBUG: section 86    ESI processing
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the ESI code from compile process when not needed.
 */
#if (USE_SQUID_ESI == 1)

#include "esi/Esi.h"
#include "clientStream.h"
#include "client_side_request.h"
#include "errorpage.h"
#include "esi/Segment.h"
#include "esi/Element.h"
#include "esi/Context.h"
#include "HttpHdrSc.h"
#include "HttpHdrScTarget.h"
#include "HttpReply.h"
#include "esi/Attempt.h"
#include "esi/Except.h"
#include "client_side.h"
#include "esi/VarState.h"
#include "esi/Assign.h"
#include "esi/Expression.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "ip/IpAddress.h"

/* quick reference on behaviour here.
 * The ESI specification 1.0 requires the ESI processor to be able to
 * return an error code at any point in the processing. To that end
 * we buffer the incoming esi body until we know we will be able to
 * satisfy the request. At that point we start streaming the queued
 * data downstream.
 *
 */

class ESIStreamContext;

/* TODO: split this out into separate files ? */
/* Parsing: quick and dirty. ESI files are not valid XML, so a generic
 * XML parser is not much use. Also we need a push parser not a pull
 * parser, so LibXML is out.
 *
 * Interpreter methods:
 * Render: May only ever be called after Process returns PROCESS_COMPLETE.
 * Renders the resulting content into a ESISegment chain.
 * Process: returns the status of the node.
 * COMPLETE - processing is complete, rendering may staret
 * PENDING_WONTFAIL - process is incomplete, but the element *will*
 *   be able to be rendered given time.
 * PENDING_MAYFAIL - processing is incomplete, and the element *may*
 *   fail to be able to rendered.
 * FAILED - processing failed, return an error to the client.
 */

/*
 * NOT TODO: esi:inline - out of scope.
 */

/* make comparisons with refcount pointers easy */
bool operator == (ESIElement const *lhs, ESIElement::Pointer const &rhs)
{
    return lhs == rhs.getRaw();
}

typedef ESIContext::esiKick_t esiKick_t;


/* some core operators */

/* esiComment */

struct esiComment : public ESIElement {
    MEMPROXY_CLASS(esiComment);
    ~esiComment();
    esiComment();
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;

    void render(ESISegment::Pointer);
    void finish();
};

MEMPROXY_CLASS_INLINE(esiComment);

#include "esi/Literal.h"

#include "esi/Sequence.h"

#include "esi/Include.h"

/* esiRemove */

class esiRemove : public ESIElement
{

public:
    void *operator new (size_t byteCount);
    void operator delete (void *address);

    esiRemove();
    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;
    void finish();
};

CBDATA_TYPE (esiRemove);
static FREE esiRemoveFree;
static ESIElement * esiRemoveNew(void);


/* esiTry */

struct esiTry : public ESIElement {
    MEMPROXY_CLASS(esiTry);

    esiTry(esiTreeParentPtr aParent);
    ~esiTry();

    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    void fail(ESIElement *, char const * = NULL);
    esiProcessResult_t process (int dovars);
    void provideData (ESISegment::Pointer data, ESIElement * source);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;

    ESIElement::Pointer attempt;
    ESIElement::Pointer except;

    struct {
        int attemptok:1; /* the attempt branch process correctly */
        int exceptok:1; /* likewise */
        int attemptfailed:1; /* The attempt branch failed */
        int exceptfailed:1; /* the except branch failed */
    } flags;
    void finish();

private:
    void notifyParent();
    esiTreeParentPtr parent;
    ESISegment::Pointer exceptbuffer;
    esiTry (esiTry const &);
    esiProcessResult_t bestAttemptRV() const;
};

MEMPROXY_CLASS_INLINE(esiTry);

#include "esi/Var.h"

/* esiChoose */

struct esiChoose : public ESIElement {
    MEMPROXY_CLASS(esiChoose);

    esiChoose(esiTreeParentPtr);
    ~esiChoose();

    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    void fail(ESIElement *, char const * = NULL);
    esiProcessResult_t process (int dovars);

    void provideData (ESISegment::Pointer data, ESIElement *source);
    void makeCachableElements(esiChoose const &old);
    void makeUsableElements(esiChoose const &old, ESIVarState &);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;
    void NULLUnChosen();

    ElementList elements;
    int chosenelement;
    ESIElement::Pointer otherwise;
    void finish();

private:
    esiChoose(esiChoose const &);
    esiTreeParentPtr parent;
    void checkValidSource (ESIElement::Pointer source) const;
    void selectElement();
};

MEMPROXY_CLASS_INLINE(esiChoose);

/* esiWhen */

struct esiWhen : public esiSequence {
    MEMPROXY_CLASS(esiWhen);
    esiWhen(esiTreeParentPtr aParent, int attributes, const char **attr, ESIVarState *);
    ~esiWhen();
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;

    bool testsTrue() const { return testValue;}

    void setTestResult(bool aBool) {testValue = aBool;}

private:
    esiWhen (esiWhen const &);
    bool testValue;
    char const *unevaluatedExpression;
    ESIVarState *varState;
    void evaluate();
};

MEMPROXY_CLASS_INLINE(esiWhen);

/* esiOtherwise */

struct esiOtherwise : public esiSequence {
    //    void *operator new (size_t byteCount);
    //    void operator delete (void *address);
    esiOtherwise(esiTreeParentPtr aParent) : esiSequence (aParent) {}
};

CBDATA_CLASS_INIT(ESIContext);

void ESIContext::startRead()
{
    assert (!reading_);
    reading_ = true;
}

void ESIContext::finishRead()
{
    assert (reading_);
    reading_ = false;
}

bool ESIContext::reading() const
{
    return reading_;
}


ESIStreamContext::ESIStreamContext() : finished(false), include (NULL), localbuffer (new ESISegment), buffer (NULL)
{}

/* Local functions */
/* ESIContext */
static ESIContext *ESIContextNew(HttpReply *, clientStreamNode *, ClientHttpRequest *);


void *
ESIContext::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (ESIContext));
    CBDATA_INIT_TYPE(ESIContext);
    ESIContext *result = cbdataAlloc(ESIContext);
    return result;
}

void
ESIContext::operator delete (void *address)
{
    ESIContext *t = static_cast<ESIContext *>(address);
    cbdataFree(t);
}

void
ESIContext::setError()
{
    errorpage = ERR_ESI;
    errorstatus = HTTP_INTERNAL_SERVER_ERROR;
    flags.error = 1;
}

void
ESIContext::appendOutboundData(ESISegment::Pointer theData)
{
    if (!outbound.getRaw()) {
        outbound = theData;
        outboundtail = outbound;
    } else {
        assert (outboundtail->next.getRaw() == NULL);
        outboundtail->next = theData;
    }

    fixupOutboundTail();
    debugs(86, 9, "ESIContext::appendOutboundData: outbound " << outbound.getRaw());
}

void
ESIContext::provideData (ESISegment::Pointer theData, ESIElement * source)
{
    debugs(86, 5, "ESIContext::provideData: " << this << " " << theData.getRaw() << " " << source);
    /* No callbacks permitted after finish() called on the tree */
    assert (tree.getRaw());
    assert (source == tree);
    appendOutboundData(theData);
    trimBlanks();

    if (!processing)
        send();
}

void
ESIContext::fail (ESIElement * source, char const *anError)
{
    setError();
    setErrorMessage (anError);
    fail ();
    send ();
}

void
ESIContext::fixupOutboundTail()
{
    /* TODO: fixup thisNode outboundtail dross a little */

    if (outboundtail.getRaw())
        outboundtail = outboundtail->tail();
}

esiKick_t
ESIContext::kick ()
{
    assert (this);

    if (flags.kicked) {
        debugs(86, 5, "esiKick: Re-entered whilst in progress");
        // return ESI_KICK_INPROGRESS;
    } else
        ++flags.kicked;

    if (flags.detached)
        /* we've been detached from - we can't do anything more */
        return ESI_KICK_FAILED;

    /* Something has occured. Process any remaining nodes */
    if (!flags.finished)
        /* Process some of our data */
        switch (process ()) {

        case ESI_PROCESS_COMPLETE:
            debugs(86, 5, "esiKick: esiProcess OK");
            break;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debugs(86, 5, "esiKick: esiProcess PENDING OK");
            break;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debugs(86, 5, "esiKick: esiProcess PENDING UNKNOWN");
            break;

        case ESI_PROCESS_FAILED:
            debugs(86, 2, "esiKick: esiProcess " << this << " FAILED");
            /* this can not happen - processing can't fail until we have data,
             * and when we come here we have sent data to the client
             */

            if (pos == 0)
                fail ();

            --flags.kicked;

            return ESI_KICK_FAILED;
        }

    /* Render if we can to get maximal sent data */
    assert (tree.getRaw() || flags.error);

    if (!flags.finished && !outbound.getRaw()) {
        outboundtail = new ESISegment;
        outbound = outboundtail;
    }

    if (!flags.error && !flags.finished)
        tree->render(outboundtail);

    if (!flags.finished)
        fixupOutboundTail();

    /* Is there data to send? */
    if (send ()) {
        /* some data was sent. we're finished until the next read */
        --flags.kicked;
        return ESI_KICK_SENT;
    }

    --flags.kicked;
    /* nothing to send */
    return flags.error ? ESI_KICK_FAILED : ESI_KICK_PENDING;
}

/* request from downstream for more data
 */
void
esiStreamRead (clientStreamNode *thisNode, ClientHttpRequest *http)
{
    clientStreamNode *next;
    /* Test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    /* we are not in the chain until ESI is detected on a data callback */
    assert (thisNode->node.prev != NULL);
    assert (thisNode->node.next != NULL);

    ESIContext::Pointer context = dynamic_cast<ESIContext *>(thisNode->data.getRaw());
    assert (context.getRaw() != NULL);

    if (context->flags.passthrough) {
        /* passthru mode - read into supplied buffers */
        next = thisNode->next();
        clientStreamRead (thisNode, http, next->readBuffer);
        return;
    }

    context->flags.clientwantsdata = 1;
    debugs(86, 5, "esiStreamRead: Client now wants data");

    /* Ok, not passing through */

    switch (context->kick ()) {

    case ESIContext::ESI_KICK_FAILED:
        /* this can not happen - processing can't fail until we have data,
         * and when we come here we have sent data to the client
         */

    case ESIContext::ESI_KICK_SENT:

    case ESIContext::ESI_KICK_INPROGRESS:
        return;

    case ESIContext::ESI_KICK_PENDING:
        break;
    }

    /* Nothing to send */

    if (context->flags.oktosend && (context->flags.finishedtemplate
                                    || context->cachedASTInUse) &&
            ! context->flags.finished) {
        /* we've started sending, finished reading, but not finished
         * processing. stop here, a callback will resume the stream
         * flow
         */
        debugs(86, 5, "esiStreamRead: Waiting for async resume of esi processing");
        return;
    }

    if (context->flags.oktosend && context->flags.finished && context->outbound.getRaw()) {
        debugs(86, 5, "all processing complete, but outbound data still buffered");
        assert (!context->flags.clientwantsdata);
        /* client MUST be processing the last reply */
        return;
    }


    if (context->flags.oktosend && context->flags.finished) {
        StoreIOBuffer tempBuffer;
        assert (!context->outbound.getRaw());
        /* We've finished processing, and there is no more data buffered */
        debugs(86, 5, "Telling recipient EOF on READ");
        clientStreamCallback (thisNode, http, NULL, tempBuffer);
        return;
    }

    if (context->reading())
        return;

    /* no data that is ready to send, and still reading? well, lets get some */
    /* secure a buffer */
    if (!context->incoming.getRaw()) {
        /* create a new buffer segment */
        context->buffered = new ESISegment;
        context->incoming = context->buffered;
    }

    assert (context->incoming.getRaw() && context->incoming->len != HTTP_REQBUF_SZ);
    {
        StoreIOBuffer tempBuffer;
        tempBuffer.offset =  context->readpos;
        tempBuffer.length = context->incoming->len - HTTP_REQBUF_SZ;
        tempBuffer.data = &context->incoming->buf[context->incoming->len];
        context->startRead();
        clientStreamRead (thisNode, http, tempBuffer);
    }
}

clientStream_status_t
esiStreamStatus (clientStreamNode *thisNode, ClientHttpRequest *http)
{
    /* Test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    /* we are not in the chain until ESI is detected on a data callback */
    assert (thisNode->node.prev != NULL);
    assert (thisNode->node.next != NULL);

    ESIContext::Pointer context = dynamic_cast<ESIContext *>(thisNode->data.getRaw());
    assert (context.getRaw() != NULL);

    if (context->flags.passthrough)
        return clientStreamStatus (thisNode, http);

    if (context->flags.oktosend && context->flags.finished &&
            !(context->outbound.getRaw() && context->outbound_offset < context->outbound->len)) {
        debugs(86, 5, "Telling recipient EOF on STATUS");
        return STREAM_UNPLANNED_COMPLETE; /* we don't know lengths in advance */
    }

    /* ?? RC: we can't be aborted / fail ? */
    return STREAM_NONE;
}

static int
esiAlwaysPassthrough(http_status sline)
{
    int result;

    switch (sline) {

    case HTTP_CONTINUE: /* Should never reach us... but squid needs to alter to accomodate this */

    case HTTP_SWITCHING_PROTOCOLS: /* Ditto */

    case HTTP_PROCESSING: /* Unknown - some extension */

    case HTTP_NO_CONTENT: /* no body, no esi */

    case HTTP_NOT_MODIFIED: /* ESI does not affect assembled page headers, so 304s are valid */
        result = 1;
        /* unreached */
        break;

    default:
        result = 0;
    }

    return result;
}

void
ESIContext::trimBlanks()
{
    /* trim leading empty buffers ? */

    while (outbound.getRaw() && outbound->next.getRaw() && !outbound->len) {
        debugs(86, 5, "ESIContext::trimBlanks: " << this <<
               " skipping segment " << outbound.getRaw());
        outbound = outbound->next;
    }

    if (outboundtail.getRaw())
        assert (outbound.getRaw());
}

/* Send data downstream
 * Returns 0 if nothing was sent. Non-zero if data was sent.
 */
size_t
ESIContext::send ()
{
    debugs(86, 5, "ESIContext::send: this=" << this);
    /* send any processed data */

    trimBlanks();

    if (!flags.clientwantsdata) {
        debugs(86, 5, "ESIContext::send: Client does not want data - not sending anything");
        return 0;
    }

    if (tree.getRaw() && tree->mayFail()) {
        debugs(86, 5, "ESIContext::send: Tree may fail. Not sending.");
        return 0;
    } else
        flags.oktosend = 1;

#if 0

    if (!flags.oktosend) {

        fatal("ESIContext::send: Not OK to send.\n");
        return 0;
    }

#endif

    if (!(rep || (outbound.getRaw() &&
                  outbound->len && (outbound_offset <= outbound->len)))) {
        debugs(86, 5, "ESIContext::send: Nothing to send.");
        return 0;
    }

    debugs(86, 5, "ESIContext::send: Sending something...");
    /* Yes! Send it without asking for more upstream */
    /* memcopying because the client provided the buffer */
    /* TODO: skip data until pos == next->readoff; */
    assert (thisNode->data == this);
    clientStreamNode *next = thisNode->next();
    ESIContext *templock = cbdataReference (this);
    size_t len = 0;

    if (outbound.getRaw())
        len = min (next->readBuffer.length, outbound->len - outbound_offset);

    /* prevent corruption on range requests, even though we don't support them yet */
    assert (pos == next->readBuffer.offset);

    /* We must send data or a reply */
    assert (len != 0 || rep != NULL);

    if (len) {
        xmemcpy (next->readBuffer.data, &outbound->buf[outbound_offset], len);

        if (len + outbound_offset == outbound->len) {
            ESISegment::Pointer temp = outbound->next;
            /* remove the used buffer */
            outbound_offset = 0;
            outbound = temp;
        }

        pos += len;

        if (!outbound.getRaw())
            outboundtail = NULL;

        trimBlanks();
    }

    flags.clientwantsdata = 0;
    debugs(86, 5, "ESIContext::send: this=" << this << " Client no longer wants data ");
    /* Deal with re-entrancy */
    HttpReply *temprep = rep;
    rep = NULL; /* freed downstream */

    if (temprep && varState)
        varState->buildVary (temprep);

    {
        StoreIOBuffer tempBuffer;
        tempBuffer.length = len;
        tempBuffer.offset = pos - len;
        tempBuffer.data = next->readBuffer.data;
        clientStreamCallback (thisNode, http, temprep, tempBuffer);
    }

    if (len == 0)
        len = 1; /* tell the caller we sent something (because we sent headers */


    cbdataReferenceDone (templock);

    debugs (86,5,"ESIContext::send: this=" << this << " sent " << len);

    return len;
}

void
ESIContext::finishChildren()
{
    if (tree.getRaw())
        tree->finish();

    tree = NULL;
}

/* Detach event from a client Stream */
void
esiStreamDetach (clientStreamNode *thisNode, ClientHttpRequest *http)
{
    /* if we have pending callbacks, tell them we're done. */
    /* test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    ESIContext::Pointer context = dynamic_cast<ESIContext *>(thisNode->data.getRaw());
    assert (context.getRaw() != NULL);
    /* detach from the stream */
    clientStreamDetach (thisNode,http);
    /* if we have pending callbacks (from subincludes), tell them we're done. */
    context->thisNode = NULL;
    context->flags.detached = 1;
    context->finishChildren();
    /* HACK for parser stack not being emptied */
    context->parserState.stack[0] = NULL;
    /* allow refcount logic to trigger */
    context->cbdataLocker = NULL;
}

/* Process incoming data for ESI tags */
/* ESI TODO: Long term: we should have a framework to parse html/xml and
 * callback to a set of processors like thisNode, to prevent multiple parsing
 * overhead. More thoughts on thisNode: We have to parse multiple times, because
 * the output of one processor may create a very different tree. What we could
 * do is something like DOM and pass that down to a final renderer. This is
 * getting into web server territory though...
 *
 * Preconditions:
 *   This is not the last node in the stream.
 *   ESI processing has been enabled.
 *   There is context data or a reply structure
 */
void
esiProcessStream (clientStreamNode *thisNode, ClientHttpRequest *http, HttpReply *rep, StoreIOBuffer receivedData)
{
    /* test preconditions */
    assert (thisNode != NULL);
    /* ESI TODO: handle thisNode rather than asserting - it should only ever
     * happen if we cause an abort and the callback chain
     * loops back to here, so we can simply return. However, that itself
     * shouldn't happen, so it stays as an assert for now. */
    assert (cbdataReferenceValid (thisNode));
    /*
     * if data is NULL thisNode is the first entrance. If rep is also NULL,
     * something is wrong.
     * */
    assert (thisNode->data.getRaw() != NULL || rep);
    assert (thisNode->node.next != NULL);

    if (!thisNode->data.getRaw())
        /* setup ESI context from reply headers */
        thisNode->data = ESIContextNew(rep, thisNode, http);

    ESIContext::Pointer context = dynamic_cast<ESIContext *>(thisNode->data.getRaw());

    assert (context.getRaw() != NULL);

    context->finishRead();

    /* Skipping all ESI processing. All remaining data gets untouched.
     * Mainly used when an error or other non-ESI processable entity
     * has been detected to prevent ESI processing the error body
     */
    if (context->flags.passthrough) {
        clientStreamCallback (thisNode, http, rep, receivedData);
        return;
    }

    debugs(86, 3, "esiProcessStream: Processing thisNode " << thisNode <<
           " context " << context.getRaw() << " offset " <<
           (int) receivedData.offset << " length " <<
           (unsigned int)receivedData.length);

    /* once we finish the template, we *cannot* return here */
    assert (!context->flags.finishedtemplate);
    assert (!context->cachedASTInUse);

    /* Can we generate any data ?*/

    if (receivedData.data) {
        /* Increase our buffer area with incoming data */
        assert (receivedData.length <= HTTP_REQBUF_SZ);
        assert (thisNode->readBuffer.offset == receivedData.offset);
        debugs (86,5, "esiProcessStream found " << receivedData.length << " bytes of body data at offset " << receivedData.offset);
        /* secure the data for later use */

        if (!context->incoming.getRaw()) {
            /* create a new buffer segment */
            debugs(86, 5, "esiProcessStream: Setting up incoming buffer");
            context->buffered = new ESISegment;
            context->incoming = context->buffered;
        }

        if (receivedData.data != &context->incoming->buf[context->incoming->len]) {
            /* We have to copy the data out because we didn't supply thisNode buffer */
            size_t space = HTTP_REQBUF_SZ - context->incoming->len;
            size_t len = min (space, receivedData.length);
            debugs(86, 5, "Copying data from " << receivedData.data << " to " <<
                   &context->incoming->buf[context->incoming->len] <<
                   " because our buffer was not used");

            xmemcpy (&context->incoming->buf[context->incoming->len], receivedData.data, len);
            context->incoming->len += len;

            if (context->incoming->len == HTTP_REQBUF_SZ) {
                /* append another buffer */
                context->incoming->next = new ESISegment;
                context->incoming = context->incoming->next;
            }

            if (len != receivedData.length) {
                /* capture the remnants */
                xmemcpy (context->incoming->buf, &receivedData.data[len], receivedData.length - len);
                context->incoming->len = receivedData.length - len;
            }

            /* and note where we are up to */
            context->readpos += receivedData.length;
        } else {
            /* update our position counters, and if needed assign a new buffer */
            context->incoming->len += receivedData.length;
            assert (context->incoming->len <= HTTP_REQBUF_SZ);

            if (context->incoming->len > HTTP_REQBUF_SZ * 3 / 4) {
                /* allocate a new buffer - to stop us asking for ridiculously small amounts */
                context->incoming->next = new ESISegment;
                context->incoming = context->incoming->next;
            }

            context->readpos += receivedData.length;
        }
    }

    /* EOF / Read error /  aborted entry */
    if (rep == NULL && receivedData.data == NULL && receivedData.length == 0 && !context->flags.finishedtemplate) {
        /* TODO: get stream status to test the entry for aborts */
        /* else flush the esi processor */
        debugs(86, 5, "esiProcess: " << context.getRaw() << " Finished reading upstream data");
        /* This is correct */
        context->flags.finishedtemplate = 1;
    }

    switch (context->kick()) {

    case ESIContext::ESI_KICK_FAILED:
        /* thisNode can not happen - processing can't fail until we have data,
         * and when we come here we have sent data to the client
         */
        return;

    case ESIContext::ESI_KICK_SENT:

    case ESIContext::ESI_KICK_INPROGRESS:
        return;

    case ESIContext::ESI_KICK_PENDING:
        break;
    }

    /* ok.. no data sent, try to pull more data in from upstream.
     * FIXME: Don't try thisNode if we have finished reading the template
     */
    if (!context->flags.finishedtemplate && !context->reading()
            && !context->cachedASTInUse) {
        StoreIOBuffer tempBuffer;
        assert (context->incoming.getRaw() && context->incoming->len < HTTP_REQBUF_SZ);
        tempBuffer.offset = context->readpos;
        tempBuffer.length =  HTTP_REQBUF_SZ - context->incoming->len;
        tempBuffer.data = &context->incoming->buf[context->incoming->len];
        context->startRead();
        clientStreamRead (thisNode, http, tempBuffer);
        return;
    }

    debugs(86, 3, "esiProcessStream: no data to send, no data to read, awaiting a callback");
}

ESIContext::~ESIContext()
{
    freeResources ();
    /* Not freed by freeresources because esi::fail needs it */
    safe_free (errormessage);
    debugs(86, 3, "ESIContext::~ESIContext: Freed " << this);
}

ESIContext *
ESIContextNew (HttpReply *rep, clientStreamNode *thisNode, ClientHttpRequest *http)
{
    assert (rep);
    ESIContext *rv = new ESIContext;
    rv->rep = rep;
    rv->cbdataLocker = rv;

    if (esiAlwaysPassthrough(rep->sline.status)) {
        rv->flags.passthrough = 1;
    } else {
        /* remove specific headers for ESI to prevent
         * downstream cache confusion */
        HttpHeader *hdr = &rep->header;
        hdr->delById(HDR_ACCEPT_RANGES);
        hdr->delById(HDR_ETAG);
        hdr->delById(HDR_CONTENT_LENGTH);
        hdr->delById(HDR_CONTENT_MD5);
        rv->tree = new esiSequence (rv, true);
        rv->thisNode = thisNode;
        rv->http = http;
        rv->flags.clientwantsdata = 1;
        rv->varState = new ESIVarState (&http->request->header, http->uri);
        debugs(86, 5, "ESIContextNew: Client wants data (always created during reply cycle");
    }

    debugs(86, 5, "ESIContextNew: Create context " << rv);
    return rv;
}

ESIElement::ESIElementType_t
ESIElement::IdentifyElement (const char *el)
{
    int offset = 0;
    assert (el);

    if (strlen (el) < 5)
        return ESI_ELEMENT_NONE;

    if (!strncmp (el, "esi:", 4))
        offset = 4;
    else if (!strncmp (el, "http://www.edge-delivery.org/esi/1.0|", 37))
        offset = 37;
    else
        return ESI_ELEMENT_NONE;

    if (!strncmp (el + offset, "otherwise", 9))
        return ESI_ELEMENT_OTHERWISE;

    if (!strncmp (el + offset, "comment", 7))
        return ESI_ELEMENT_COMMENT;

    if (!strncmp (el + offset, "include", 7))
        return ESI_ELEMENT_INCLUDE;

    if (!strncmp (el + offset, "attempt", 7))
        return ESI_ELEMENT_ATTEMPT;

    if (!strncmp (el + offset, "assign", 6))
        return ESI_ELEMENT_ASSIGN;

    if (!strncmp (el + offset, "remove", 6))
        return ESI_ELEMENT_REMOVE;

    if (!strncmp (el + offset, "except", 6))
        return ESI_ELEMENT_EXCEPT;

    if (!strncmp (el + offset, "choose", 6))
        return ESI_ELEMENT_CHOOSE;

    if (!strncmp (el + offset, "vars", 4))
        return ESI_ELEMENT_VARS;

    if (!strncmp (el + offset, "when", 4))
        return ESI_ELEMENT_WHEN;

    if (!strncmp (el + offset, "try", 3))
        return ESI_ELEMENT_TRY;

    return ESI_ELEMENT_NONE;
}

ESIElement::Pointer
ESIContext::ParserState::top()
{
    return stack[stackdepth-1];
}

ESIContext::ParserState::ParserState() : inited_ (false)
{}

bool
ESIContext::ParserState::inited() const
{
    return inited_;
}

void
ESIContext::addStackElement (ESIElement::Pointer element)
{
    /* Put on the stack to allow skipping of 'invalid' markup */
    assert (parserState.stackdepth <11);
    assert (!failed());
    debugs(86, 5, "ESIContext::addStackElement: About to add ESI Node " << element.getRaw());

    if (!parserState.top()->addElement(element)) {
        debugs(86, 1, "ESIContext::addStackElement: failed to add esi node, probable error in ESI template");
        flags.error = 1;
    } else {
        /* added ok, push onto the stack */
        parserState.stack[parserState.stackdepth++] = element;
    }
}

void
ESIContext::start(const char *el, const char **attr, size_t attrCount)
{
    int i;
    unsigned int ellen = strlen (el);
    char localbuf [HTTP_REQBUF_SZ];
    ESIElement::Pointer element;
    int specifiedattcount = attrCount * 2;
    char *pos;
    assert (ellen < sizeof (localbuf)); /* prevent unexpected overruns. */

    debugs(86, 5, "ESIContext::Start: element '" << el << "' with " << specifiedattcount << " tags");

    if (failed())
        /* waiting for expat to finish the buffer we gave it */
        return;

    switch (ESIElement::IdentifyElement (el)) {

    case ESIElement::ESI_ELEMENT_NONE:
        /* Spit out elements we aren't interested in */
        localbuf[0] = '<';
        localbuf[1] = '\0';
        assert (xstrncpy (&localbuf[1], el, sizeof(localbuf) - 2));
        pos = localbuf + strlen (localbuf);

        for (i = 0; i < specifiedattcount && attr[i]; i += 2) {
            *pos++ = ' ';
            /* TODO: handle thisNode gracefully */
            assert (xstrncpy (pos, attr[i], sizeof(localbuf) + (pos - localbuf)));
            pos += strlen (pos);
            *pos++ = '=';
            *pos++ = '\"';
            const char *chPtr = attr[i + 1];
            char ch;
            while ((ch = *chPtr++) != '\0') {
                if (ch == '\"') {
                    assert( xstrncpy(pos, "&quot;", sizeof(localbuf) + (pos-localbuf)) );
                    pos += 6;
                } else {
                    *(pos++) = ch;
                }
            }
            pos += strlen (pos);
            *pos++ = '\"';
        }

        *pos++ = '>';
        *pos = '\0';

        addLiteral (localbuf, pos - localbuf);
        debugs(86, 5, "esi stack depth " << parserState.stackdepth);
        return;
        break;

    case ESIElement::ESI_ELEMENT_COMMENT:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiComment ();
        break;

    case ESIElement::ESI_ELEMENT_INCLUDE:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new ESIInclude (parserState.top().getRaw(), specifiedattcount, attr, this);
        break;

    case ESIElement::ESI_ELEMENT_REMOVE:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = esiRemoveNew ();
        break;

    case ESIElement::ESI_ELEMENT_TRY:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiTry (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_ATTEMPT:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiAttempt (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_EXCEPT:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiExcept (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_VARS:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new ESIVar (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_CHOOSE:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiChoose (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_WHEN:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiWhen (parserState.top().getRaw(), specifiedattcount, attr, varState);
        break;

    case ESIElement::ESI_ELEMENT_OTHERWISE:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiOtherwise (parserState.top().getRaw());
        break;

    case ESIElement::ESI_ELEMENT_ASSIGN:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new ESIAssign (parserState.top().getRaw(), specifiedattcount, attr, this);
        break;
    }

    addStackElement(element);

    debugs(86, 5, "esi stack depth " << parserState.stackdepth);

}  /* End of start handler */

void
ESIContext::end(const char *el)
{
    unsigned int ellen = strlen (el);
    char localbuf [HTTP_REQBUF_SZ];
    char *pos;

    if (flags.error)
        /* waiting for expat to finish the buffer we gave it */
        return;

    switch (ESIElement::IdentifyElement (el)) {

    case ESIElement::ESI_ELEMENT_NONE:
        assert (ellen < sizeof (localbuf)); /* prevent unexpected overruns. */
        /* Add elements we aren't interested in */
        localbuf[0] = '<';
        localbuf[1] = '/';
        assert (xstrncpy (&localbuf[2], el, sizeof(localbuf) - 3));
        pos = localbuf + strlen (localbuf);
        *pos++ = '>';
        *pos = '\0';
        addLiteral (localbuf, pos - localbuf);
        break;

    case ESIElement::ESI_ELEMENT_COMMENT:

    case ESIElement::ESI_ELEMENT_INCLUDE:

    case ESIElement::ESI_ELEMENT_REMOVE:

    case ESIElement::ESI_ELEMENT_TRY:

    case ESIElement::ESI_ELEMENT_ATTEMPT:

    case ESIElement::ESI_ELEMENT_EXCEPT:

    case ESIElement::ESI_ELEMENT_VARS:

    case ESIElement::ESI_ELEMENT_CHOOSE:

    case ESIElement::ESI_ELEMENT_WHEN:

    case ESIElement::ESI_ELEMENT_OTHERWISE:

    case ESIElement::ESI_ELEMENT_ASSIGN:
        /* pop of the stack */
        parserState.stack[--parserState.stackdepth] = NULL;
        break;
    }
}  /* End of end handler */

void
ESIContext::parserDefault (const char *s, int len)
{
    if (failed())
        return;

    /* handle any skipped data */
    addLiteral (s, len);
}

void
ESIContext::parserComment (const char *s)
{
    if (failed())
        return;

    if (!strncmp(s, "esi",3)) {
        debugs(86, 5, "ESIContext::parserComment: ESI <!-- block encountered");
        ESIParser::Pointer tempParser = ESIParser::NewParser (this);

        /* wrap the comment in some tags */

        if (!tempParser->parse("<div>", 5,0) ||
                !tempParser->parse(s + 3, strlen(s) - 3, 0) ||
                !tempParser->parse("</div>",6,1)) {
            debugs(86, 0, "ESIContext::parserComment: Parsing fragment '" << s + 3 << "' failed.");
            setError();
            char tempstr[1024];
            snprintf(tempstr, 1023, "ESIContext::parserComment: Parse error at line %ld:\n%s\n",
                     tempParser->lineNumber(),
                     tempParser->errorString());
            debugs(86, 0, "" << tempstr << "");

            setErrorMessage(tempstr);
        }

        debugs(86, 5, "ESIContext::parserComment: ESI <!-- block parsed");
        return;
    } else {
        char localbuf [HTTP_REQBUF_SZ];
        unsigned int len;
        debugs(86, 5, "ESIContext::parserComment: Regenerating comment block");
        len = strlen (s);

        if (len > sizeof (localbuf) - 9) {
            debugs(86, 0, "ESIContext::parserComment: Truncating long comment");
            len = sizeof (localbuf) - 9;
        }

        xstrncpy(localbuf, "<!--", 5);
        xstrncpy(localbuf + 4, s, len + 1);
        xstrncpy(localbuf + 4 + len, "-->", 4);
        addLiteral (localbuf,len + 7);
    }
}

void
ESIContext::addLiteral (const char *s, int len)
{
    /* handle any skipped data */
    assert (len);
    debugs(86, 5, "literal length is " << len);
    /* give a literal to the current element */
    assert (parserState.stackdepth <11);
    ESIElement::Pointer element (new esiLiteral (this, s, len));

    if (!parserState.top()->addElement(element)) {
        debugs(86, 1, "ESIContext::addLiteral: failed to add esi node, probable error in ESI template");
        flags.error = 1;
    }
}

void
ESIContext::ParserState::init(ESIParserClient *userData)
{
    theParser = ESIParser::NewParser (userData);
    inited_ = true;
}

void
ESIContext::parseOneBuffer()
{
    assert (buffered.getRaw());

    debugs (86,9,"ESIContext::parseOneBuffer: " << buffered->len << " bytes");
    bool lastBlock = buffered->next.getRaw() == NULL && flags.finishedtemplate ? true : false;

    if (! parserState.theParser->parse(buffered->buf, buffered->len, lastBlock)) {
        setError();
        char tempstr[1024];
        snprintf (tempstr, 1023, "esiProcess: Parse error at line %ld:\n%s\n",
                  parserState.theParser->lineNumber(),
                  parserState.theParser->errorString());
        debugs(86, 0, "" << tempstr << "");

        setErrorMessage(tempstr);

        assert (flags.error);

        return;
    }

    if (flags.error) {
        setError();
        return;
    }

    ESISegment::Pointer temp = buffered;
    buffered = temp->next;
}

void
ESIContext::parse()
{
    if (!parserState.stackdepth) {
        debugs(86, 5, "empty parser stack, inserting the top level node");
        assert (tree.getRaw());
        parserState.stack[parserState.stackdepth++] = tree;
    }

    if (rep && !parserState.inited())
        parserState.init(this);

    /* we have data */
    if (buffered.getRaw()) {
        parserState.parsing = 1;
        /* we don't keep any data around */

        PROF_start(esiParsing);

        while (buffered.getRaw() && !flags.error)
            parseOneBuffer();

        PROF_stop(esiParsing);

        /* Tel the read code to allocate a new buffer */
        incoming = NULL;

        parserState.parsing = 0;
    }
}

esiProcessResult_t
ESIContext::process ()
{
    /* parsing:
     * read through buffered, skipping plain text, and skipping any
     * <...> entry that is not an <esi: entry.
     * when it's found, hand an esiLiteral of the preceeding data to our current
     * context
     */

    if (parserState.parsing) {
        /* in middle of parsing - finish here */
        return ESI_PROCESS_PENDING_MAYFAIL;
    }

    assert (flags.finished == 0);

    assert (!flags.error);

    if (!hasCachedAST())
        parse();
    else if (!flags.finishedtemplate)
        getCachedAST();

    if (flags.error) {
        debugs(86, 5, "ESIContext::process: Parsing failed");
        finishChildren ();
        parserState.popAll();
        return ESI_PROCESS_FAILED;
    }

    if (!flags.finishedtemplate && !incoming.getRaw() && !cachedASTInUse) {
        buffered = new ESISegment;
        incoming = buffered;
    }

    if (!flags.finishedtemplate && !cachedASTInUse) {
        return ESI_PROCESS_PENDING_MAYFAIL;
    }

    assert (flags.finishedtemplate || cachedASTInUse);
    updateCachedAST();
    /* ok, we've done all we can with the data. What can we process now?
     */
    {
        esiProcessResult_t status;
        PROF_start(esiProcessing);
        processing = true;
        status = tree->process(0);
        processing = false;

        switch (status) {

        case ESI_PROCESS_COMPLETE:
            debugs(86, 5, "esiProcess: tree Processed OK");
            break;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debugs(86, 5, "esiProcess: tree Processed PENDING OK");
            break;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debugs(86, 5, "esiProcess: tree Processed PENDING UNKNOWN");
            break;

        case ESI_PROCESS_FAILED:
            debugs(86, 0, "esiProcess: tree Processed FAILED");
            setError();

            setErrorMessage("esiProcess: ESI template Processing failed.");

            PROF_stop(esiProcessing);

            return ESI_PROCESS_FAILED;

            break;
        }

        if (status != ESI_PROCESS_PENDING_MAYFAIL && (flags.finishedtemplate || cachedASTInUse)) {
            /* We've read the entire template, and no nodes will
             * return failure
             */
            debugs(86, 5, "esiProcess, request will succeed");
            flags.oktosend = 1;
        }

        if (status == ESI_PROCESS_COMPLETE
                && (flags.finishedtemplate || cachedASTInUse)) {
            /* we've finished all processing. Render and send. */
            debugs(86, 5, "esiProcess, processing complete");
            flags.finished = 1;
        }

        PROF_stop(esiProcessing);
        return status; /* because we have no callbacks */
    }
}

void
ESIContext::ParserState::freeResources()
{
    theParser = NULL;
    inited_ = false;
}

void
ESIContext::ParserState::popAll()
{
    while (stackdepth)
        stack[--stackdepth] = NULL;
}

void
ESIContext::freeResources ()
{
    debugs(86, 5, HERE << "Freeing for this=" << this);

    HTTPMSGUNLOCK(rep);

    finishChildren ();

    if (parserState.inited()) {
        parserState.freeResources();
    }

    parserState.popAll();
    ESISegmentFreeList (buffered);
    ESISegmentFreeList (outbound);
    ESISegmentFreeList (outboundtail);
    delete varState;
    varState=NULL;
    /* don't touch incoming, it's a pointer into buffered anyway */
}

extern ErrorState *clientBuildError (err_type, http_status, char const *, IpAddress &, HttpRequest *);


/* This can ONLY be used before we have sent *any* data to the client */
void
ESIContext::fail ()
{
    debugs(86, 5, "ESIContext::fail: this=" << this);
    /* check preconditions */
    assert (pos == 0);
    /* cleanup current state */
    freeResources ();
    /* Stop altering thisNode request */
    flags.oktosend = 1;
    flags.finished = 1;
    /* don't honour range requests - for errors we send it all */
    flags.error = 1;
    /* create an error object */
    ErrorState * err = clientBuildError(errorpage, errorstatus, NULL, http->getConn()->peer, http->request);
    err->err_msg = errormessage;
    errormessage = NULL;
    rep = err->BuildHttpReply();
    assert (rep->body.mb->contentSize() >= 0);
    size_t errorprogress = rep->body.mb->contentSize();
    /* Tell esiSend where to start sending from */
    outbound_offset = 0;
    /* copy the membuf from the reply to outbound */

    while (errorprogress < (size_t)rep->body.mb->contentSize()) {
        appendOutboundData(new ESISegment);
        errorprogress += outboundtail->append(rep->body.mb->content() + errorprogress, rep->body.mb->contentSize() - errorprogress);
    }

    /* the esiCode now thinks that the error is the outbound,
     * and all processing has finished. */
    /* Send as much as we can */
    send ();

    /* don't cancel anything. The stream nodes will clean up after
     * themselves when the reply is freed - and we don't know what to
     * clean anyway.
     */
}

/* Implementation of ESIElements */

/* esiComment */
esiComment::~esiComment()
{
    debugs(86, 5, "esiComment::~esiComment " << this);
}

esiComment::esiComment()
{}

void
esiComment::finish()
{}

void
esiComment::render(ESISegment::Pointer output)
{
    /* Comments do nothing dude */
    debugs(86, 5, "esiCommentRender: Rendering comment " << this << " into " << output.getRaw());
}

ESIElement::Pointer
esiComment::makeCacheable() const
{
    debugs(86, 5, "esiComment::makeCacheable: returning NULL");
    return NULL;
}

ESIElement::Pointer
esiComment::makeUsable(esiTreeParentPtr, ESIVarState &) const
{
    fatal ("esiComment::Usable: unreachable code!\n");
    return NULL;
}

/* esiLiteral */
esiLiteral::~esiLiteral()
{
    debugs(86, 5, "esiLiteral::~esiLiteral: " << this);
    ESISegmentFreeList (buffer);
    cbdataReferenceDone (varState);
}

esiLiteral::esiLiteral(ESISegment::Pointer aSegment)
{
    buffer = aSegment;
    /* we've been handed a complete, processed string */
    varState = NULL;
    /* Nothing to do */
    flags.donevars = 1;
}

void
esiLiteral::finish()
{}

/* precondition: the buffer chain has at least start + length bytes of data
 */
esiLiteral::esiLiteral(ESIContext *context, const char *s, int numberOfCharacters)
{
    assert (s);
    buffer = new ESISegment;
    ESISegment::Pointer local = buffer;
    size_t start = 0;
    int remainingCharacters = numberOfCharacters;

    while (remainingCharacters > 0) {
        if (local->len == sizeof (local->buf)) {
            local->next = new ESISegment;
            local=local->next;
        }

        size_t len = local->append (&s[start], remainingCharacters);
        start += len;
        remainingCharacters -= len;
    }

    varState = cbdataReference (context->varState);
}

void
esiLiteral::render (ESISegment::Pointer output)
{
    debugs(86, 9, "esiLiteral::render: Rendering " << this);
    /* append the entire chain */
    assert (output->next.getRaw() == NULL);
    output->next = buffer;
    buffer = NULL;
}

esiProcessResult_t
esiLiteral::process (int dovars)
{
    if (flags.donevars)
        return ESI_PROCESS_COMPLETE;

    if (dovars) {
        ESISegment::Pointer temp = buffer;
        /* Ensure variable state is clean */

        while (temp.getRaw()) {
            varState->feedData(temp->buf,temp->len);
            temp = temp->next;
        }

        /* free the pre-processed content */
        ESISegmentFreeList (buffer);

        buffer = varState->extractList ();
    }

    flags.donevars = 1;
    return ESI_PROCESS_COMPLETE;
}

esiLiteral::esiLiteral(esiLiteral const &old) : buffer (old.buffer->cloneList()),
        varState (NULL)
{
    flags.donevars = 0;
}

ESIElement::Pointer
esiLiteral::makeCacheable() const
{
    return new esiLiteral (*this);
}

ESIElement::Pointer
esiLiteral::makeUsable(esiTreeParentPtr , ESIVarState &newVarState) const
{
    debugs(86, 5, "esiLiteral::makeUsable: Creating usable literal");
    esiLiteral * result = new esiLiteral (*this);
    result->varState = cbdataReference (&newVarState);
    return result;
}

/* esiRemove */
void
esiRemoveFree (void *data)
{
    esiRemove *thisNode = (esiRemove *)data;
    debugs(86, 5, "esiRemoveFree " << thisNode);
}

void *
esiRemove::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiRemove));
    void *rv;
    CBDATA_INIT_TYPE_FREECB(esiRemove, esiRemoveFree);
    rv = (void *)cbdataAlloc (esiRemove);
    return rv;
}

void
esiRemove::operator delete (void *address)
{
    cbdataFree (address);
}

ESIElement *
esiRemoveNew ()
{
    return new esiRemove;
}

esiRemove::esiRemove()
{}

void
esiRemove::finish()
{}

void
esiRemove::render(ESISegment::Pointer output)
{
    /* Removes do nothing dude */
    debugs(86, 5, "esiRemoveRender: Rendering remove " << this);
}

/* Accept non-ESI children */
bool
esiRemove::addElement (ESIElement::Pointer element)
{
    if (!dynamic_cast<esiLiteral*>(element.getRaw())) {
        debugs(86, 5, "esiRemoveAdd: Failed for " << this);
        return false;
    }

    return true;
}

ESIElement::Pointer
esiRemove::makeCacheable() const
{
    debugs(86, 5, "esiRemove::makeCacheable: Returning NULL");
    return NULL;
}

ESIElement::Pointer
esiRemove::makeUsable(esiTreeParentPtr, ESIVarState &) const
{
    fatal ("esiRemove::Usable: unreachable code!\n");
    return NULL;
}

/* esiTry */
esiTry::~esiTry()
{
    debugs(86, 5, "esiTry::~esiTry " << this);
}

esiTry::esiTry(esiTreeParentPtr aParent) : parent (aParent) , exceptbuffer(NULL)
{}

void
esiTry::render (ESISegment::Pointer output)
{
    /* Try renders from it's children */
    assert (this);
    assert (attempt.getRaw());
    assert (except.getRaw());
    debugs(86, 5, "esiTryRender: Rendering Try " << this);

    if (flags.attemptok) {
        attempt->render(output);
    } else if (flags.exceptok) {
        /* prerendered */

        if (exceptbuffer.getRaw())
            ESISegment::ListTransfer(exceptbuffer, output);
        else
            except->render(output);
    } else
        debugs(86, 5, "esiTryRender: Neither except nor attempt succeeded?!?");
}

/* Accept attempt and except only */
bool
esiTry::addElement(ESIElement::Pointer element)
{
    debugs(86, 5, "esiTryAdd: Try " << this << " adding element " <<
           element.getRaw());

    if (dynamic_cast<esiLiteral*>(element.getRaw())) {
        /* Swallow whitespace */
        debugs(86, 5, "esiTryAdd: Try " << this << " skipping whitespace " << element.getRaw());
        return true;
    }

    if (dynamic_cast<esiAttempt*>(element.getRaw())) {
        if (attempt.getRaw()) {
            debugs(86, 1, "esiTryAdd: Failed for " << this << " - try allready has an attempt node (section 3.4)");
            return false;
        }

        attempt = element;
        return true;
    }

    if (dynamic_cast<esiExcept*>(element.getRaw())) {
        if (except.getRaw()) {
            debugs(86, 1, "esiTryAdd: Failed for " << this << " - try already has an except node (section 3.4)");
            return false;
        }

        except = element;
        return true;
    }

    debugs(86, 1, "esiTryAdd: Failed to add element " << element.getRaw() << " to try " << this << ", incorrect element type (see section 3.4)");
    return false;
}

esiProcessResult_t
esiTry::bestAttemptRV() const
{
    if (flags.attemptfailed)
        return ESI_PROCESS_COMPLETE;
    else
        return ESI_PROCESS_PENDING_MAYFAIL;
}

esiProcessResult_t
esiTry::process (int dovars)
{
    esiProcessResult_t rv = ESI_PROCESS_PENDING_MAYFAIL;
    assert (this);

    if (!attempt.getRaw()) {
        debugs(86, 0, "esiTryProcess: Try has no attempt element - ESI template is invalid (section 3.4)");
        return ESI_PROCESS_FAILED;
    }

    if (!except.getRaw()) {
        debugs(86, 0, "esiTryProcess: Try has no except element - ESI template is invalid (section 3.4)");
        return ESI_PROCESS_FAILED;
    }

    if (!flags.attemptfailed)
        /* Try the attempt branch */
        switch ((rv = attempt->process(dovars))) {

        case ESI_PROCESS_COMPLETE:
            debugs(86, 5, "esiTryProcess: attempt Processed OK");
            flags.attemptok = 1;
            return ESI_PROCESS_COMPLETE;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debugs(86, 5, "esiTryProcess: attempt Processed PENDING OK");
            /* We're not done yet, but don't need to test except */
            return ESI_PROCESS_PENDING_WONTFAIL;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debugs(86, 5, "eseSequenceProcess: element Processed PENDING UNKNOWN");
            break;

        case ESI_PROCESS_FAILED:
            debugs(86, 5, "esiSequenceProcess: element Processed FAILED");
            flags.attemptfailed = 1;
            break;
        }

    /* attempt is either MAYFAIL or FAILED */
    if (flags.exceptok)
        return bestAttemptRV();

    /* query except to see if it has a definite result */
    if (!flags.exceptfailed)
        /* Try the except branch */
        switch (except->process(dovars)) {

        case ESI_PROCESS_COMPLETE:
            debugs(86, 5, "esiTryProcess: except Processed OK");
            flags.exceptok = 1;
            return bestAttemptRV();

        case ESI_PROCESS_PENDING_WONTFAIL:
            debugs(86, 5, "esiTryProcess: attempt Processed PENDING OK");
            /* We're not done yet, but can't fail */
            return ESI_PROCESS_PENDING_WONTFAIL;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debugs(86, 5, "eseSequenceProcess: element Processed PENDING UNKNOWN");
            /* The except branch fail fail */
            return ESI_PROCESS_PENDING_MAYFAIL;

        case ESI_PROCESS_FAILED:
            debugs(86, 5, "esiSequenceProcess: element Processed FAILED");
            flags.exceptfailed = 1;
            break;
        }

    if (flags.exceptfailed && flags.attemptfailed)
        return ESI_PROCESS_FAILED;

    /* one of attempt or except returned PENDING MAYFAIL */
    return ESI_PROCESS_PENDING_MAYFAIL;
}

void
esiTry::notifyParent()
{
    if (flags.attemptfailed) {
        if (flags.exceptok) {
            parent->provideData (exceptbuffer, this);
            exceptbuffer = NULL;
        } else if (flags.exceptfailed || except.getRaw() == NULL) {
            parent->fail (this, "esi:try - except claused failed, or no except clause found");
        }
    }

    /* nothing to do when except fails and attempt hasn't */
}

void
esiTry::fail(ESIElement *source, char const *anError)
{
    assert (source);
    assert (source == attempt || source == except);
    debugs(86, 5, "esiTry::fail: this=" << this << ", source=" << source << ", message=" << anError);

    if (source == except) {
        flags.exceptfailed = 1;
    } else {
        flags.attemptfailed = 1;
    }

    notifyParent();
}

void
esiTry::provideData (ESISegment::Pointer data, ESIElement* source)
{
    if (source == attempt) {
        flags.attemptok = 1;
        parent->provideData (data, this);
    } else if (source == except) {
        flags.exceptok = 1;
        assert (exceptbuffer == NULL);
        ESISegment::ListTransfer (data, exceptbuffer);
        notifyParent();
    }
}

esiTry::esiTry(esiTry const &old)
{
    attempt = NULL;
    except  = NULL;
    flags.attemptok = 0;
    flags.exceptok = 0;
    flags.attemptfailed = 0;
    flags.exceptfailed = 0;
    parent = NULL;
    exceptbuffer = NULL;
}

ESIElement::Pointer
esiTry::makeCacheable() const
{
    debugs(86, 5, "esiTry::makeCacheable: making cachable Try from " << this);
    esiTry *resultT = new esiTry (*this);
    ESIElement::Pointer result = resultT;

    if (attempt.getRaw())
        resultT->attempt = attempt->makeCacheable();

    if (except.getRaw())
        resultT->except  = except->makeCacheable();

    return result;
}

ESIElement::Pointer
esiTry::makeUsable(esiTreeParentPtr newParent, ESIVarState &newVarState) const
{
    debugs(86, 5, "esiTry::makeUsable: making usable Try from " << this);
    esiTry *resultT = new esiTry (*this);
    ESIElement::Pointer result = resultT;

    resultT->parent = newParent;

    if (attempt.getRaw())
        resultT->attempt = attempt->makeUsable(resultT, newVarState);

    if (except.getRaw())
        resultT->except  = except->makeUsable(resultT, newVarState);

    return result;
}

void
esiTry::finish()
{
    parent = NULL;

    if (attempt.getRaw())
        attempt->finish();

    attempt = NULL;

    if (except.getRaw())
        except->finish();

    except = NULL;
}

/* esiAttempt */
#if 0
void *
esiAttempt::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiAttempt));

}

void
esiAttempt::operator delete (void *address)
{
    cbdataFree (address);
}

#endif

/* esiExcept */
#if 0
void *
esiExcept::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiExcept));
    void *rv;
    CBDATA_INIT_TYPE_FREECB(esiExcept, esiSequence::Free);
    rv = (void *)cbdataAlloc (esiExcept);
    return rv;
}

void
esiExcept::operator delete (void *address)
{
    cbdataFree (address);
}

#endif

/* ESIVar */
#if 0
void *
esiVar::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiVar));
    void *rv;
    CBDATA_INIT_TYPE_FREECB(esiVar, esiSequence::Free);
    rv = (void *)cbdataAlloc (esiVar);
    return rv;
}

void
esiVar::operator delete (void *address)
{
    cbdataFree (address);
}

#endif

/* esiChoose */
esiChoose::~esiChoose()
{
    debugs(86, 5, "esiChoose::~esiChoose " << this);
}

esiChoose::esiChoose(esiTreeParentPtr aParent) : elements (), chosenelement (-1),parent (aParent)
{}

void
esiChoose::render(ESISegment::Pointer output)
{
    /* append all processed elements, and trim processed and rendered elements */
    assert (output->next == NULL);
    assert (elements.size() || otherwise.getRaw());
    debugs(86, 5, "esiChooseRender: rendering");

    if (chosenelement >= 0)
        elements[chosenelement]->render(output);
    else if (otherwise.getRaw())
        otherwise->render(output);
}

bool
esiChoose::addElement(ESIElement::Pointer element)
{
    /* add an element to the output list */

    if (dynamic_cast<esiLiteral*>(element.getRaw())) {
        /* Swallow whitespace */
        debugs(86, 5, "esiChooseAdd: Choose " << this << " skipping whitespace " << element.getRaw());
        return true;
    }

    /* Some elements require specific parents */
    if (!(dynamic_cast<esiWhen*>(element.getRaw()) || dynamic_cast<esiOtherwise*>(element.getRaw()))) {
        debugs(86, 0, "esiChooseAdd: invalid child node for esi:choose (section 3.3)");
        return false;
    }

    if (dynamic_cast<esiOtherwise*>(element.getRaw())) {
        if (otherwise.getRaw()) {
            debugs(86, 0, "esiChooseAdd: only one otherwise node allowed for esi:choose (section 3.3)");
            return false;
        }

        otherwise = element;
    } else {
        elements.push_back (element);

        debugs (86,3, "esiChooseAdd: Added a new element, elements = " << elements.size());

        if (chosenelement == -1)
            if ((dynamic_cast<esiWhen *>(element.getRaw()))->
                    testsTrue()) {
                chosenelement = elements.size() - 1;
                debugs (86,3, "esiChooseAdd: Chose element " << elements.size());
            }
    }

    return true;
}

void
esiChoose::selectElement()
{
    if (chosenelement > -1)
        return;

    for (size_t counter = 0; counter < elements.size(); ++counter) {
        if ((dynamic_cast<esiWhen *>(elements[counter].getRaw()))->
                testsTrue()) {
            chosenelement = counter;
            debugs (86,3, "esiChooseAdd: Chose element " << counter + 1);
            return;
        }
    }
}

void
esiChoose::finish()
{
    elements.setNULL(0, elements.size());

    if (otherwise.getRaw())
        otherwise->finish();

    otherwise = NULL;

    parent = NULL;
}

void
ElementList::setNULL (int start, int end)
{
    assert (start >= 0 && start <= elementcount);
    assert (end >= 0 && end <= elementcount);

    for (int loopPosition = start; loopPosition < end; ++loopPosition) {
        if (elements[loopPosition].getRaw())
            elements[loopPosition]->finish();

        debugs(86, 5, "esiSequence::NULLElements: Setting index " <<
               loopPosition << ", pointer " <<
               elements[loopPosition].getRaw() << " to NULL");

        elements[loopPosition] = NULL;
    }
}

void
esiChoose::NULLUnChosen()
{
    if (chosenelement >= 0) {
        if (otherwise.getRaw())
            otherwise->finish();

        otherwise = NULL;

        elements.setNULL (0, chosenelement);

        elements.setNULL (chosenelement + 1, elements.size());
    } else if (otherwise.getRaw()) {
        elements.setNULL (0, elements.size());
    }
}

esiProcessResult_t
esiChoose::process (int dovars)
{
    /* process as much of the list as we can, stopping only on
     * faliures
     */
    /* We MUST have a when clause */
    NULLUnChosen();

    if (!elements.size()) {
        parent->fail(this);

        if (otherwise.getRaw())
            otherwise->finish();

        otherwise = NULL;

        parent = NULL;

        return ESI_PROCESS_FAILED;
    }

    if (chosenelement >= 0) {
        return elements[chosenelement]->process(dovars);
    } else if (otherwise.getRaw())
        return otherwise->process(dovars);
    else
        return ESI_PROCESS_COMPLETE;
}

void
esiChoose::checkValidSource (ESIElement::Pointer source) const
{
    if (!elements.size())
        fatal ("invalid callback = no when clause\n");

    if (chosenelement >= 0)
        assert (source == elements[chosenelement]);
    else if (otherwise.getRaw())
        assert (source == otherwise);
    else
        fatal ("esiChoose::checkValidSource: invalid callback - no elements chosen\n");
}

void
esiChoose::fail(ESIElement * source, char const *anError)
{
    checkValidSource (source);
    elements.setNULL (0, elements.size());

    if (otherwise.getRaw())
        otherwise->finish();

    otherwise = NULL;

    parent->fail(this, anError);

    parent = NULL;
}

void
esiChoose::provideData (ESISegment::Pointer data, ESIElement*source)
{
    checkValidSource (source);
    parent->provideData (data, this);
}


esiChoose::esiChoose(esiChoose const &old) : chosenelement(-1), otherwise (NULL), parent (NULL)
{
    for (size_t counter = 0; counter < old.elements.size(); ++counter) {
        ESIElement::Pointer newElement = old.elements[counter]->makeCacheable();

        if (newElement.getRaw())
            assert (addElement(newElement));
    }
}

void
esiChoose::makeCachableElements(esiChoose const &old)
{
    for (size_t counter = 0; counter < old.elements.size(); ++counter) {
        ESIElement::Pointer newElement = old.elements[counter]->makeCacheable();

        if (newElement.getRaw())
            assert (addElement(newElement));
    }
}

void
esiChoose::makeUsableElements(esiChoose const &old, ESIVarState &newVarState)
{
    for (size_t counter = 0; counter < old.elements.size(); ++counter) {
        ESIElement::Pointer newElement = old.elements[counter]->makeUsable (this, newVarState);

        if (newElement.getRaw())
            assert (addElement(newElement));
    }
}

ESIElement::Pointer
esiChoose::makeCacheable() const
{
    esiChoose *resultC = new esiChoose (*this);
    ESIElement::Pointer result = resultC;
    resultC->makeCachableElements(*this);

    if (otherwise.getRaw())
        resultC->otherwise = otherwise->makeCacheable();

    return result;
}

ESIElement::Pointer
esiChoose::makeUsable(esiTreeParentPtr newParent, ESIVarState &newVarState) const
{
    esiChoose *resultC = new esiChoose (*this);
    ESIElement::Pointer result = resultC;
    resultC->parent = newParent;
    resultC->makeUsableElements(*this, newVarState);
    resultC->selectElement();

    if (otherwise.getRaw())
        resultC->otherwise = otherwise->makeUsable(resultC, newVarState);

    return result;
}

/* ElementList */
ElementList::ElementList () : elements(NULL), allocedcount(0), allocedsize(0), elementcount (0)
{}

ElementList::~ElementList()
{
    debugs(86, 5, "ElementList::~ElementList " << this);
    setNULL(0, elementcount);

    if (elements)
        memFreeBuf (allocedsize, elements);
}

ESIElement::Pointer &
ElementList::operator [] (int index)
{
    return elements[index];
}

ESIElement::Pointer const &
ElementList::operator [] (int index) const
{
    return elements[index];
}

void
ElementList::pop_front (size_t const count)
{
    if (!count)
        return;

    xmemmove (elements, &elements[count], (elementcount - count)  * sizeof (ESIElement::Pointer));

    elementcount -= count;
}

void
ElementList::push_back(ESIElement::Pointer &newElement)
{
    elements = (ESIElement::Pointer *)memReallocBuf (elements, ++elementcount * sizeof (ESIElement::Pointer),
               &allocedsize);
    assert (elements);
    allocedcount = elementcount;
    memset(&elements[elementcount - 1], '\0', sizeof (ESIElement::Pointer));
    elements[elementcount - 1] = newElement;
}

size_t
ElementList::size() const
{
    return elementcount;
}

/* esiWhen */
esiWhen::esiWhen (esiTreeParentPtr aParent, int attrcount, const char **attr,ESIVarState *aVar) : esiSequence (aParent)
{
    varState = NULL;
    char const *expression = NULL;

    for (int loopCounter = 0; loopCounter < attrcount && attr[loopCounter]; loopCounter += 2) {
        if (!strcmp(attr[loopCounter],"test")) {
            /* evaluate test */
            debugs(86, 5, "esiWhen::esiWhen: Evaluating '" << attr[loopCounter+1] << "'");
            /* TODO: warn the user instead of asserting */
            assert (expression == NULL);
            expression = attr[loopCounter+1];
        } else {
            /* ignore mistyped attributes.
             * TODO:? error on these for user feedback - config parameter needed
             */
            debugs(86, 1, "Found misttyped attribute on ESI When clause");
        }
    }

    /* No expression ? default is not matching */
    if (!expression)
        return;

    unevaluatedExpression = xstrdup(expression);

    varState = cbdataReference (aVar);

    evaluate();
}

esiWhen::~esiWhen()
{
    safe_free (unevaluatedExpression);

    if (varState)
        cbdataReferenceDone (varState);
}

void
esiWhen::evaluate()
{
    if (!unevaluatedExpression)
        return;

    assert (varState);

    varState->feedData(unevaluatedExpression, strlen (unevaluatedExpression));

    char const *expression = varState->extractChar ();

    setTestResult(ESIExpression::Evaluate (expression));

    safe_free (expression);
}

esiWhen::esiWhen(esiWhen const &old) : esiSequence (old)
{
    unevaluatedExpression = NULL;

    if (old.unevaluatedExpression)
        unevaluatedExpression = xstrdup(old.unevaluatedExpression);

    varState = NULL;
}

ESIElement::Pointer
esiWhen::makeCacheable() const
{
    return new esiWhen(*this);
}

ESIElement::Pointer
esiWhen::makeUsable(esiTreeParentPtr newParent, ESIVarState &newVarState) const
{
    esiWhen *resultW = new esiWhen (*this);
    ESIElement::Pointer result = resultW;
    resultW->parent = newParent;
    resultW->makeUsableElements(*this, newVarState);
    resultW->varState = cbdataReference (&newVarState);
    resultW->evaluate();
    return result;
}

/* esiOtherwise */
#if 0
void *
esiOtherwise::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiOtherwise));
    void *rv;
    CBDATA_INIT_TYPE_FREECB(esiOtherwise, esiSequence::Free);
    rv = (void *)cbdataAlloc (esiOtherwise);
    return rv;
}

void
esiOtherwise::operator delete (void *address)
{
    cbdataFree (address);
}

#endif

/* TODO: implement surrogate targeting and control processing */
int
esiEnableProcessing (HttpReply *rep)
{
    int rv = 0;

    if (rep->header.has(HDR_SURROGATE_CONTROL)) {
        HttpHdrScTarget *sctusable = httpHdrScGetMergedTarget (rep->surrogate_control,
                                     Config.Accel.surrogate_id);

        if (!sctusable || sctusable->content.size() == 0)
            /* Nothing generic or targeted at us, or no
             * content processing requested
             */
            return 0;

        if (sctusable->content.pos("ESI/1.0") != NULL)
            rv = 1;

        httpHdrScTargetDestroy (sctusable);
    }

    return rv;
}

#endif /* USE_SQUID_ESI == 1 */

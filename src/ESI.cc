
/*
 * $Id: ESI.cc,v 1.2 2003/03/11 08:24:42 robertc Exp $
 *
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
#include "ESI.h"
#include "clientStream.h"
#include "client_side_request.h"
#include "ESISegment.h"
#include "ESIElement.h"
#include "ESIContext.h"
#include "HttpReply.h"
#include "ESIAttempt.h"
#include "ESIExcept.h"
#include "client_side.h"

/* quick reference on behaviour here.
 * The ESI specification 1.0 requires the ESI processor to be able to 
 * return an error code at any point in the processing. To that end 
 * we buffer the incoming esi body until we know we will be able to 
 * satisfy the request. At that point we start streaming the queued
 * data downstream.
 *
 */

typedef struct _esiStreamContext esiStreamContext;

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


/* esi variable replacement logic */

typedef enum {
    ESI_BROWSER_MSIE,
    ESI_BROWSER_MOZILLA,
    ESI_BROWSER_OTHER
} esiBrowser_t;

static char const * esiBrowsers[]=
    {"MSIE",
     "MOZILLA",
     "OTHER"
    };

/* Recursive uses are not supported by design */

struct _query_elem{char *var, *val;};

struct esiVarState
{
    ESISegment::Pointer extractList();
    char *extractChar();
    void feedData (const char *buf, size_t len);
    void buildVary (HttpReply *rep);

    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;
    void freeResources();
    esiVarState (HttpHeader const *hdr, char const *uri);

private:
    char *getProductVersion (char const *s);
    ESISegment::Pointer input;
    ESISegment::Pointer output;
    HttpHeader hdr;

    struct _query_elem *query;
    size_t query_sz;
    size_t query_elements;
    char *query_string;

    struct
    {

int language:
        1;

int cookie:
        1;

int host:
        1;

int referer:
        1;

int useragent:
        1;
    }

    flags;
    esiBrowser_t browser;
    char *browserversion;
    enum esiVar_t {
        ESI_VAR_LANGUAGE,
        ESI_VAR_COOKIE,
        ESI_VAR_HOST,
        ESI_VAR_REFERER,
        ESI_VAR_USERAGENT,
        ESI_QUERY_STRING,
        ESI_VAR_OTHER
    };
    void doIt ();
    void eval (esiVar_t type, char const *, char const *);
    enum esiUserOs_t{
        ESI_OS_WIN,
        ESI_OS_MAC,
        ESI_OS_UNIX,
        ESI_OS_OTHER
    } UserOs;
    static char const * esiUserOs[];
    static esiVar_t GetVar(char *s, int len);
    bool validChar (char c);
};

CBDATA_TYPE (esiVarState);
FREE esiVarStateFree;

char const *esiVarState::esiUserOs[]=
    {
        "WIN",
        "MAC",
        "UNIX",
        "OTHER"
    };


extern int esiExpressionEval (char const *);

typedef ESIContext::esiKick_t esiKick_t;


/* some core operators */

/* esiComment */

struct esiComment : public ESIElement
{
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf()const;
    ~esiComment();
    esiComment();
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;

    void render(ESISegment::Pointer);
    void finish();

private:
    static MemPool *pool;
};

MemPool * esiComment::pool = NULL;

#include "ESILiteral.h"
MemPool *esiLiteral::pool = NULL;

#include "ESISequence.h"

/* esiInclude */

struct esiInclude : public ESIElement
{
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;

    esiInclude(esiTreeParentPtr, int attributes, const char **attr, ESIContext *);
    ~esiInclude();
    void render(ESISegment::Pointer);
    esiProcessResult_t process (int dovars);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;
    void subRequestDone (esiStreamContext *, bool);

    struct
    {

int onerrorcontinue:
        1; /* on error return zero data */

int failed:
        1; /* Failed to process completely */

int finished:
        1; /* Finished getting subrequest data */
    }

    flags;
    esiStreamContext *src;
    esiStreamContext *alt;
    ESISegment::Pointer srccontent;
    ESISegment::Pointer altcontent;
    esiVarState *varState;
    char *srcurl, *alturl;
    void fail(esiStreamContext *);
    void finish();

private:
    static MemPool *Pool;
    static void Start (esiStreamContext *, char const *, esiVarState *);
    esiTreeParentPtr parent;
    void start();
    bool started;
    bool sent;
    esiInclude(esiInclude const &);
    bool dataNeeded() const;
};

MemPool *esiInclude::Pool = NULL;

/* esiRemove */

class esiRemove : public ESIElement
{

public:
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;

    esiRemove();
    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;
    void finish();
};

CBDATA_TYPE (esiRemove);
static FREE esiRemoveFree;
static ESIElement * esiRemoveNew(void);


/* esiTry */

struct esiTry : public ESIElement
{
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;

    esiTry(esiTreeParentPtr aParent);
    ~esiTry();

    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    void fail(ESIElement *);
    esiProcessResult_t process (int dovars);
    void provideData (ESISegment::Pointer data, ESIElement * source);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;

    ESIElement::Pointer attempt;
    ESIElement::Pointer except;

    struct
    {

int attemptok:
        1; /* the attempt branch process correctly */

int exceptok:
        1; /* likewise */

int attemptfailed:
        1; /* The attempt branch failed */

int exceptfailed:
        1; /* the except branch failed */
    }

    flags;
    void finish();

private:
    static MemPool *Pool;
    void notifyParent();
    esiTreeParentPtr parent;
    ESISegment::Pointer exceptbuffer;
    esiTry (esiTry const &);
    esiProcessResult_t bestAttemptRV() const;
};

MemPool *esiTry::Pool = NULL;

/* esiVar */

struct esiVar:public esiSequence
{
    //    void *operator new (size_t byteCount);
    //    void operator delete (void *address);
    void deleteSelf() const;
    esiVar(esiTreeParentPtr aParent) : esiSequence (aParent)
    {
        flags.dovars = 1;
    }
};

/* esiChoose */

struct esiChoose : public ESIElement
{
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;

    esiChoose(esiTreeParentPtr);
    ~esiChoose();

    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    void fail(ESIElement *);
    esiProcessResult_t process (int dovars);

    void provideData (ESISegment::Pointer data, ESIElement *source);
    void makeCachableElements(esiChoose const &old);
    void makeUsableElements(esiChoose const &old, esiVarState &);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;
    void NULLUnChosen();

    ElementList elements;
    int chosenelement;
    ESIElement::Pointer otherwise;
    void finish();

private:
    static MemPool *Pool;
    esiChoose(esiChoose const &);
    esiTreeParentPtr parent;
    void checkValidSource (ESIElement::Pointer source) const;
    void selectElement();
};

MemPool *esiChoose::Pool = NULL;

/* esiWhen */

struct esiWhen : public esiSequence
{
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void deleteSelf() const;
    esiWhen(esiTreeParentPtr aParent, int attributes, const char **attr, esiVarState *);
    ~esiWhen();
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, esiVarState &) const;

    bool testsTrue() const { return testValue;}

    void setTestResult(bool aBool) {testValue = aBool;}

private:
    static MemPool *Pool;
    esiWhen (esiWhen const &);
    bool testValue;
    char const *unevaluatedExpression;
    esiVarState *varState;
    void evaluate();
};

MemPool *esiWhen::Pool = NULL;

/* esiOtherwise */

struct esiOtherwise : public esiSequence
{
    //    void *operator new (size_t byteCount);
    //    void operator delete (void *address);
    void deleteSelf() const;
    esiOtherwise(esiTreeParentPtr aParent) : esiSequence (aParent) {}}

;

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

typedef RefCount<esiInclude> esiIncludePtr;

struct _esiStreamContext
{

public:
    void *operator new(size_t);
    _esiStreamContext();
    int finished;
    esiIncludePtr include;
    ESISegment::Pointer localbuffer;
    ESISegment::Pointer buffer;
};

CBDATA_TYPE (esiStreamContext);

_esiStreamContext::_esiStreamContext() : finished(false), include (NULL), localbuffer (new ESISegment), buffer (NULL)
{}

/* Local functions */
/* ESIContext */
static ESIContext *ESIContextNew(HttpReply *, clientStreamNode *, clientHttpRequest *);
/* esiStreamContext */
static FREE esiStreamContextFree;
static esiStreamContext *esiStreamContextNew (esiIncludePtr);

/* other */
static CSCB esiBufferRecipient;
static CSD esiBufferDetach;

/* ESI TO CONSIDER:
 * 1. retry failed upstream requests
 */

void *
ESIContext::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (ESIContext));
    CBDATA_INIT_TYPE(ESIContext);
    ESIContext *result = cbdataAlloc(ESIContext);
    /* Mark result as being owned - we want the refcounter to do the
     * delete call
     */
    cbdataReference(result);
    return result;
}

void
ESIContext::operator delete (void *address)
{
    ESIContext *t = static_cast<ESIContext *>(address);
    cbdataFree(t);
    /* And allow the memory to be freed */
    cbdataReferenceDone (address);
}

void
ESIContext::deleteSelf() const
{
    delete this;
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
    debug (86,9)("ESIContext::appendOutboundData: outbound %p\n", outbound.getRaw());
}

void
ESIContext::provideData (ESISegment::Pointer theData, ESIElement * source)
{
    debug (86,5)("ESIContext::provideData: %p %p %p\n",this, theData.getRaw(), source);
    /* No callbacks permitted after finish() called on the tree */
    assert (tree.getRaw());
    assert (source == tree);
    appendOutboundData(theData);
    trimBlanks();

    if (!processing)
        send();
}

void
ESIContext::fail (ESIElement * source)
{
    setError();
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
        debug (86,5)("esiKick: Re-entered whilst in progress\n");
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
            debug (86,5)("esiKick: esiProcess OK\n");
            break;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debug (86,5)("esiKick: esiProcess PENDING OK\n");
            break;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debug (86,5)("esiKick: esiProcess PENDING UNKNOWN\n");
            break;

        case ESI_PROCESS_FAILED:
            debug (86,0)("esiKick: esiProcess %p FAILED\n", this);
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
esiStreamRead (clientStreamNode *thisNode, clientHttpRequest *http)
{
    clientStreamNode *next;
    ESIContext *context;
    /* Test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    /* we are not in the chain until ESI is detected on a data callback */
    assert (thisNode->data != NULL);
    assert (thisNode->node.prev != NULL);
    assert (thisNode->node.next != NULL);

    context = (ESIContext *)cbdataReference (thisNode->data);

    if (context->flags.passthrough) {
        /* passthru mode - read into supplied buffers */
        next = thisNode->next();
        clientStreamRead (thisNode, http, next->readBuffer);
        cbdataReferenceDone (context);
        return;
    }

    context->flags.clientwantsdata = 1;
    debug (86,5)("esiStreamRead: Client now wants data\n");

    /* Ok, not passing through */

    switch (context->kick ()) {

    case ESIContext::ESI_KICK_FAILED:
        /* this can not happen - processing can't fail until we have data,
         * and when we come here we have sent data to the client
         */

    case ESIContext::ESI_KICK_SENT:

    case ESIContext::ESI_KICK_INPROGRESS:
        cbdataReferenceDone (context);
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
        debug (86,5) ("esiStreamRead: Waiting for async resume of esi processing\n");
        cbdataReferenceDone (context);
        return;
    }

    if (context->flags.oktosend && context->flags.finished && context->outbound.getRaw()) {
        debug (86,5)("all processing complete, but outbound data still buffered\n");
        assert (!context->flags.clientwantsdata);
        /* client MUST be processing the last reply */
        cbdataReferenceDone (context);
        return;
    }


    if (context->flags.oktosend && context->flags.finished) {
        StoreIOBuffer tempBuffer;
        assert (!context->outbound.getRaw());
        /* We've finished processing, and there is no more data buffered */
        debug (86,5)("Telling recipient EOF on READ\n");
        clientStreamCallback (thisNode, http, NULL, tempBuffer);
        cbdataReferenceDone (context);
        return;
    }

    if (context->reading()) {
        cbdataReferenceDone (context);
        return;
    }

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

    cbdataReferenceDone (context);
}

clientStream_status_t
esiStreamStatus (clientStreamNode *thisNode, clientHttpRequest *http)
{
    /* Test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    /* we are not in the chain until ESI is detected on a data callback */
    assert (thisNode->data != NULL);
    assert (thisNode->node.prev != NULL);
    assert (thisNode->node.next != NULL);

    ESIContext *context = (ESIContext *)cbdataReference (thisNode->data);

    if (context->flags.passthrough) {
        cbdataReferenceDone (context);
        return clientStreamStatus (thisNode, http);
    }

    if (context->flags.oktosend && context->flags.finished &&
            !(context->outbound.getRaw() && context->outbound_offset < context->outbound->len)) {
        cbdataReferenceDone (context);
        debug (86,5) ("Telling recipient EOF on STATUS\n");
        return STREAM_UNPLANNED_COMPLETE; /* we don't know lengths in advance */
    }

    /* ?? RC: we can't be aborted / fail ? */
    cbdataReferenceDone (context);

    return STREAM_NONE;
}

static int
esiAlwaysPassthrough(http_status sline)
{
    switch (sline) {

    case HTTP_CONTINUE: /* Should never reach us... but squid needs to alter to accomodate this */

    case HTTP_SWITCHING_PROTOCOLS: /* Ditto */

    case HTTP_PROCESSING: /* Unknown - some extension */

    case HTTP_NO_CONTENT: /* no body, no esi */

    case HTTP_NOT_MODIFIED: /* ESI does not affect assembled page headers, so 304s are valid */
        return 1;
        /* unreached */
        break;

    default:
        return 0;
    }
}

void
ESIContext::trimBlanks()
{
    /* trim leading empty buffers ? */

    while (outbound.getRaw() && outbound->next.getRaw() && !outbound->len) {
        debug(86,5)("ESIContext::trimBlanks: %p skipping segment %p\n", this, outbound.getRaw());
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
    debug (86,5)("ESIContext::send: this=%p\n",this);
    /* send any processed data */

    trimBlanks();

    if (!flags.clientwantsdata) {
        debug (86,5)("ESIContext::send: Client does not want data - not sending anything\n");
        return 0;
    }

    if (tree.getRaw() && tree->mayFail()) {
        debug (86, 5)("ESIContext::send: Tree may fail. Not sending.\n");
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
        debug (86,5)("ESIContext::send: Nothing to send.\n");
        return 0;
    }

    debug (86,5)("ESIContext::send: Sending something...\n");
    /* Yes! Send it without asking for more upstream */
    /* memcopying because the client provided the buffer */
    /* TODO: skip data until pos == next->readoff; */
    assert (thisNode->data == this);
    clientStreamNode *next = thisNode->next();
    cbdataReference (this);
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
    debug (86,5)("ESIContext::send: this=%p Client no longer wants data \n",this);
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

    ESIContext *temp = this;

    cbdataReferenceDone (temp);

    debug (86,5)("ESIContext::send: this=%p sent %d\n",this,len);

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
esiStreamDetach (clientStreamNode *thisNode, clientHttpRequest *http)
{
    /* if we have pending callbacks, tell them we're done. */
    ESIContext *context;
    /* test preconditions */
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));
    context = ( ESIContext *)cbdataReference(thisNode->data);
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
    cbdataReferenceDone (context);
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
esiProcessStream (clientStreamNode *thisNode, clientHttpRequest *http, HttpReply *rep, StoreIOBuffer recievedData)
{
    ESIContext *context;
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
    assert (thisNode->data != NULL || rep);
    assert (thisNode->node.next != NULL);

    if (!thisNode->data)
        /* setup ESI context from reply headers */
        thisNode->data = ESIContextNew(rep, thisNode, http);

    context = (ESIContext *)cbdataReference(thisNode->data);

    context->finishRead();

    /* Skipping all ESI processing. All remaining data gets untouched.
     * Mainly used when an error or other non-ESI processable entity
     * has been detected to prevent ESI processing the error body
     */
    if (context->flags.passthrough) {
        cbdataReferenceDone(context);
        clientStreamCallback (thisNode, http, rep, recievedData);
        return;
    }

    debug (86, 3)("esiProcessStream: Processing thisNode %p context %p offset %d length %u\n",thisNode, context, (int) recievedData.offset, (unsigned int)recievedData.length);

    /* once we finish the template, we *cannot* return here */
    assert (!context->flags.finishedtemplate);
    assert (!context->cachedASTInUse);

    /* Can we generate any data ?*/

    if (recievedData.data) {
        /* Increase our buffer area with incoming data */
        assert (recievedData.length <= HTTP_REQBUF_SZ);
        assert (thisNode->readBuffer.offset == recievedData.offset);
        debug (86,5)("esiProcessStream found %u bytes of body data at offset %ld\n", recievedData.length, recievedData.offset);
        /* secure the data for later use */

        if (!context->incoming.getRaw()) {
            /* create a new buffer segment */
            debug (86,5) ("esiProcessStream: Setting up incoming buffer\n");
            context->buffered = new ESISegment;
            context->incoming = context->buffered;
        }

        if (recievedData.data != &context->incoming->buf[context->incoming->len]) {
            /* We have to copy the data out because we didn't supply thisNode buffer */
            size_t space = HTTP_REQBUF_SZ - context->incoming->len;
            size_t len = min (space, recievedData.length);
            debug (86,5)("Copying data from %p to %p because our buffer was not used\n", recievedData.data,
                         &context->incoming->buf[context->incoming->len]);
            xmemcpy (&context->incoming->buf[context->incoming->len], recievedData.data, len);
            context->incoming->len += len;

            if (context->incoming->len == HTTP_REQBUF_SZ) {
                /* append another buffer */
                context->incoming->next = new ESISegment;
                context->incoming = context->incoming->next;
            }

            if (len != recievedData.length) {
                /* capture the remnants */
                xmemcpy (context->incoming->buf, &recievedData.data[len], recievedData.length - len);
                context->incoming->len = recievedData.length - len;
            }

            /* and note where we are up to */
            context->readpos += recievedData.length;
        } else {
            /* update our position counters, and if needed assign a new buffer */
            context->incoming->len += recievedData.length;
            assert (context->incoming->len <= HTTP_REQBUF_SZ);

            if (context->incoming->len > HTTP_REQBUF_SZ * 3 / 4) {
                /* allocate a new buffer - to stop us asking for ridiculously small amounts */
                context->incoming->next = new ESISegment;
                context->incoming = context->incoming->next;
            }

            context->readpos += recievedData.length;
        }
    }

    /* EOF / Read error /  aborted entry */
    if (rep == NULL && recievedData.data == NULL && recievedData.length == 0 && !context->flags.finishedtemplate) {
        /* TODO: get stream status to test the entry for aborts */
        /* else flush the esi processor */
        debug (86,5)("esiProcess: %p Finished reading upstream data\n", context);
        /* This is correct */
        context->flags.finishedtemplate = 1;
    }

    switch (context->kick()) {

    case ESIContext::ESI_KICK_FAILED:
        /* thisNode can not happen - processing can't fail until we have data,
         * and when we come here we have sent data to the client
         */
        cbdataReferenceDone (context);
        return;

    case ESIContext::ESI_KICK_SENT:

    case ESIContext::ESI_KICK_INPROGRESS:
        cbdataReferenceDone (context);
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
        cbdataReferenceDone (context);
        return;
    }

    debug (86,3)("esiProcessStream: no data to send, no data to read, awaiting a callback\n");
    cbdataReferenceDone(context);
}

ESIContext::~ESIContext()
{
    freeResources ();
    /* Not freed by freeresources because esi::fail needs it */
    safe_free (errormessage);
    debug (86,3)("ESIContext::~ESIContext: Freed %p\n", this);
}

ESIContext *
ESIContextNew (HttpReply *rep, clientStreamNode *thisNode, clientHttpRequest *http)
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
        httpHeaderDelById(hdr, HDR_ACCEPT_RANGES);
        httpHeaderDelById(hdr, HDR_ETAG);
        httpHeaderDelById(hdr, HDR_CONTENT_LENGTH);
        httpHeaderDelById(hdr, HDR_CONTENT_MD5);
        rv->tree = new esiSequence (rv, true);
        rv->thisNode = thisNode;
        rv->http = http;
        rv->flags.clientwantsdata = 1;
        rv->varState = new esiVarState (&http->request->header, http->uri);
        debug (86,5)("ESIContextNew: Client wants data (always created during reply cycle\n");
    }

    debug (86,5)("ESIContextNew: Create context %p\n",rv);
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
    debug (86,5)("ESIContext::addStackElement: About to add ESI Node %p\n", element.getRaw());

    if (!parserState.top()->addElement(element)) {
        debug (86,1)("ESIContext::addStackElement: failed to add esi node, probable error in ESI template\n");
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

    debug (86, 5)("ESIContext::Start: element '%s' with %d tags\n", el, specifiedattcount);

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
            *pos++ = '\'';
            assert (xstrncpy (pos, attr[i + 1], sizeof(localbuf) + (pos - localbuf)));
            pos += strlen (pos);
            *pos++ = '\'';
        }

        *pos++ = '>';
        *pos = '\0';

        addLiteral (localbuf, pos - localbuf);
        debug (86,5)("esi stack depth %d\n",parserState.stackdepth);
        return;
        break;

    case ESIElement::ESI_ELEMENT_COMMENT:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiComment ();
        break;

    case ESIElement::ESI_ELEMENT_INCLUDE:
        /* Put on the stack to allow skipping of 'invalid' markup */
        element = new esiInclude (parserState.top().getRaw(), specifiedattcount, attr, this);
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
        element = new esiVar (parserState.top().getRaw());
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
    }

    addStackElement(element);

    debug (86,5)("esi stack depth %d\n",parserState.stackdepth);

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
        debug (86,5)("ESIContext::parserComment: ESI <!-- block encountered\n");
        ESIParser::Pointer tempParser = ESIParser::NewParser (this);

        /* wrap the comment in some tags */

        if (!tempParser->parse("<div>", 5,0) ||
                !tempParser->parse(s + 3, strlen(s) - 3, 0) ||
                !tempParser->parse("</div>",6,1)) {
            debug (86,0)("ESIContext::parserComment: Parsing fragment '%s' failed.\n", s + 3);
            setError();
            char tempstr[1024];
            snprintf(tempstr, 1023, "ESIContext::parserComment: Parse error at line %d:\n%s\n",
                     tempParser->lineNumber(),
                     tempParser->errorString());
            debug (86,0)("%s",tempstr);

            if (!errormessage)
                errormessage = xstrdup (tempstr);
        }

        debug (86,5)("ESIContext::parserComment: ESI <!-- block parsed\n");
        return;
    } else {
        char localbuf [HTTP_REQBUF_SZ];
        unsigned int len;
        debug (86,5)("ESIContext::parserComment: Regenerating comment block\n");
        len = strlen (s);

        if (len > sizeof (localbuf) - 9) {
            debug (86,0)("ESIContext::parserComment: Truncating long comment\n");
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
    debug (86,5)("literal length is %d\n", len);
    /* give a literal to the current element */
    assert (parserState.stackdepth <11);
    ESIElement::Pointer element (new esiLiteral (this, s, len));

    if (!parserState.top()->addElement(element)) {
        debug (86,1)("ESIContext::addLiteral: failed to add esi node, probable error in ESI template\n");
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

    debug (86,9)("ESIContext::parseOneBuffer: %d bytes\n",buffered->len);
    bool lastBlock = buffered->next.getRaw() == NULL && flags.finishedtemplate ? true : false;

    if (! parserState.theParser->parse(buffered->buf, buffered->len, lastBlock)) {
        setError();
        char tempstr[1024];
        snprintf (tempstr, 1023, "esiProcess: Parse error at line %d:\n%s\n",
                  parserState.theParser->lineNumber(),
                  parserState.theParser->errorString());
        debug (86,0)("%s", tempstr);

        if (!errormessage)
            errormessage = xstrdup (tempstr);

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
        debug (86,5)("empty parser stack, inserting the top level node\n");
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
        debug (86,5) ("ESIContext::process: Parsing failed\n");
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

        switch (status)
        {

        case ESI_PROCESS_COMPLETE:
            debug (86,5)("esiProcess: tree Processed OK\n");
            break;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debug (86,5)("esiProcess: tree Processed PENDING OK\n");
            break;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debug (86,5)("esiProcess: tree Processed PENDING UNKNOWN\n");
            break;

        case ESI_PROCESS_FAILED:
            debug (86,0)("esiProcess: tree Processed FAILED\n");
            setError();

            if (!errormessage)
                errormessage = xstrdup("esiProcess: ESI template Processing failed.");

            PROF_stop(esiProcessing);

            return ESI_PROCESS_FAILED;

            break;
        }

        if (status != ESI_PROCESS_PENDING_MAYFAIL && (flags.finishedtemplate || cachedASTInUse))
        {
            /* We've read the entire template, and no nodes will
             * return failure
             */
            debug (86,5)("esiProcess, request will succeed\n");
            flags.oktosend = 1;
        }

        if (status == ESI_PROCESS_COMPLETE
                && (flags.finishedtemplate || cachedASTInUse))
        {
            /* we've finished all processing. Render and send. */
            debug (86,5)("esiProcess, processing complete\n");
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
    debug (86,5)("ESIContext::freeResources: Freeing for this=%p\n",this);

    if (rep) {
        httpReplyDestroy(rep);
        rep = NULL;
    }

    finishChildren ();

    if (parserState.inited()) {
        parserState.freeResources();
    }

    parserState.popAll();
    ESISegmentFreeList (buffered);
    ESISegmentFreeList (outbound);
    ESISegmentFreeList (outboundtail);
    cbdataFree (varState);
    /* don't touch incoming, it's a pointer into buffered anyway */
}

extern ErrorState *clientBuildError (err_type, http_status, char const *, struct in_addr *, request_t *);


/* This can ONLY be used before we have sent *any* data to the client */
void
ESIContext::fail ()
{
    debug (86,5)("ESIContext::fail: this=%p\n",this);
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
    ErrorState * err = clientBuildError(errorpage, errorstatus, NULL,
                                        http->conn ? &http->conn->peer.sin_addr : &no_addr, http->request);
    err->err_msg = errormessage;
    errormessage = NULL;
    rep = errorBuildReply (err);
    assert (rep->body.mb.size >= 0);
    size_t errorprogress = rep->body.mb.size;
    /* Tell esiSend where to start sending from */
    outbound_offset = 0;
    /* copy the membuf from the reply to outbound */

    while (errorprogress < (size_t)rep->body.mb.size) {
        appendOutboundData(new ESISegment);
        errorprogress += outboundtail->append(rep->body.mb.buf + errorprogress, rep->body.mb.size - errorprogress);
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

/* Detach from a buffering stream
 */
void
esiBufferDetach (clientStreamNode *node, clientHttpRequest *http)
{
    /* Detach ourselves */
    clientStreamDetach (node, http);
}

/*
 * Write a chunk of data to a client 'socket'. 
 * If the reply is present, send the reply headers down the wire too,
 * and clean them up when finished.
 * Pre-condition: 
 *   The request is an internal ESI subrequest.
 *   data context is not NULL
 *   There are no more entries in the stream chain.
 */
void
esiBufferRecipient (clientStreamNode *node, clientHttpRequest *http, HttpReply *rep, StoreIOBuffer recievedData)
{
    esiStreamContext *esiStream;
    /* Test preconditions */
    assert (node != NULL);
    /* ESI TODO: handle thisNode rather than asserting
     * - it should only ever happen if we cause an 
     * abort and the callback chain loops back to 
     * here, so we can simply return. However, that 
     * itself shouldn't happen, so it stays as an 
     * assert for now. */
    assert (cbdataReferenceValid (node));
    assert (node->data != NULL);
    assert (node->node.next == NULL);
    assert (http->conn == NULL);

    esiStream = (esiStreamContext *)cbdataReference (node->data);
    /* If segments become more flexible, ignore thisNode */
    assert (recievedData.length <= sizeof(esiStream->localbuffer->buf));
    assert (!esiStream->finished);

    debug (86,5) ("esiBufferRecipient rep %p body %p len %d\n", rep, recievedData.data, recievedData.length);
    assert (node->readBuffer.offset == recievedData.offset || recievedData.length == 0);

    /* trivial case */

    if (http->out.offset != 0) {
        assert(rep == NULL);
    } else {
        if (rep) {
            if (rep->sline.status != HTTP_OK) {
                httpReplyDestroy(rep);
                rep = NULL;
                esiStream->include->fail (esiStream);
                esiStream->finished = 1;
                cbdataReferenceDone (esiStream);
                httpRequestFree (http);
                return;
            }

#if HEADERS_LOG
            /* should be done in the store rather than every recipient?  */
            headersLog(0, 0, http->request->method, rep);

#endif

            httpReplyDestroy(rep);

            rep = NULL;
        }
    }

    if (recievedData.data && recievedData.length) {
        http->out.offset += recievedData.length;

        if (recievedData.data >= esiStream->localbuffer->buf &&
                recievedData.data < &esiStream->localbuffer->buf[sizeof(esiStream->localbuffer->buf)]) {
            /* original static buffer */

            if (recievedData.data != esiStream->localbuffer->buf) {
                /* But not the start of it */
                xmemmove (esiStream->localbuffer->buf, recievedData.data, recievedData.length);
            }

            esiStream->localbuffer->len = recievedData.length;
        } else {
            assert (esiStream->buffer.getRaw() != NULL);
            esiStream->buffer->len = recievedData.length;
        }
    }

    /* EOF / Read error /  aborted entry */
    if (rep == NULL && recievedData.data == NULL && recievedData.length == 0) {
        /* TODO: get stream status to test the entry for aborts */
        debug (86,5)("Finished reading upstream data in subrequest\n");
        esiStream->include->subRequestDone (esiStream, true);
        esiStream->finished = 1;
        cbdataReferenceDone (esiStream);
        httpRequestFree (http);
        return;
    }


    /* after the write to the user occurs, (ie here, or in a callback)
     * we call */
    if (clientHttpRequestStatus(-1, http)) {
        /* TODO: Does thisNode if block leak htto ? */
        esiStreamContext *temp = esiStream;
        esiStream->include->fail (esiStream);
        esiStream->finished = 1;
        cbdataReferenceDone (esiStream);
        cbdataFree (temp); /* free the request */
        return;
    };

    switch (clientStreamStatus (node, http)) {

    case STREAM_UNPLANNED_COMPLETE: /* fallthru ok */

    case STREAM_COMPLETE: /* ok */
        debug (86,3)("ESI subrequest finished OK\n");
        esiStream->include->subRequestDone (esiStream, true);
        esiStream->finished = 1;
        cbdataReferenceDone (esiStream);
        httpRequestFree (http);
        return;

    case STREAM_FAILED:
        debug (86,1)("ESI subrequest failed transfer\n");
        esiStream->include->fail (esiStream);
        esiStream->finished = 1;
        cbdataReferenceDone (esiStream);
        httpRequestFree (http);
        return;

    case STREAM_NONE: {
            StoreIOBuffer tempBuffer;

            if (!esiStream->buffer.getRaw()) {
                esiStream->buffer = esiStream->localbuffer;
            }

            esiStream->buffer = esiStream->buffer->tail();

            if (esiStream->buffer->len) {
                esiStream->buffer->next = new ESISegment;
                esiStream->buffer = esiStream->buffer->next;
            }

            tempBuffer.offset = http->out.offset;
            tempBuffer.length = sizeof (esiStream->buffer->buf);
            tempBuffer.data = esiStream->buffer->buf;
            /* now just read into 'buffer' */
            clientStreamRead (node,
                              http, tempBuffer);
            debug (86,5)("esiBufferRecipient: Requested more data for ESI subrequest\n");
        }

        break;

    default:
        fatal ("Hit unreachable code in esiBufferRecipient\n");
    }

    cbdataReferenceDone (esiStream);
}

/* esiStream functions */
void
esiStreamContextFree (void *data)
{
    esiStreamContext *esiStream = (esiStreamContext *)data;
    assert (esiStream);
    esiStream->buffer = NULL;
    esiStream->localbuffer = NULL;
    esiStream->include = NULL;
    debug (86,5)("Freeing stream context\n");
}

void *
_esiStreamContext::operator new (size_t count)
{
    CBDATA_INIT_TYPE_FREECB(esiStreamContext, esiStreamContextFree);
    return cbdataAlloc(esiStreamContext);
}

esiStreamContext *
esiStreamContextNew (esiIncludePtr include)
{
    esiStreamContext *rv = new _esiStreamContext;
    rv->include = include;
    return rv;
}

/* Implementation of ESIElements */

/* esiComment */
esiComment::~esiComment()
{
    debug (86,5)("esiComment::~esiComment %p\n", this);
}

void *
esiComment::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiComment));

    if (!pool)
        pool = memPoolCreate ("esiComment", sizeof (esiComment));

    return memPoolAlloc(pool);
}

void
esiComment::operator delete (void *address)
{
    memPoolFree (pool, address);
}

void
esiComment::deleteSelf() const
{
    delete this;
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
    debug (86, 5)("esiCommentRender: Rendering comment %p into %p\n", this, output.getRaw());
}

ESIElement::Pointer
esiComment::makeCacheable() const
{
    debug (86, 5) ("esiComment::makeCacheable: returning NULL\n");
    return NULL;
}

ESIElement::Pointer
esiComment::makeUsable(esiTreeParentPtr, esiVarState &) const
{
    fatal ("esiComment::Usable: unreachable code!\n");
    return NULL;
}

/* esiLiteral */
void *
esiLiteral::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiLiteral));

    if (!pool)
        pool = memPoolCreate ("esiLiteral", sizeof (esiLiteral));

    return memPoolAlloc (pool);
}

void
esiLiteral::operator delete (void *address)
{
    memPoolFree (pool, address);
}

void
esiLiteral::deleteSelf() const
{
    delete this;
}

esiLiteral::~esiLiteral()
{
    debug (86, 5) ("esiLiteral::~esiLiteral: %p\n", this);
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
    off_t start = 0;
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
    debug (86,9)("esiLiteral::render: Rendering %p\n",this);
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
esiLiteral::makeUsable(esiTreeParentPtr , esiVarState &newVarState) const
{
    debug (86,5)("esiLiteral::makeUsable: Creating usable literal\n");
    esiLiteral * result = new esiLiteral (*this);
    result->varState = cbdataReference (&newVarState);
    return result;
}

/* esiInclude */
esiInclude::~esiInclude()
{
    debug (86,5)("esiInclude::Free %p\n", this);
    ESISegmentFreeList (srccontent);
    ESISegmentFreeList (altcontent);
    cbdataReferenceDone (varState);
    safe_free (srcurl);
    safe_free (alturl);
}

void
esiInclude::finish()
{
    parent = NULL;
}

void *
esiInclude::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiInclude));

    if (!Pool)
        Pool = memPoolCreate ("esiInclude", sizeof (esiInclude));

    return memPoolAlloc(Pool);
}

void
esiInclude::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
esiInclude::deleteSelf() const
{
    delete this;
}

ESIElement::Pointer
esiInclude::makeCacheable() const
{
    return new esiInclude (*this);
}

ESIElement::Pointer
esiInclude::makeUsable(esiTreeParentPtr newParent, esiVarState &newVarState) const
{
    esiInclude *resultI = new esiInclude (*this);
    ESIElement::Pointer result = resultI;
    resultI->parent = newParent;
    resultI->varState = cbdataReference (&newVarState);

    if (resultI->srcurl)
        resultI->src = esiStreamContextNew (resultI);

    if (resultI->alturl)
        resultI->alt = esiStreamContextNew (resultI);

    return result;
}

esiInclude::esiInclude(esiInclude const &old) : parent (NULL), started (false), sent (false)
{
    varState = NULL;
    flags.onerrorcontinue = old.flags.onerrorcontinue;

    if (old.srcurl)
        srcurl = xstrdup (old.srcurl);

    if (old.alturl)
        alturl = xstrdup (old.alturl);
}

void
esiInclude::Start (esiStreamContext *stream, char const *url, esiVarState *vars)
{
    HttpHeader tempheaders;

    if (!stream)
        return;

    httpHeaderInit (&tempheaders, hoRequest);

    /* Ensure variable state is clean */
    vars->feedData(url, strlen (url));

    /* tempUrl is eaten by the request */
    char const *tempUrl = vars->extractChar ();

    debug (86,5)("esiIncludeStart: Starting subrequest with url '%s'\n", tempUrl);

    if (clientBeginRequest(METHOD_GET, tempUrl, esiBufferRecipient, esiBufferDetach, stream, &tempheaders, stream->localbuffer->buf, HTTP_REQBUF_SZ)) {
        debug (86,0) ("starting new ESI subrequest failed\n");
    }

    httpHeaderClean (&tempheaders);
}

esiInclude::esiInclude (esiTreeParentPtr aParent, int attrcount, char const **attr, ESIContext *aContext) : parent (aParent), started (false), sent (false)
{
    int i;
    assert (aContext);

    for (i = 0; i < attrcount && attr[i]; i += 2) {
        if (!strcmp(attr[i],"src")) {
            /* Start a request for thisNode url */
            debug (86,5)("esiIncludeNew: Requesting source '%s'\n",attr[i+1]);
            /* TODO: don't assert on thisNode, ignore the duplicate */
            assert (src == NULL);
            src = esiStreamContextNew (this);
            assert (src != NULL);
            srcurl = xstrdup ( attr[i+1]);
        } else if (!strcmp(attr[i],"alt")) {
            /* Start a secondary request for thisNode url */
            /* TODO: make a config parameter to wait on requesting alt's
             * for the src to fail
             */
            debug (86,5)("esiIncludeNew: Requesting alternate '%s'\n",attr[i+1]);
            assert (alt == NULL); /* TODO: FIXME */
            alt = esiStreamContextNew (this);
            assert (alt != NULL);
            alturl = xstrdup (attr[i+1]);
        } else if (!strcmp(attr[i],"onerror")) {
            if (!strcmp(attr[i+1], "continue")) {
                flags.onerrorcontinue = 1;
            } else {
                /* ignore mistyped attributes */
                debug (86, 1)("invalid value for onerror='%s'\n", attr[i+1]);
            }
        } else {
            /* ignore mistyped attributes. TODO:? error on these for user feedback - config parameter needed
             */
        }
    }

    varState = cbdataReference(aContext->varState);
}

void
esiInclude::start()
{
    /* prevent freeing ourselves */
    esiIncludePtr foo(this);

    if (started)
        return;

    started = true;

    if (src) {
        Start (src, srcurl, varState);
        Start (alt, alturl, varState);
    } else {
        if (alt)
            cbdataFree (alt);

        debug (86,1)("esiIncludeNew: esi:include with no src attributes\n");

        flags.failed = 1;
    }
}

void
esiInclude::render(ESISegment::Pointer output)
{
    if (sent)
        return;

    ESISegment::Pointer myout;

    debug (86, 5)("esiIncludeRender: Rendering include %p\n", this);

    assert (flags.finished || (flags.failed && flags.onerrorcontinue));

    if (flags.failed && flags.onerrorcontinue) {
        return;
    }

    /* Render the content */
    if (srccontent.getRaw()) {
        myout = srccontent;
        srccontent = NULL;
    } else if (altcontent.getRaw()) {
        myout = altcontent;
        altcontent = NULL;
    } else
        fatal ("esiIncludeRender called with no content, and no failure!\n");

    assert (output->next == NULL);

    output->next = myout;

    sent = true;
}

esiProcessResult_t
esiInclude::process (int dovars)
{
    start();
    debug (86, 5)("esiIncludeRender: Processing include %p\n", this);

    if (flags.failed) {
        if (flags.onerrorcontinue)
            return ESI_PROCESS_COMPLETE;
        else
            return ESI_PROCESS_FAILED;
    }

    if (!flags.finished) {
        if (flags.onerrorcontinue)
            return ESI_PROCESS_PENDING_WONTFAIL;
        else
            return ESI_PROCESS_PENDING_MAYFAIL;
    }

    return ESI_PROCESS_COMPLETE;
}

void
esiInclude::fail (esiStreamContext *stream)
{
    subRequestDone (stream, false);
}

bool
esiInclude::dataNeeded() const
{
    return !(flags.finished || flags.failed);
}

void
esiInclude::subRequestDone (esiStreamContext *stream, bool success)
{
    assert (this);

    if (!dataNeeded())
        return;

    if (stream == src) {
        debug (86,3)("esiInclude::subRequestDone: %s\n", srcurl);

        if (success) {
            /* copy the lead segment */
            debug (86,3)("esiIncludeSubRequestDone: Src OK - include PASSED.\n");
            assert (!srccontent.getRaw());
            ESISegment::ListTransfer (stream->localbuffer, srccontent);
            /* we're done! */
            flags.finished = 1;
        } else {
            /* Fail if there is no alt being retrieved */
            debug (86,3)("esiIncludeSubRequestDone: Src FAILED\n");

            if (!(alt || altcontent.getRaw())) {
                debug (86,3)("esiIncludeSubRequestDone: Include FAILED - No ALT\n");
                flags.failed = 1;
            } else if (altcontent.getRaw()) {
                debug (86,3)("esiIncludeSubRequestDone: Include PASSED - ALT already Complete\n");
                /* ALT was already retrieved, we are done */
                flags.finished = 1;
            }
        }

        src = NULL;
    } else if (stream == alt) {
        debug (86,3)("esiInclude::subRequestDone: %s\n", alturl);

        if (success) {
            debug (86,3)("esiIncludeSubRequestDone: ALT OK.\n");
            /* copy the lead segment */
            assert (!altcontent.getRaw());
            ESISegment::ListTransfer (stream->localbuffer, altcontent);
            /* we're done! */

            if (!(src || srccontent.getRaw())) {
                /* src already failed, kick ESI processor */
                debug (86,3)("esiIncludeSubRequestDone: Include PASSED - SRC already failed.\n");
                flags.finished = 1;
            }
        } else {
            if (!(src || srccontent.getRaw())) {
                debug (86,3)("esiIncludeSubRequestDone: ALT FAILED, Include FAILED - SRC already failed\n");
                /* src already failed */
                flags.failed = 1;
            }
        }

        alt = NULL;
    } else {
        fatal ("esiIncludeSubRequestDone: non-owned stream found!\n");
    }

    if (flags.finished || flags.failed) {
        /* Kick ESI Processor */
        debug (86,5)("esiInclude %p SubRequest %p completed, kicking processor , status %s\n", this, stream, flags.finished ? "OK" : "FAILED");
        assert (parent.getRaw());

        if (!flags.failed) {
            sent = true;
            parent->provideData (srccontent.getRaw() ? srccontent:altcontent,this);

            if (srccontent.getRaw())
                srccontent = NULL;
            else
                altcontent = NULL;
        } else if (flags.onerrorcontinue) {
            /* render nothing but inform of completion */

            if (!sent) {
                sent = true;
                parent->provideData (new ESISegment, this);
            } else
                assert (0);
        } else
            parent->fail(this);
    }
}

/* esiRemove */
void
esiRemoveFree (void *data)
{
    esiRemove *thisNode = (esiRemove *)data;
    debug (86,5)("esiRemoveFree %p\n", thisNode);
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

void
esiRemove::deleteSelf() const
{
    delete this;
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
    debug (86, 5)("esiRemoveRender: Rendering remove %p\n", this);
}

/* Accept non-ESI children */
bool
esiRemove::addElement (ESIElement::Pointer element)
{
    if (!dynamic_cast<esiLiteral*>(element.getRaw())) {
        debug (86,5)("esiRemoveAdd: Failed for %p\n",this);
        return false;
    }

    return true;
}

ESIElement::Pointer
esiRemove::makeCacheable() const
{
    debug (86,5)("esiRemove::makeCacheable: Returning NULL\n");
    return NULL;
}

ESIElement::Pointer
esiRemove::makeUsable(esiTreeParentPtr, esiVarState &) const
{
    fatal ("esiRemove::Usable: unreachable code!\n");
    return NULL;
}

/* esiTry */
esiTry::~esiTry()
{
    debug (86,5)("esiTry::~esiTry %p\n", this);
}

void *
esiTry::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiTry));

    if (!Pool)
        Pool = memPoolCreate ("esiTry", sizeof(esiTry));

    return memPoolAlloc (Pool);
}

void
esiTry::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
esiTry::deleteSelf() const
{
    delete this;
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
    debug (86, 5)("esiTryRender: Rendering Try %p\n", this);

    if (flags.attemptok) {
        attempt->render(output);
    } else if (flags.exceptok) {
        /* prerendered */

        if (exceptbuffer.getRaw())
            ESISegment::ListTransfer(exceptbuffer, output);
        else
            except->render(output);
    } else
        debug (86,5)("esiTryRender: Neither except nor attempt succeeded?!?\n");
}

/* Accept attempt and except only */
bool
esiTry::addElement(ESIElement::Pointer element)
{
    debug (86,5)("esiTryAdd: Try %p adding element %p\n",this, element.getRaw());

    if (dynamic_cast<esiLiteral*>(element.getRaw())) {
        /* Swallow whitespace */
        debug (86,5)("esiTryAdd: Try %p skipping whitespace %p\n",this, element.getRaw());
        return true;
    }

    if (dynamic_cast<esiAttempt*>(element.getRaw())) {
        if (attempt.getRaw()) {
            debug (86,1)("esiTryAdd: Failed for %p - try allready has an attempt node (section 3.4)\n",this);
            return false;
        }

        attempt = element;
        return true;
    }

    if (dynamic_cast<esiExcept*>(element.getRaw())) {
        if (except.getRaw()) {
            debug (86,1)("esiTryAdd: Failed for %p - try already has an except node (section 3.4)\n",this);
            return false;
        }

        except = element;
        return true;
    }

    debug (86,1)("esiTryAdd: Failed to add element %p to try %p, incorrect element type (see section 3.4)\n", element.getRaw(), this);
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
        debug (86,0)("esiTryProcess: Try has no attempt element - ESI template is invalid (section 3.4)\n");
        return ESI_PROCESS_FAILED;
    }

    if (!except.getRaw()) {
        debug (86,0)("esiTryProcess: Try has no except element - ESI template is invalid (section 3.4)\n");
        return ESI_PROCESS_FAILED;
    }

    if (!flags.attemptfailed)
        /* Try the attempt branch */
        switch ((rv = attempt->process(dovars))) {

        case ESI_PROCESS_COMPLETE:
            debug (86,5)("esiTryProcess: attempt Processed OK\n");
            flags.attemptok = 1;
            return ESI_PROCESS_COMPLETE;

        case ESI_PROCESS_PENDING_WONTFAIL:
            debug (86,5)("esiTryProcess: attempt Processed PENDING OK\n");
            /* We're not done yet, but don't need to test except */
            return ESI_PROCESS_PENDING_WONTFAIL;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debug (86,5)("eseSequenceProcess: element Processed PENDING UNKNOWN\n");
            break;

        case ESI_PROCESS_FAILED:
            debug (86,5)("esiSequenceProcess: element Processed FAILED\n");
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
            debug (86,5)("esiTryProcess: except Processed OK\n");
            flags.exceptok = 1;
            return bestAttemptRV();

        case ESI_PROCESS_PENDING_WONTFAIL:
            debug (86,5)("esiTryProcess: attempt Processed PENDING OK\n");
            /* We're not done yet, but can't fail */
            return ESI_PROCESS_PENDING_WONTFAIL;

        case ESI_PROCESS_PENDING_MAYFAIL:
            debug (86,5)("eseSequenceProcess: element Processed PENDING UNKNOWN\n");
            /* The except branch fail fail */
            return ESI_PROCESS_PENDING_MAYFAIL;

        case ESI_PROCESS_FAILED:
            debug (86,5)("esiSequenceProcess: element Processed FAILED\n");
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
            parent->fail (this);
        }
    }

    /* nothing to do when except fails and attempt hasn't */
}

void
esiTry::fail(ESIElement *source)
{
    assert (source);
    assert (source == attempt || source == except);
    debug (86,5) ("esiTry::fail: this=%p, source=%p\n", this, source);

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
    debug (86,5)("esiTry::makeCacheable: making cachable Try from %p\n",this);
    esiTry *resultT = new esiTry (*this);
    ESIElement::Pointer result = resultT;

    if (attempt.getRaw())
        resultT->attempt = attempt->makeCacheable();

    if (except.getRaw())
        resultT->except  = except->makeCacheable();

    return result;
}

ESIElement::Pointer
esiTry::makeUsable(esiTreeParentPtr newParent, esiVarState &newVarState) const
{
    debug (86,5)("esiTry::makeUsable: making usable Try from %p\n",this);
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
void
esiAttempt::deleteSelf() const
{
    delete this;
}

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
void
esiExcept::deleteSelf() const
{
    delete this;
}

/* esiVar */
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

void
esiVar::deleteSelf() const
{
    delete this;
}

/* esiVarState */
void
esiVarStateFree (void *data)
{
    esiVarState *thisNode = (esiVarState*)data;
    thisNode->freeResources();
}

void
esiVarState::freeResources()
{
    input = NULL;
    ESISegmentFreeList (output);
    httpHeaderClean (&hdr);

    if (query) {
        unsigned int i;

        for (i = 0; i < query_elements; ++i) {
            safe_free(query[i].var);
            safe_free(query[i].val);
        }

        memFreeBuf (query_sz, query);
    }

    safe_free (query_string);
    safe_free (browserversion);
}

void *
esiVarState::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiVarState));
    void *rv;
    CBDATA_INIT_TYPE_FREECB(esiVarState, esiVarStateFree);
    rv = (void *)cbdataAlloc (esiVarState);
    return rv;
}

void
esiVarState::operator delete (void *address)
{
    cbdataFree (address);
}

void
esiVarState::deleteSelf() const
{
    delete this;
}

char *
esiVarState::getProductVersion (char const *s)
{
    char const *t;
    int len;
    t = index (s,'/');

    if (!t || !*(++t))
        return xstrdup ("");

    len = strcspn (t, " \r\n()<>@,;:\\\"/[]?={}");

    return xstrndup (t, len);
}

esiVarState::esiVarState (HttpHeader const *aHeader, char const *uri)
        : output (NULL)
{
    /* Fill out variable values */
    /* Count off the query elements */
    char const *query_start = strchr (uri, '?');

    if (query_start && query_start[1] != '\0' ) {
        unsigned int n;
        query_string = xstrdup (query_start + 1);
        query_elements = 1;
        char const *query_pos = query_start + 1;

        while ((query_pos = strchr (query_pos, '&'))) {
            ++query_elements;
            ++query_pos;
        }

        query = (_query_elem *)memReallocBuf(query, query_elements * sizeof (struct _query_elem),
                                             &query_sz);
        query_pos = query_start + 1;
        n = 0;

        while (query_pos) {
            char *next = strchr (query_pos, '&');
            char *div = strchr (query_pos, '=');

            if (next)
                ++next;

            assert (n < query_elements);

            if (!div)
                div = next;

            if (!(div - query_pos + 1))
                /* zero length between & and = or & and & */
                continue;

            query[n].var = xstrndup (query_pos, div - query_pos + 1) ;

            if (div == next) {
                query[n].val = xstrdup ("");
            } else {
                query[n].val = xstrndup (div + 1, next - div - 1);
            }

            query_pos = next;
            ++n;
        }
    } else {
        query_string = xstrdup ("");
    }

    if (query) {
        unsigned int n = 0;
        debug (86,6)("esiVarStateNew: Parsed Query string: '%s'\n",uri);

        while (n < query_elements) {
            debug (86,6)("esiVarStateNew: Parsed Query element %d '%s'='%s'\n",n + 1, query[n].var, query[n].val);
            ++n;
        }
    }

    /* Now setup the UserAgent values */
    /* An example:
     *    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705) */
    /* Grr thisNode is painful - RFC 2616 specifies that 'by convention' the tokens are in order of importance
     * in identifying the product. According to the RFC the above should be interpreted as:
     * Product - Mozilla version 4.0
     * in comments - compatible; .... 3705 
     *
     * Useing the RFC a more appropriate header would be
     *    User-Agent: MSIE/6.0 Mozilla/4.0 Windows-NT/5.1 .NET-CLR/1.0.3705
     *    or something similar.
     *
     * Because we can't parse under those rules and get real-world useful answers, we follow the following 
     * algorithm:
     * if the string Windows appears in the header, the OS is WIN.
     * If the string Mac appears in the header, the OS is MAC.
     * If the string nix, or BSD appears in the header, the OS is UNIX.
     * If the string MSIE appears in the header, the BROWSER is MSIE, and the version is the string from 
     * MSIE<sp> to the first ;, or end of string.
     * If the String MSIE does not appear in the header, and MOZILLA does, we use the version from the 
     * /version field.
     * if MOZILLA doesn't appear, the browser is set to OTHER.
     * In future, thisNode may be better implemented as a regexp.
     */
    /* TODO: only grab the needed headers */
    httpHeaderInit (&hdr, hoReply);

    httpHeaderAppend (&hdr, aHeader);

    if (httpHeaderHas(&hdr, HDR_USER_AGENT)) {
        char const *s = httpHeaderGetStr (&hdr, HDR_USER_AGENT);
        char const *t, *t1;

        if (strstr (s, "Windows"))
            UserOs = ESI_OS_WIN;
        else if (strstr (s, "Mac"))
            UserOs = ESI_OS_MAC;
        else if (strstr (s, "nix") || strstr (s, "BSD"))
            UserOs = ESI_OS_UNIX;
        else
            UserOs = ESI_OS_OTHER;

        /* Now the browser and version */
        if ((t = strstr (s, "MSIE"))) {
            browser = ESI_BROWSER_MSIE;
            t = index (t, ' ');

            if (!t)
                browserversion = xstrdup ("");
            else {
                t1 = index (t, ';');

                if (!t1)
                    browserversion = xstrdup (t + 1);
                else
                    browserversion = xstrndup (t + 1, t1-t);
            }
        } else if (strstr (s, "Mozilla")) {
            browser = ESI_BROWSER_MOZILLA;
            browserversion = getProductVersion(s);
        } else {
            browser = ESI_BROWSER_OTHER;
            browserversion = getProductVersion(s);
        }
    } else {
        UserOs = ESI_OS_OTHER;
        browser = ESI_BROWSER_OTHER;
        browserversion = xstrdup ("");
    }
}

void
esiVarState::feedData (const char *buf, size_t len)
{
    /* TODO: if needed - tune to skip segment iteration */
    debug (86,6)("esiVarState::feedData: accepting %d bytes\n", len);
    ESISegment::ListAppend (input, buf, len);
}

ESISegment::Pointer
esiVarState::extractList()
{
    doIt();
    ESISegment::Pointer rv = output;
    output = NULL;
    debug (86,6)("esiVarStateExtractList: Extracted list\n");
    return rv;
}

char *
esiVarState::extractChar ()
{
    if (!input.getRaw())
        fatal ("Attempt to extract variable state with no data fed in \n");

    doIt();

    char *rv = output->listToChar();

    ESISegmentFreeList (output);

    debug (86,6)("esiVarStateExtractList: Extracted char\n");

    return rv;
}

int
httpHeaderHasListMember(const HttpHeader * hdr, http_hdr_type id, const char *member, const char separator);

int
httpHeaderHasListMember(const HttpHeader * hdr, http_hdr_type id, const char *member, const char separator)
{
    int result = 0;
    const char *pos = NULL;
    const char *item;
    int ilen;
    int mlen = strlen(member);

    assert(hdr);
    assert(id >= 0);

    String header (httpHeaderGetStrOrList(hdr, id));

    while (strListGetItem(&header, separator, &item, &ilen, &pos)) {
        if (strncmp(item, member, mlen) == 0
                && (item[mlen] == '=' || item[mlen] == separator || item[mlen] == ';' || item[mlen] == '\0')) {
            result = 1;
            break;
        }
    }

    return result;
}

void
esiVarState::eval (esiVar_t type, char const *subref, char const *found_default )
{
    const char *s = NULL;

    if (!found_default)
        found_default = "";

    switch (type) {

    case ESI_VAR_HOST:
        flags.host = 1;

        if (!subref && httpHeaderHas(&hdr,HDR_HOST)) {
            s = httpHeaderGetStr (&hdr, HDR_HOST);
        } else
            s = found_default;

        ESISegment::ListAppend (output, s, strlen (s));

        break;

    case ESI_VAR_COOKIE:
        flags.cookie = 1;

        if (httpHeaderHas(&hdr, HDR_COOKIE)) {
            if (!subref)
                s = httpHeaderGetStr (&hdr, HDR_COOKIE);
            else {
                String S = httpHeaderGetListMember (&hdr, HDR_COOKIE, subref, ';');

                if (S.size())
                    ESISegment::ListAppend (output, S.buf(), S.size());
                else if (found_default)
                    ESISegment::ListAppend (output, found_default, strlen (found_default));
            }
        } else
            s = found_default;

        if (s)
            ESISegment::ListAppend (output, s, strlen (s));

        break;

    case ESI_VAR_REFERER:
        flags.referer = 1;

        if (!subref && httpHeaderHas(&hdr, HDR_REFERER))
            s = httpHeaderGetStr (&hdr, HDR_REFERER);
        else
            s = found_default;

        ESISegment::ListAppend (output, s, strlen (s));

        break;

    case ESI_QUERY_STRING:
        if (!subref)
            s = query_string;
        else {
            unsigned int i = 0;

            while (i < query_elements && !s) {
                if (!strcmp (subref, query[i].var))
                    s = query[i].val;

                ++i;
            }

            if (!s)
                s = found_default;
        }

        ESISegment::ListAppend (output, s, strlen (s));
        break;

    case ESI_VAR_USERAGENT:
        flags.useragent = 1;

        if (httpHeaderHas(&hdr, HDR_USER_AGENT)) {
            if (!subref)
                s = httpHeaderGetStr (&hdr, HDR_USER_AGENT);
            else {
                if (!strcmp (subref, "os")) {
                    s = esiUserOs[UserOs];
                } else if (!strcmp (subref, "browser")) {
                    s = esiBrowsers[browser];
                } else if (!strcmp (subref, "version")) {
                    s = browserversion;
                } else
                    s = "";
            }
        } else
            s = found_default;

        ESISegment::ListAppend (output, s, strlen (s));

        break;

    case ESI_VAR_LANGUAGE:
        flags.language = 1;

        if (httpHeaderHas(&hdr, HDR_ACCEPT_LANGUAGE)) {
            if (!subref) {
                String S (httpHeaderGetList (&hdr, HDR_ACCEPT_LANGUAGE));
                ESISegment::ListAppend (output, S.buf(), S.size());
            } else {
                if (httpHeaderHasListMember (&hdr, HDR_ACCEPT_LANGUAGE, subref, ',')) {
                    s = "true";
                } else {
                    s = "false";
                }

                ESISegment::ListAppend (output, s, strlen (s));
            }
        } else {
            s = found_default;
            ESISegment::ListAppend (output, s, strlen (s));
        }

        break;

    case ESI_VAR_OTHER:
        /* No-op. We swallow it */

        if (found_default) {
            ESISegment::ListAppend (output, found_default, strlen (found_default));
        }

        break;
    }
}

bool
esiVarState::validChar (char c)
{
    if (('A' <= c && c <= 'Z') ||
            ('a' <= c && c <= 'z') ||
            '_' == c || '-' == c)
        return true;

    return false;
}

esiVarState::esiVar_t
esiVarState::GetVar(char *s, int len)
{
    assert (s);

    if (len == 9) {
        if (!strncmp (s, "HTTP_HOST", 9))
            return ESI_VAR_HOST;
        else
            return ESI_VAR_OTHER;
    }

    if (len == 11) {
        if (!strncmp (s, "HTTP_COOKIE", 11))
            return ESI_VAR_COOKIE;
        else
            return ESI_VAR_OTHER;
    }

    if (len == 12) {
        if (!strncmp (s, "HTTP_REFERER", 12))
            return ESI_VAR_REFERER;
        else if (!strncmp (s, "QUERY_STRING", 12))
            return ESI_QUERY_STRING;
        else
            return ESI_VAR_OTHER;
    }

    if (len == 15) {
        if (!strncmp (s, "HTTP_USER_AGENT", 15))
            return ESI_VAR_USERAGENT;
        else
            return ESI_VAR_OTHER;
    }

    if (len == 20) {
        if (!strncmp (s, "HTTP_ACCEPT_LANGUAGE", 20))
            return ESI_VAR_LANGUAGE;
        else
            return ESI_VAR_OTHER;
    }

    return ESI_VAR_OTHER;
}

/* because we are only used to process:
 * - include URL's
 * - non-esi elements
 * - choose clauses
 * buffering is ok - we won't delay the start of async activity, or
 * of output data preparation
 */
void
esiVarState::doIt ()
{
    assert (output == NULL);
    int state = 0;
    char *string = input->listToChar();
    size_t len = strlen (string);
    size_t pos = 0;
    size_t var_pos = 0;
    size_t done_pos = 0;
    char * found_subref = NULL;
    char *found_default = NULL;
    esiVar_t vartype = ESI_VAR_OTHER;
    ESISegmentFreeList (input);

    while (pos < len) {
        switch (state) {

        case 0: /* skipping pre-variables */

            if (string[pos] != '$') {
                ++pos;
            } else {
                if (pos - done_pos)
                    /* extract known good text */
                    ESISegment::ListAppend (output, string + done_pos, pos - done_pos);

                done_pos = pos;

                state = 1;

                ++pos;
            }

            break;

        case 1:/* looking for ( */

            if (string[pos] != '(') {
                state = 0;
            } else {
                state = 2; /* extract a variable name */
                var_pos = ++pos;
            }

            break;

        case 2: /* looking for variable name */

            if (!validChar(string[pos])) {
                /* not a variable name char */

                if (pos - var_pos)
                    vartype = GetVar (string + var_pos, pos - var_pos);

                state = 3;
            } else {
                ++pos;
            }

            break;

        case 3: /* looking for variable subref, end bracket or default indicator */

            if (string[pos] == ')') {
                /* end of string */
                eval(vartype, found_subref, found_default);
                done_pos = ++pos;
                safe_free(found_subref);
                safe_free(found_default);
                state = 0;
            } else if (!found_subref && !found_default && string[pos] == '{') {
                debug (86,6)("esiVarStateDoIt: Subref of some sort\n");
                /* subreference of some sort */
                /* look for the entry name */
                var_pos = ++pos;
                state = 4;
            } else if (!found_default && string[pos] == '|') {
                debug (86,6)("esiVarStateDoIt: Default present\n");
                /* extract default value */
                state = 5;
                var_pos = ++pos;
            } else {
                /* unexpected char, not a variable after all */
                debug (86,6)("esiVarStateDoIt: unexpected char after varname\n");
                state = 0;
                pos = done_pos + 2;
            }

            break;

        case 4: /* looking for variable subref */

            if (string[pos] == '}') {
                /* end of subref */
                found_subref = xstrndup (&string[var_pos], pos - var_pos + 1);
                debug (86,6)("esiVarStateDoIt: found end of variable subref '%s'\n", found_subref);
                state = 3;
                ++pos;
            } else if (!validChar (string[pos])) {
                debug (86,6)("esiVarStateDoIt: found invalid char in variable subref\n");
                /* not a valid subref */
                safe_free(found_subref);
                state = 0;
                pos = done_pos + 2;
            } else {
                ++pos;
            }

            break;

        case 5: /* looking for a default value */

            if (string[pos] == '\'') {
                /* begins with a quote */
                debug (86,6)("esiVarStateDoIt: found quoted default\n");
                state = 6;
                var_pos = ++pos;
            } else {
                /* doesn't */
                debug (86,6)("esiVarStateDoIt: found unquoted default\n");
                state = 7;
                ++pos;
            }

            break;

        case 6: /* looking for a quote terminate default value */

            if (string[pos] == '\'') {
                /* end of default */
                found_default = xstrndup (&string[var_pos], pos - var_pos + 1);
                debug (86,6)("esiVarStateDoIt: found end of quoted default '%s'\n", found_default);
                state = 3;
            }

            ++pos;
            break;

        case 7: /* looking for } terminate default value */

            if (string[pos] == ')') {
                /* end of default - end of variable*/
                found_default = xstrndup (&string[var_pos], pos - var_pos + 1);
                debug (86,6)("esiVarStateDoIt: found end of variable (w/ unquoted default) '%s'\n",found_default);
                eval(vartype,found_subref, found_default);
                done_pos = ++pos;
                safe_free(found_default);
                safe_free(found_subref);
                state = 0;
            }

            ++pos;
            break;

        default:
            fatal("esiVarStateDoIt: unexpected state\n");
        }
    }

    /* pos-done_pos chars are ready to copy */
    if (pos-done_pos)
        ESISegment::ListAppend (output, string+done_pos, pos - done_pos);

    safe_free (found_default);

    safe_free (found_subref);
}

/* XXX FIXME: this should be comma delimited, no? */
void
esiVarState::buildVary (HttpReply *rep)
{
    char tempstr[1024];
    tempstr[0]='\0';

    if (flags.language)
        strcat (tempstr, "Accept-Language ");

    if (flags.cookie)
        strcat (tempstr, "Cookie ");

    if (flags.host)
        strcat (tempstr, "Host ");

    if (flags.referer)
        strcat (tempstr, "Referer ");

    if (flags.useragent)
        strcat (tempstr, "User-Agent ");

    if (!tempstr[0])
        return;

    String strVary (httpHeaderGetList (&rep->header, HDR_VARY));

    if (!strVary.size() || strVary.buf()[0] != '*') {
        httpHeaderPutStr (&rep->header, HDR_VARY, tempstr);
    }
}

/* esiChoose */
esiChoose::~esiChoose()
{
    debug (86,5)("esiChoose::~esiChoose %p\n", this);
}

void *
esiChoose::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiChoose));

    if (!Pool)
        Pool = memPoolCreate ("esiChoose", sizeof(esiChoose));

    return memPoolAlloc (Pool);
}

void
esiChoose::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
esiChoose::deleteSelf() const
{
    delete this;
}

esiChoose::esiChoose(esiTreeParentPtr aParent) : elements (), chosenelement (-1),parent (aParent)
{}

void
esiChoose::render(ESISegment::Pointer output)
{
    /* append all processed elements, and trim processed and rendered elements */
    assert (output->next == NULL);
    assert (elements.size() || otherwise.getRaw());
    debug (86,5)("esiChooseRender: rendering\n");

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
        debug (86,5)("esiChooseAdd: Choose %p skipping whitespace %p\n",this, element.getRaw());
        return true;
    }

    /* Some elements require specific parents */
    if (!(dynamic_cast<esiWhen*>(element.getRaw()) || dynamic_cast<esiOtherwise*>(element.getRaw()))) {
        debug (86,0)("esiChooseAdd: invalid child node for esi:choose (section 3.3)\n");
        return false;
    }

    if (dynamic_cast<esiOtherwise*>(element.getRaw())) {
        if (otherwise.getRaw()) {
            debug (86,0)("esiChooseAdd: only one otherwise node allowed for esi:choose (section 3.3)\n");
            return false;
        }

        otherwise = element;
    } else {
        elements.push_back (element);

        debug (86,3)("esiChooseAdd: Added a new element, elements = %d\n", elements.size());

        if (chosenelement == -1)
            if ((dynamic_cast<esiWhen *>(element.getRaw()))->
                    testsTrue()) {
                chosenelement = elements.size() - 1;
                debug (86,3)("esiChooseAdd: Chose element %d\n", elements.size());
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
            debug (86,3)("esiChooseAdd: Chose element %d\n", counter + 1);
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

        debug (86,5)("esiSequence::NULLElements: Setting index %d, pointer %p to NULL\n", loopPosition, elements[loopPosition].getRaw());

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
esiChoose::fail(ESIElement * source)
{
    checkValidSource (source);
    elements.setNULL (0, elements.size());

    if (otherwise.getRaw())
        otherwise->finish();

    otherwise = NULL;

    parent->fail(this);

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
esiChoose::makeUsableElements(esiChoose const &old, esiVarState &newVarState)
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
esiChoose::makeUsable(esiTreeParentPtr newParent, esiVarState &newVarState) const
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
    debug (86,5)("ElementList::~ElementList %p\n", this);
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
void *
esiWhen::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (esiWhen));

    if (!Pool)
        Pool = memPoolCreate("esiWhen", sizeof(esiWhen));

    return memPoolAlloc(Pool);
}

void
esiWhen::operator delete (void *address)
{
    memPoolFree(Pool, address);
}

void
esiWhen::deleteSelf() const
{
    delete this;
}

esiWhen::esiWhen (esiTreeParentPtr aParent, int attrcount, const char **attr,esiVarState *aVar) : esiSequence (aParent)
{
    varState = NULL;
    char const *expression = NULL;

    for (int loopCounter = 0; loopCounter < attrcount && attr[loopCounter]; loopCounter += 2) {
        if (!strcmp(attr[loopCounter],"test")) {
            /* evaluate test */
            debug (86,5)("esiIncludeNew: Evaluating '%s'\n",attr[loopCounter+1]);
            /* TODO: warn the user instead of asserting */
            assert (expression == NULL);
            expression = attr[loopCounter+1];
        } else {
            /* ignore mistyped attributes.
             * TODO:? error on these for user feedback - config parameter needed
             */
            debug (86,1)("Found misttyped attribute on ESI When clause\n");
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

    setTestResult(esiExpressionEval (expression));

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
esiWhen::makeUsable(esiTreeParentPtr newParent, esiVarState &newVarState) const
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

void
esiOtherwise::deleteSelf() const
{
    delete this;
}

/* TODO: implement surrogate targeting and control processing */
int
esiEnableProcessing (HttpReply *rep)
{
    int rv = 0;

    if (httpHeaderHas(&rep->header, HDR_SURROGATE_CONTROL)) {
        HttpHdrScTarget *sctusable = httpHdrScGetMergedTarget (rep->surrogate_control,
                                     Config.Accel.surrogate_id);

        if (!sctusable || sctusable->content.size() == 0)
            /* Nothing generic or targeted at us, or no
             * content processing requested 
             */
            return 0;

        if (strstr (sctusable->content.buf(), "ESI/1.0"))
            rv = 1;

        httpHdrScTargetDestroy (sctusable);
    }

    return rv;
}



/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"

#if USE_SQUID_ESI

#include "client_side.h"
#include "client_side_request.h"
#include "esi/Include.h"
#include "esi/VarState.h"
#include "fatal.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "log/access_log.h"

CBDATA_CLASS_INIT (ESIStreamContext);

/* other */
static CSCB esiBufferRecipient;
static CSD esiBufferDetach;
/* esiStreamContext */
static ESIStreamContext *ESIStreamContextNew (ESIIncludePtr);

/* ESI TO CONSIDER:
 * 1. retry failed upstream requests
 */

/* Detach from a buffering stream
 */
void
esiBufferDetach (clientStreamNode *node, ClientHttpRequest *http)
{
    /* Detach ourselves */
    clientStreamDetach (node, http);
}

/**
 * Write a chunk of data to a client 'socket'.
 * If the reply is present, send the reply headers down the wire too.
 *
 * Pre-condition:
 *   The request is an internal ESI subrequest.
 *   data context is not NULL
 *   There are no more entries in the stream chain.
 *   The caller is responsible for creation and deletion of the Reply headers.
 *
 \note
 * Bug 975, bug 1566 : delete rep; 2006/09/02: TS, #975
 *
 * This was causing double-deletes. Its possible that not deleting
 * it here will cause memory leaks, but if so, this delete should
 * not be reinstated or it will trigger bug #975 again - RBC 20060903
 */
void
esiBufferRecipient (clientStreamNode *node, ClientHttpRequest *http, HttpReply *rep, StoreIOBuffer receivedData)
{
    /* Test preconditions */
    assert (node != NULL);
    /* ESI TODO: handle thisNode rather than asserting
     * - it should only ever happen if we cause an
     * abort and the callback chain loops back to
     * here, so we can simply return. However, that
     * itself shouldn't happen, so it stays as an
     * assert for now. */
    assert (cbdataReferenceValid (node));
    assert (node->node.next == NULL);
    assert (http->getConn() == NULL);

    ESIStreamContext::Pointer esiStream = dynamic_cast<ESIStreamContext *>(node->data.getRaw());
    assert (esiStream.getRaw() != NULL);
    /* If segments become more flexible, ignore thisNode */
    assert (receivedData.length <= sizeof(esiStream->localbuffer->buf));
    assert (!esiStream->finished);

    debugs (86,5, HERE << "rep " << rep << " body " << receivedData.data << " len " << receivedData.length);
    assert (node->readBuffer.offset == receivedData.offset || receivedData.length == 0);

    /* trivial case */

    if (http->out.offset != 0) {
        assert(rep == NULL);
    } else {
        if (rep) {
            if (rep->sline.status() != Http::scOkay) {
                rep = NULL;
                esiStream->include->includeFail (esiStream);
                esiStream->finished = 1;
                httpRequestFree (http);
                return;
            }

#if HEADERS_LOG
            /* should be done in the store rather than every recipient?  */
            headersLog(0, 0, http->request->method, rep);

#endif
            rep = NULL;
        }
    }

    if (receivedData.data && receivedData.length) {
        http->out.offset += receivedData.length;

        if (receivedData.data >= esiStream->localbuffer->buf &&
                receivedData.data < &esiStream->localbuffer->buf[sizeof(esiStream->localbuffer->buf)]) {
            /* original static buffer */

            if (receivedData.data != esiStream->localbuffer->buf) {
                /* But not the start of it */
                memmove(esiStream->localbuffer->buf, receivedData.data, receivedData.length);
            }

            esiStream->localbuffer->len = receivedData.length;
        } else {
            assert (esiStream->buffer.getRaw() != NULL);
            esiStream->buffer->len = receivedData.length;
        }
    }

    /* EOF / Read error /  aborted entry */
    if (rep == NULL && receivedData.data == NULL && receivedData.length == 0) {
        /* TODO: get stream status to test the entry for aborts */
        debugs(86, 5, HERE << "Finished reading upstream data in subrequest");
        esiStream->include->subRequestDone (esiStream, true);
        esiStream->finished = 1;
        httpRequestFree (http);
        return;
    }

    /* after the write to the user occurs, (ie here, or in a callback)
     * we call */
    if (clientHttpRequestStatus(-1, http)) {
        /* TODO: Does thisNode if block leak htto ? */
        /* XXX when reviewing ESI this is the first place to look */
        node->data = NULL;
        esiStream->finished = 1;
        esiStream->include->includeFail (esiStream);
        return;
    };

    switch (clientStreamStatus (node, http)) {

    case STREAM_UNPLANNED_COMPLETE: /* fallthru ok */

    case STREAM_COMPLETE: /* ok */
        debugs(86, 3, "ESI subrequest finished OK");
        esiStream->include->subRequestDone (esiStream, true);
        esiStream->finished = 1;
        httpRequestFree (http);
        return;

    case STREAM_FAILED:
        debugs(86, DBG_IMPORTANT, "ESI subrequest failed transfer");
        esiStream->include->includeFail (esiStream);
        esiStream->finished = 1;
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
        clientStreamRead (node, http, tempBuffer);
        debugs(86, 5, HERE << "Requested more data for ESI subrequest");
    }

    break;

    default:
        fatal ("Hit unreachable code in esiBufferRecipient\n");
    }

}

/* esiStream functions */
ESIStreamContext::~ESIStreamContext()
{
    freeResources();
}

void
ESIStreamContext::freeResources()
{
    debugs(86, 5, "Freeing stream context resources.");
    buffer = NULL;
    localbuffer = NULL;
    include = NULL;
}

ESIStreamContext *
ESIStreamContextNew (ESIIncludePtr include)
{
    ESIStreamContext *rv = new ESIStreamContext;
    rv->include = include;
    return rv;
}

/* ESIInclude */
ESIInclude::~ESIInclude()
{
    debugs(86, 5, "ESIInclude::Free " << this);
    ESISegmentFreeList (srccontent);
    ESISegmentFreeList (altcontent);
    cbdataReferenceDone (varState);
    safe_free (srcurl);
    safe_free (alturl);
}

void
ESIInclude::finish()
{
    parent = NULL;
}

ESIElement::Pointer
ESIInclude::makeCacheable() const
{
    return new ESIInclude (*this);
}

ESIElement::Pointer
ESIInclude::makeUsable(esiTreeParentPtr newParent, ESIVarState &newVarState) const
{
    ESIInclude *resultI = new ESIInclude (*this);
    ESIElement::Pointer result = resultI;
    resultI->parent = newParent;
    resultI->varState = cbdataReference (&newVarState);

    if (resultI->srcurl)
        resultI->src = ESIStreamContextNew (resultI);

    if (resultI->alturl)
        resultI->alt = ESIStreamContextNew (resultI);

    return result;
}

ESIInclude::ESIInclude(ESIInclude const &old) :
    varState(NULL),
    srcurl(NULL),
    alturl(NULL),
    parent(NULL),
    started(false),
    sent(false)
{
    memset(&flags, 0, sizeof(flags));
    flags.onerrorcontinue = old.flags.onerrorcontinue;

    if (old.srcurl)
        srcurl = xstrdup(old.srcurl);

    if (old.alturl)
        alturl = xstrdup(old.alturl);
}

void
ESIInclude::prepareRequestHeaders(HttpHeader &tempheaders, ESIVarState *vars)
{
    tempheaders.update(&vars->header());
    tempheaders.removeHopByHopEntries();
}

void
ESIInclude::Start (ESIStreamContext::Pointer stream, char const *url, ESIVarState *vars)
{
    if (!stream.getRaw())
        return;

    HttpHeader tempheaders(hoRequest);

    prepareRequestHeaders(tempheaders, vars);

    /* Ensure variable state is clean */
    vars->feedData(url, strlen (url));

    /* tempUrl is eaten by the request */
    char const *tempUrl = vars->extractChar ();

    debugs(86, 5, "ESIIncludeStart: Starting subrequest with url '" << tempUrl << "'");
    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initEsi);
    if (clientBeginRequest(Http::METHOD_GET, tempUrl, esiBufferRecipient, esiBufferDetach, stream.getRaw(), &tempheaders, stream->localbuffer->buf, HTTP_REQBUF_SZ, mx)) {
        debugs(86, DBG_CRITICAL, "starting new ESI subrequest failed");
    }

    tempheaders.clean();
}

ESIInclude::ESIInclude(esiTreeParentPtr aParent, int attrcount, char const **attr, ESIContext *aContext) :
    varState(NULL),
    srcurl(NULL),
    alturl(NULL),
    parent(aParent),
    started(false),
    sent(false)
{
    assert (aContext);
    memset(&flags, 0, sizeof(flags));

    for (int i = 0; i < attrcount && attr[i]; i += 2) {
        if (!strcmp(attr[i],"src")) {
            /* Start a request for thisNode url */
            debugs(86, 5, "ESIIncludeNew: Requesting source '" << attr[i+1] << "'");

            /* TODO: don't assert on thisNode, ignore the duplicate */
            assert (src.getRaw() == NULL);
            src = ESIStreamContextNew (this);
            assert (src.getRaw() != NULL);
            srcurl = xstrdup(attr[i+1]);
        } else if (!strcmp(attr[i],"alt")) {
            /* Start a secondary request for thisNode url */
            /* TODO: make a config parameter to wait on requesting alt's
             * for the src to fail
             */
            debugs(86, 5, "ESIIncludeNew: Requesting alternate '" << attr[i+1] << "'");

            assert (alt.getRaw() == NULL); /* TODO: fix? */
            alt = ESIStreamContextNew (this);
            assert (alt.getRaw() != NULL);
            alturl = xstrdup(attr[i+1]);
        } else if (!strcmp(attr[i],"onerror")) {
            if (!strcmp(attr[i+1], "continue")) {
                flags.onerrorcontinue = 1;
            } else {
                /* ignore mistyped attributes */
                debugs(86, DBG_IMPORTANT, "invalid value for onerror='" << attr[i+1] << "'");
            }
        } else {
            /* ignore mistyped attributes. TODO:? error on these for user feedback - config parameter needed
             */
        }
    }

    varState = cbdataReference(aContext->varState);
}

void
ESIInclude::start()
{
    /* prevent freeing ourselves */
    ESIIncludePtr foo(this);

    if (started)
        return;

    started = true;

    if (src.getRaw()) {
        Start (src, srcurl, varState);
        Start (alt, alturl, varState);
    } else {
        alt = NULL;

        debugs(86, DBG_IMPORTANT, "ESIIncludeNew: esi:include with no src attributes");

        flags.failed = 1;
    }
}

void
ESIInclude::render(ESISegment::Pointer output)
{
    if (sent)
        return;

    ESISegment::Pointer myout;

    debugs(86, 5, "ESIIncludeRender: Rendering include " << this);

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
        fatal ("ESIIncludeRender called with no content, and no failure!\n");

    assert (output->next == NULL);

    output->next = myout;

    sent = true;
}

esiProcessResult_t
ESIInclude::process (int dovars)
{
    /* Prevent refcount race leading to free */
    Pointer me (this);
    start();
    debugs(86, 5, "ESIIncludeRender: Processing include " << this);

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
ESIInclude::includeFail (ESIStreamContext::Pointer stream)
{
    subRequestDone (stream, false);
}

bool
ESIInclude::dataNeeded() const
{
    return !(flags.finished || flags.failed);
}

void
ESIInclude::subRequestDone (ESIStreamContext::Pointer stream, bool success)
{
    if (!dataNeeded())
        return;

    if (stream == src) {
        debugs(86, 3, "ESIInclude::subRequestDone: " << srcurl);

        if (success) {
            /* copy the lead segment */
            debugs(86, 3, "ESIIncludeSubRequestDone: Src OK - include PASSED.");
            assert (!srccontent.getRaw());
            ESISegment::ListTransfer (stream->localbuffer, srccontent);
            /* we're done! */
            flags.finished = 1;
        } else {
            /* Fail if there is no alt being retrieved */
            debugs(86, 3, "ESIIncludeSubRequestDone: Src FAILED");

            if (!(alt.getRaw() || altcontent.getRaw())) {
                debugs(86, 3, "ESIIncludeSubRequestDone: Include FAILED - No ALT");
                flags.failed = 1;
            } else if (altcontent.getRaw()) {
                debugs(86, 3, "ESIIncludeSubRequestDone: Include PASSED - ALT already Complete");
                /* ALT was already retrieved, we are done */
                flags.finished = 1;
            }
        }

        src = NULL;
    } else if (stream == alt) {
        debugs(86, 3, "ESIInclude::subRequestDone: " << alturl);

        if (success) {
            debugs(86, 3, "ESIIncludeSubRequestDone: ALT OK.");
            /* copy the lead segment */
            assert (!altcontent.getRaw());
            ESISegment::ListTransfer (stream->localbuffer, altcontent);
            /* we're done! */

            if (!(src.getRaw() || srccontent.getRaw())) {
                /* src already failed, kick ESI processor */
                debugs(86, 3, "ESIIncludeSubRequestDone: Include PASSED - SRC already failed.");
                flags.finished = 1;
            }
        } else {
            if (!(src.getRaw() || srccontent.getRaw())) {
                debugs(86, 3, "ESIIncludeSubRequestDone: ALT FAILED, Include FAILED - SRC already failed");
                /* src already failed */
                flags.failed = 1;
            }
        }

        alt = NULL;
    } else {
        fatal ("ESIIncludeSubRequestDone: non-owned stream found!\n");
    }

    if (flags.finished || flags.failed) {
        /* Kick ESI Processor */
        debugs (86, 5, "ESIInclude " << this <<
                " SubRequest " << stream.getRaw() <<
                " completed, kicking processor , status " <<
                (flags.finished ? "OK" : "FAILED"));
        /* There is a race condition - and we have no reproducible test case -
         * during a subrequest the parent will get set to NULL, which is not
         * meant to be possible. Rather than killing squid, we let it leak
         * memory but complain in the log.
         *
         * Someone wanting to debug this could well start by running squid with
         * a hardware breakpoint set to this location.
         * Its probably due to parent being set to null - by a call to
         * 'this.finish' while the subrequest is still not completed.
         */
        if (parent.getRaw() == NULL) {
            debugs (86, 0, "ESIInclude::subRequestDone: Sub request completed "
                    "after finish() called and parent unlinked. Unable to "
                    "continue handling the request, and may be memory leaking. "
                    "See http://www.squid-cache.org/bugs/show_bug.cgi?id=951 - we "
                    "are looking for a reproducible test case. This will require "
                    "an ESI template with includes, probably with alt-options, "
                    "and we're likely to need traffic dumps to allow us to "
                    "reconstruct the exact tcp handling sequences to trigger this "
                    "rather elusive bug.");
            return;
        }
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
            parent->fail(this, "esi:include could not be completed.");
    }
}

#endif /* USE_SQUID_ESI */


#include "squid.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "HttpRequest.h"
#include "ICAPClientReqmodPrecache.h"
#include "ICAPServiceRep.h"
#include "ICAPClient.h"

CBDATA_CLASS_INIT(ICAPClientReqmodPrecache);

ICAPClientReqmodPrecache::ICAPClientReqmodPrecache(ICAPServiceRep::Pointer aService): service(aService), http(NULL), virgin(NULL), adapted(NULL)
{
    debug(93,3)("ICAPClientReqmodPrecache constructed, this=%p\n", this);
}

ICAPClientReqmodPrecache::~ICAPClientReqmodPrecache()
{
    stop(notifyNone);
    cbdataReferenceDone(http);
    debug(93,3)("ICAPClientReqmodPrecache destructed, this=%p\n", this);

    if (virgin != NULL)
        freeVirgin();

    if (adapted != NULL) {
        /*
         * adapted->sink is equal to this.  Remove the pointer since
         * we are deleting this.
         */

        if (adapted->sink)
            adapted->sink = NULL;

        freeAdapted();
    }
}

void ICAPClientReqmodPrecache::startReqMod(ClientHttpRequest *aHttp, HttpRequest *request)
{
    debug(93,3)("ICAPClientReqmodPrecache::startReqMod() called\n");
    http = cbdataReference(aHttp);

    virgin = new MsgPipe("virgin"); // this is the place to create a refcount ptr
    virgin->source = this;
    virgin->data = new MsgPipeData;
    virgin->data->cause = NULL;
    virgin->data->setHeader(request);
    virgin->data->body = new MemBuf;
    virgin->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);

    adapted = new MsgPipe("adapted");
    adapted->sink = this;

    ICAPInitXaction(service, virgin, adapted);

    virgin->sendSourceStart(); // we may have virgin data to provide
    adapted->sendSinkNeed();   // we want adapted response, eventially
}

void ICAPClientReqmodPrecache::sendMoreData(StoreIOBuffer buf)
{
    debug(93,3)("ICAPClientReqmodPrecache::sendMoreData() called\n");
    //buf.dump();
    /*
     * The caller is responsible for not giving us more data
     * than will fit in body MemBuf.  Caller should use
     * potentialSpaceSize() to find out how much we can hold.
     */
    virgin->data->body->append(buf.data, buf.length);
    virgin->sendSourceProgress();
}

int
ICAPClientReqmodPrecache::potentialSpaceSize()
{
    if (virgin == NULL)
        return 0;

    return (int) virgin->data->body->potentialSpaceSize();
}

// ClientHttpRequest says we have the entire HTTP message
void ICAPClientReqmodPrecache::doneSending()
{
    debug(93,3)("ICAPClientReqmodPrecache::doneSending() called\n");

    virgin->sendSourceFinish();
}

// ClientHttpRequest tells us to abort
void ICAPClientReqmodPrecache::ownerAbort()
{
    debug(93,3)("ICAPClientReqmodPrecache::ownerAbort() called\n");
    stop(notifyIcap);
}

// ICAP client needs more virgin response data
void ICAPClientReqmodPrecache::noteSinkNeed(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSinkNeed() called\n");

    if (virgin->data->body->potentialSpaceSize())
        http->icapSpaceAvailable();
}

// ICAP client aborting
void ICAPClientReqmodPrecache::noteSinkAbort(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSinkAbort() called\n");
    stop(notifyOwner);
}

// ICAP client starts sending adapted response
// ICAP client has received new HTTP headers (if any) at this point
void ICAPClientReqmodPrecache::noteSourceStart(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSourceStart() called\n");
    /*
     * If adapted->data->header is NULL then the ICAP response did
     * not have a req/res-hdr section.  Send the NULL pointer to
     * tell the other side to use the original request/response
     * headers.
     */
    HttpRequest *req = dynamic_cast<HttpRequest*>(adapted->data->header);

    if (req && req->content_length > 0) {
        assert(req->body_reader == NULL);
        req->body_reader = new BodyReader(req->content_length, readBody, abortBody, kickBody, this);
    }

    http->takeAdaptedHeaders(adapted->data->header);
    noteSourceProgress(p);
}

/*
 * This is where we receive a notification from the other
 * side of the MsgPipe that new adapted data is available.
 * We, in turn, tell whoever is reading from the request's
 * body_reader about the new data.
 */
void ICAPClientReqmodPrecache::noteSourceProgress(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSourceProgress() called\n");
    //tell ClientHttpRequest to store a fresh portion of the adapted response

    if (p->data->body->hasContent()) {
        HttpRequest *req = dynamic_cast<HttpRequest*>(adapted->data->header);
        assert(req);
        debugs(32,3,HERE << "notifying body_reader, contentSize() = " << p->data->body->contentSize());
        req->body_reader->notify(p->data->body->contentSize());
    }
}

// ICAP client is done sending adapted response
void ICAPClientReqmodPrecache::noteSourceFinish(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSourceFinish() called\n");
    //tell ClientHttpRequest that we expect no more response data
    http->doneAdapting();
    stop(notifyNone);
}

// ICAP client is aborting
void ICAPClientReqmodPrecache::noteSourceAbort(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSourceAbort() called\n");
    stop(notifyOwner);
}

// internal cleanup
void ICAPClientReqmodPrecache::stop(Notify notify)
{
    if (virgin != NULL) {
        if (notify == notifyIcap)
            virgin->sendSourceAbort();
        else
            virgin->source = NULL;

        freeVirgin();
    }

#if DONT_FREE_ADAPTED
    /*
     * NOTE: We do not clean up "adapted->sink" here because it may
     * have an HTTP message body that needs to stay around a little
     * while longer so that the HTTP server-side can forward it on.
     */
    if (adapted != NULL) {
        if (notify == notifyIcap)
            adapted->sendSinkAbort();
        else
            adapted->sink = NULL;

        freeAdapted();
    }

#endif

    if (http) {
        if (notify == notifyOwner)
            // tell ClientHttpRequest that we are aborting prematurely
            http->abortAdapting();

        cbdataReferenceDone(http);

        // http is now NULL, will not call it any more
    }
}

void ICAPClientReqmodPrecache::freeVirgin()
{
    // virgin->data->cause should be NULL;
    virgin = NULL;	// refcounted
}

void ICAPClientReqmodPrecache::freeAdapted()
{
    adapted = NULL;	// refcounted
}

/*
 * Something that needs to read the adapated request body
 * calls this function, via the BodyReader class.  We copy
 * the body data from our bodybuf object to the BodyReader
 * MemBuf, which was passed as a reference to this function.
 */
size_t
ICAPClientReqmodPrecache::readBody(void *data, MemBuf &mb, size_t size)
{
    ICAPClientReqmodPrecache *icap = static_cast<ICAPClientReqmodPrecache *>(data);
    assert(icap != NULL);
    assert(icap->adapted != NULL);
    assert(icap->adapted->data != NULL);
    MemBuf *bodybuf = icap->adapted->data->body;
    assert(bodybuf != NULL);
    debugs(32,3,HERE << "readBody requested size " << size);
    debugs(32,3,HERE << "readBody bodybuf size " << bodybuf->contentSize());

    if ((mb_size_t) size > bodybuf->contentSize())
        size = bodybuf->contentSize();

    debugs(32,3,HERE << "readBody actual size " << size);

    assert(size);

    mb.append(bodybuf->content(), size);

    bodybuf->consume(size);

    return size;
}

void
ICAPClientReqmodPrecache::abortBody(void *data, size_t remaining)
{
    if (remaining >= 0) {
        debugs(0,0,HERE << "ICAPClientReqmodPrecache::abortBody size " << remaining);
        // more?
    }

    ICAPClientReqmodPrecache *icap = static_cast<ICAPClientReqmodPrecache *>(data);
    icap->stop(notifyIcap);
}

/*
 * Restart reading the adapted response from the ICAP server in case
 * the body buffer became full and we stopped reading.
 */
void
ICAPClientReqmodPrecache::kickBody(void *data)
{
    debugs(32,3,HERE << "ICAPClientReqmodPrecache::kickBody");
    ICAPClientReqmodPrecache *icap = static_cast<ICAPClientReqmodPrecache *>(data);
    assert(icap->adapted != NULL);
    icap->adapted->sendSinkNeed();
}

#include "squid.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "MsgPipeData.h"
#include "HttpRequest.h"
#include "ICAPClientReqmodPrecache.h"
#include "ICAPServiceRep.h"
#include "ICAPClient.h"

CBDATA_CLASS_INIT(ICAPClientReqmodPrecache);

ICAPClientReqmodPrecache::ICAPClientReqmodPrecache(ICAPServiceRep::Pointer aService):
    ICAPClientVector(aService, "ICAPClientReqmodPrecache"), http(NULL)
{
}

void ICAPClientReqmodPrecache::startReqMod(ClientHttpRequest *aHttp, HttpRequest *request)
{
    http = cbdataReference(aHttp);
    startMod(http, NULL, request);
}

void ICAPClientReqmodPrecache::tellSpaceAvailable() {
    http->icapSpaceAvailable();
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
        /*
         * NOTE: req will be NULL if this is a "request satisfaction"
         * ICAP reply.  In other words, the ICAP REQMOD reply may
         * contain an HTTP response, in which case we'll have a body, but
         * adapted->data->header will be an HttpReply, not an HttpRequest.
         */
        HttpRequest *req = dynamic_cast<HttpRequest*>(adapted->data->header);

        if (req) {
            debugs(93,3,HERE << "notifying body_reader, contentSize() = " << p->data->body->contentSize());
            req->body_reader->notify(p->data->body->contentSize());
        } else {
            http->takeAdaptedBody(adapted->data->body);
        }
    }
}

void ICAPClientReqmodPrecache::tellDoneAdapting()
{
    debug(93,3)("ICAPClientReqmodPrecache::tellDoneAdapting() called\n");
    //tell ClientHttpRequest that we expect no more response data
    http->doneAdapting(); // does not delete us (yet?)
    stop(notifyNone);
    // we should be eventually deleted by owner in ~ClientHttpRequest()
}

void ICAPClientReqmodPrecache::tellAbortAdapting()
{
    debug(93,3)("ICAPClientReqmodPrecache::tellAbortAdapting() called\n");
    // tell ClientHttpRequest that we are aborting ICAP processing prematurely
    http->abortAdapting();
}

// internal cleanup
void ICAPClientReqmodPrecache::stop(Notify notify)
{
    /*
     * NOTE: We do not clean up "adapted->sink" here because it may
     * have an HTTP message body that needs to stay around a little
     * while longer so that the HTTP server-side can forward it on.
     */

    // XXX: who will clean up the "adapted->sink" then? Does it happen
    // when the owner deletes us? Is that why we are deleted when the
    // owner is destroyed and not when ICAP adaptation is done, like
    // in http.cc case?

    // XXX: "adapted->sink" does not really have an "HTTP message body",
    // In fact, it simply points to "this". Should the above comment
    // refer to adapted and adapted->data->body?

    ICAPClientVector::clean(notify, false);
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
    debugs(93,3,HERE << "readBody requested size " << size);
    debugs(93,3,HERE << "readBody bodybuf size " << bodybuf->contentSize());

    if ((mb_size_t) size > bodybuf->contentSize())
        size = bodybuf->contentSize();

    debugs(93,3,HERE << "readBody actual size " << size);

    assert(size);

    mb.append(bodybuf->content(), size);

    bodybuf->consume(size);

    return size;
}

void
ICAPClientReqmodPrecache::abortBody(void *data, size_t remaining)
{
    if (remaining >= 0) {
        debugs(93,1,HERE << "ICAPClientReqmodPrecache::abortBody size " << remaining);
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
    debugs(93,3,HERE << "ICAPClientReqmodPrecache::kickBody");
    ICAPClientReqmodPrecache *icap = static_cast<ICAPClientReqmodPrecache *>(data);
    assert(icap->adapted != NULL);
    icap->adapted->sendSinkNeed();
}

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

    if (adapted != NULL)
        freeAdapted();
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
    http->takeAdaptedHeaders(adapted->data->header);
    noteSourceProgress(p);
}

// ICAP client sends more data
void ICAPClientReqmodPrecache::noteSourceProgress(MsgPipe *p)
{
    debug(93,3)("ICAPClientReqmodPrecache::noteSourceProgress() called\n");
    //tell ClientHttpRequest to store a fresh portion of the adapted response

    if (p->data->body->hasContent()) {
        http->takeAdaptedBody(p->data->body);
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

    if (adapted != NULL) {
        if (notify == notifyIcap)
            adapted->sendSinkAbort();
        else
            adapted->sink = NULL;

        freeAdapted();
    }

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

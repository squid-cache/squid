#include "squid.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "HttpRequest.h"
#include "ICAPClientSideHook.h"
#include "ICAPServiceRep.h"
#include "ICAPClient.h"

#include "LeakFinder.h"

extern LeakFinder *MsgPipeLeaker;

CBDATA_CLASS_INIT(ICAPClientSideHook);

ICAPClientSideHook::ICAPClientSideHook(ICAPServiceRep::Pointer aService): service(aService), http(NULL), virgin(NULL), adapted(NULL)
{
    debug(93,3)("ICAPClientSideHook constructed, this=%p\n", this);
}

ICAPClientSideHook::~ICAPClientSideHook()
{
    stop(notifyNone);
    cbdataReferenceDone(http);
    debug(93,3)("ICAPClientSideHook destructed, this=%p\n", this);

    if (virgin != NULL)
        freeVirgin();

    if (adapted != NULL)
        freeAdapted();
}

void ICAPClientSideHook::startReqMod(ClientHttpRequest *aHttp, HttpRequest *request)
{
    debug(93,3)("ICAPClientSideHook::startReqMod() called\n");
    http = cbdataReference(aHttp);

    virgin = new MsgPipe("virgin"); // this is the place to create a refcount ptr
    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin->source = this;
    virgin->data = new MsgPipeData;
    virgin->data->cause = NULL;
    virgin->data->header = requestLink(request);
    virgin->data->body = new MemBuf;
    virgin->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);

    adapted = new MsgPipe("adapted");
    leakTouch(adapted.getRaw(), MsgPipeLeaker);
    adapted->sink = this;

    ICAPInitXaction(service, virgin, adapted);

    virgin->sendSourceStart(); // we may have virgin data to provide
    adapted->sendSinkNeed();   // we want adapted response, eventially
}

void ICAPClientSideHook::sendMoreData(StoreIOBuffer buf)
{
    debug(93,3)("ICAPClientSideHook::sendMoreData() called\n");
    //buf.dump();
    /*
     * The caller is responsible for not giving us more data
     * than will fit in body MemBuf.  Caller should use
     * potentialSpaceSize() to find out how much we can hold.
     */
    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin->data->body->append(buf.data, buf.length);
    virgin->sendSourceProgress();
}

int
ICAPClientSideHook::potentialSpaceSize()
{
    if (virgin == NULL)
        return 0;

    leakTouch(virgin.getRaw(), MsgPipeLeaker);

    return (int) virgin->data->body->potentialSpaceSize();
}

// ClientHttpRequest says we have the entire HTTP message
void ICAPClientSideHook::doneSending()
{
    debug(93,3)("ICAPClientSideHook::doneSending() called\n");
    leakTouch(virgin.getRaw(), MsgPipeLeaker);

    virgin->sendSourceFinish();
}

// ClientHttpRequest tells us to abort
void ICAPClientSideHook::ownerAbort()
{
    debug(93,3)("ICAPClientSideHook::ownerAbort() called\n");
    stop(notifyIcap);
}

// ICAP client needs more virgin response data
void ICAPClientSideHook::noteSinkNeed(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSinkNeed() called\n");

    leakTouch(virgin.getRaw(), MsgPipeLeaker);

    if (virgin->data->body->potentialSpaceSize())
        http->icapSpaceAvailable();
}

// ICAP client aborting
void ICAPClientSideHook::noteSinkAbort(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSinkAbort() called\n");
    stop(notifyOwner);
}

// ICAP client starts sending adapted response
// ICAP client has received new HTTP headers (if any) at this point
void ICAPClientSideHook::noteSourceStart(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSourceStart() called\n");
    leakTouch(adapted.getRaw(), MsgPipeLeaker);
    http->takeAdaptedHeaders(adapted->data->header);
    noteSourceProgress(p);
}

// ICAP client sends more data
void ICAPClientSideHook::noteSourceProgress(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSourceProgress() called\n");
    //tell ClientHttpRequest to store a fresh portion of the adapted response

    leakTouch(p, MsgPipeLeaker);

    if (p->data->body->hasContent()) {
        http->takeAdaptedBody(p->data->body);
    }
}

// ICAP client is done sending adapted response
void ICAPClientSideHook::noteSourceFinish(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSourceFinish() called\n");
    //tell ClientHttpRequest that we expect no more response data
    leakTouch(p, MsgPipeLeaker);
    http->doneAdapting();
    stop(notifyNone);
}

// ICAP client is aborting
void ICAPClientSideHook::noteSourceAbort(MsgPipe *p)
{
    debug(93,3)("ICAPClientSideHook::noteSourceAbort() called\n");
    leakTouch(p, MsgPipeLeaker);
    stop(notifyOwner);
}

// internal cleanup
void ICAPClientSideHook::stop(Notify notify)
{
    if (virgin != NULL) {
        leakTouch(virgin.getRaw(), MsgPipeLeaker);

        if (notify == notifyIcap)
            virgin->sendSourceAbort();
        else
            virgin->source = NULL;

        freeVirgin();
    }

    if (adapted != NULL) {
        leakTouch(adapted.getRaw(), MsgPipeLeaker);

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

void ICAPClientSideHook::freeVirgin()
{
    // virgin->data->cause should be NULL;
    requestUnlink(dynamic_cast<HttpRequest*>(virgin->data->header));
    virgin->data->header = NULL;
    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin = NULL;	// refcounted
}

void ICAPClientSideHook::freeAdapted()
{
    adapted->data->header = NULL;	// we don't own it
    leakTouch(adapted.getRaw(), MsgPipeLeaker);
    adapted = NULL;	// refcounted
}

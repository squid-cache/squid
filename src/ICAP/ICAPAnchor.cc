#include "squid.h"
#include "http.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ICAPAnchor.h"
#include "ICAPClient.h"
#include "ICAPServiceRep.h"

#include "LeakFinder.h"

CBDATA_CLASS_INIT(ICAPAnchor);

extern LeakFinder *MsgPipeLeaker;

ICAPAnchor::ICAPAnchor(ICAPServiceRep::Pointer aService): service(aService), httpState(NULL), virgin(NULL), adapted(NULL)
{
    debug(93,5)("ICAPAnchor constructed, this=%p\n", this);
}

ICAPAnchor::~ICAPAnchor()
{
    stop(notifyNone);
    cbdataReferenceDone(httpState);
    debug(93,5)("ICAPAnchor destructed, this=%p\n", this);

    if (virgin != NULL)
        freeVirgin();

    if (adapted != NULL)
        freeAdapted();

    service = NULL;
}

void ICAPAnchor::startRespMod(HttpStateData *anHttpState, HttpRequest *request, HttpReply *reply)
{
    httpState = cbdataReference(anHttpState);

    virgin = new MsgPipe("virgin"); // this is the place to create a refcount ptr
    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin->source = this;
    virgin->data = new MsgPipeData;
    virgin->data->cause = requestLink(request);
    virgin->data->header = reply;
    virgin->data->body = new MemBuf;
    virgin->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);

    adapted = new MsgPipe("adapted");
    leakTouch(adapted.getRaw(), MsgPipeLeaker);
    adapted->sink = this;
#if ICAP_ANCHOR_LOOPBACK

    adapted->data = new MsgPipeData;
    adapted->data->cause = request; // should not hurt
#else

    ICAPInitXaction(service, virgin, adapted);
#endif

    virgin->sendSourceStart(); // we may have virgin data to provide
    adapted->sendSinkNeed();   // we want adapted response, eventially
}

void ICAPAnchor::sendMoreData(StoreIOBuffer buf)
{
    debug(93,5)("ICAPAnchor::sendMoreData() called\n");
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
ICAPAnchor::potentialSpaceSize()
{
    if (virgin == NULL)
        return 0;

    leakTouch(virgin.getRaw(), MsgPipeLeaker);

    return (int) virgin->data->body->potentialSpaceSize();
}

// HttpStateData says we have the entire HTTP message
void ICAPAnchor::doneSending()
{
    debug(93,5)("ICAPAnchor::doneSending() called\n");

#if ICAP_ANCHOR_LOOPBACK
    /* simple assignments are not the right way to do this */
    adapted->data->header = virgin->data->header;
    adapted->data->body = virgin->data->body;
    noteSourceFinish(adapted);
    return;
#else

    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin->sendSourceFinish();
#endif
}

// HttpStateData tells us to abort
void ICAPAnchor::ownerAbort()
{
    debug(93,5)("ICAPAnchor::ownerAbort() called\n");
    stop(notifyIcap);
}

// ICAP client needs more virgin response data
void ICAPAnchor::noteSinkNeed(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSinkNeed() called\n");

    leakTouch(virgin.getRaw(), MsgPipeLeaker);

    if (virgin->data->body->potentialSpaceSize())
        httpState->icapSpaceAvailable();
}

// ICAP client aborting
void ICAPAnchor::noteSinkAbort(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSinkAbort() called\n");
    stop(notifyOwner);
}

// ICAP client starts sending adapted response
// ICAP client has received new HTTP headers (if any) at this point
void ICAPAnchor::noteSourceStart(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSourceStart() called\n");
    leakTouch(adapted.getRaw(), MsgPipeLeaker);

    HttpReply *reply = dynamic_cast<HttpReply*>(adapted->data->header);
    assert(reply); // check that ICAP xaction created the right object
    httpState->takeAdaptedHeaders(reply);

    assert(reply == adapted->data->header);
    adapted->data->header = NULL;

    noteSourceProgress(p);
}

// ICAP client sends more data
void ICAPAnchor::noteSourceProgress(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSourceProgress() called\n");
    //tell HttpStateData to store a fresh portion of the adapted response

    leakTouch(p, MsgPipeLeaker);

    if (p->data->body->hasContent()) {
        httpState->takeAdaptedBody(p->data->body);
    }
}

// ICAP client is done sending adapted response
void ICAPAnchor::noteSourceFinish(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSourceFinish() called\n");
    //tell HttpStateData that we expect no more response data
    leakTouch(p, MsgPipeLeaker);
    httpState->doneAdapting();
    stop(notifyNone);
}

// ICAP client is aborting
void ICAPAnchor::noteSourceAbort(MsgPipe *p)
{
    debug(93,5)("ICAPAnchor::noteSourceAbort() called\n");
    leakTouch(p, MsgPipeLeaker);
    stop(notifyOwner);
}

// internal cleanup
void ICAPAnchor::stop(Notify notify)
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

    if (httpState) {
        if (notify == notifyOwner)
            // tell HttpStateData that we are aborting prematurely
            httpState->abortAdapting();

        cbdataReferenceDone(httpState);

        // httpState is now NULL, will not call it any more
    }
}

void ICAPAnchor::freeVirgin()
{
    requestUnlink(virgin->data->cause);
    virgin->data->cause = NULL;
    virgin->data->header = NULL;
    leakTouch(virgin.getRaw(), MsgPipeLeaker);
    virgin = NULL;	// refcounted
}

void ICAPAnchor::freeAdapted()
{
    /*
     * Note on adapted->data->header.  ICAPXaction-side created it
     * but gave control of it to us.  Normally we give it to
     * HttpStateData::takeAdaptedHeader.  If not, we have to
     * make sure it gets deleted;
     */

    if (adapted->data->header != NULL) {
        debug(93,3)("hey, adapted->data->header is still set!\n");
        delete adapted->data->header;
        adapted->data->header = NULL;
    }

    leakTouch(adapted.getRaw(), MsgPipeLeaker);
    adapted = NULL;	// refcounted
}

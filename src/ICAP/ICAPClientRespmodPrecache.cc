#include "squid.h"
#include "http.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ICAPClientRespmodPrecache.h"
#include "ICAPClient.h"
#include "ICAPServiceRep.h"

CBDATA_CLASS_INIT(ICAPClientRespmodPrecache);

ICAPClientRespmodPrecache::ICAPClientRespmodPrecache(ICAPServiceRep::Pointer aService): service(aService), httpState(NULL), virgin(NULL), adapted(NULL)
{
    debug(93,5)("ICAPClientRespmodPrecache constructed, this=%p\n", this);
}

ICAPClientRespmodPrecache::~ICAPClientRespmodPrecache()
{
    stop(notifyNone);
    cbdataReferenceDone(httpState);
    debug(93,5)("ICAPClientRespmodPrecache destructed, this=%p\n", this);

    if (virgin != NULL)
        freeVirgin();

    if (adapted != NULL)
        freeAdapted();

    service = NULL;
}

void ICAPClientRespmodPrecache::startRespMod(HttpStateData *anHttpState, HttpRequest *request, HttpReply *reply)
{
    httpState = cbdataReference(anHttpState);

    virgin = new MsgPipe("virgin"); // this is the place to create a refcount ptr
    virgin->source = this;
    virgin->data = new MsgPipeData;
    virgin->data->cause = requestLink(request);
    virgin->data->header = reply;
    virgin->data->body = new MemBuf;
    virgin->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);

    adapted = new MsgPipe("adapted");
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

void ICAPClientRespmodPrecache::sendMoreData(StoreIOBuffer buf)
{
    debug(93,5)("ICAPClientRespmodPrecache::sendMoreData() called\n");
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
ICAPClientRespmodPrecache::potentialSpaceSize()
{
    if (virgin == NULL)
        return 0;

    return (int) virgin->data->body->potentialSpaceSize();
}

// HttpStateData says we have the entire HTTP message
void ICAPClientRespmodPrecache::doneSending()
{
    debug(93,5)("ICAPClientRespmodPrecache::doneSending() called\n");

#if ICAP_ANCHOR_LOOPBACK
    /* simple assignments are not the right way to do this */
    adapted->data->header = virgin->data->header;
    adapted->data->body = virgin->data->body;
    noteSourceFinish(adapted);
    return;
#else

    virgin->sendSourceFinish();
#endif
}

// HttpStateData tells us to abort
void ICAPClientRespmodPrecache::ownerAbort()
{
    debug(93,5)("ICAPClientRespmodPrecache::ownerAbort() called\n");
    stop(notifyIcap);
}

// ICAP client needs more virgin response data
void ICAPClientRespmodPrecache::noteSinkNeed(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSinkNeed() called\n");

    if (virgin->data->body->potentialSpaceSize())
        httpState->icapSpaceAvailable();
}

// ICAP client aborting
void ICAPClientRespmodPrecache::noteSinkAbort(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSinkAbort() called\n");
    stop(notifyOwner);
}

// ICAP client starts sending adapted response
// ICAP client has received new HTTP headers (if any) at this point
void ICAPClientRespmodPrecache::noteSourceStart(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSourceStart() called\n");

    /*
     * May want to assert that adapted != NULL here
     */

    HttpReply *reply = dynamic_cast<HttpReply*>(adapted->data->header);
    /*
     *	The ICAP reply MUST have a new HTTP reply header, or else
     *	it is an invalid ICAP message.  Invalid ICAP messages should
     *	be handled prior to this point.
     */
    assert(reply); // check that ICAP xaction created the right object
    assert(reply == adapted->data->header);

    /*
     * Examine the HTTP reply headers to find out if there is an associated
     * body.  We should probably check the ICAP Encapsulated header values
     * as well.
     */
    ssize_t dummy;
    bool expect_body = reply->expectingBody(virgin->data->cause->method, dummy);

    /*
     * When we call takeAdaptedHeaders() we give up any control over
     * adapted->data->header
     */
    httpState->takeAdaptedHeaders(reply);
    adapted->data->header = NULL;
    reply = NULL;

    if (expect_body)
        noteSourceProgress(p);
    else
        noteSourceFinish(p);
}

// ICAP client sends more data
void ICAPClientRespmodPrecache::noteSourceProgress(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSourceProgress() called\n");
    //tell HttpStateData to store a fresh portion of the adapted response

    if (p->data->body->hasContent()) {
        httpState->takeAdaptedBody(p->data->body);
    }
}

// ICAP client is done sending adapted response
void ICAPClientRespmodPrecache::noteSourceFinish(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSourceFinish() called\n");
    //tell HttpStateData that we expect no more response data
    httpState->doneAdapting();
    stop(notifyNone);
}

// ICAP client is aborting
void ICAPClientRespmodPrecache::noteSourceAbort(MsgPipe *p)
{
    debug(93,5)("ICAPClientRespmodPrecache::noteSourceAbort() called\n");
    stop(notifyOwner);
}

// internal cleanup
void ICAPClientRespmodPrecache::stop(Notify notify)
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

    if (httpState) {
        if (notify == notifyOwner)
            // tell HttpStateData that we are aborting prematurely
            httpState->abortAdapting();

        cbdataReferenceDone(httpState);

        // httpState is now NULL, will not call it any more
    }
}

void ICAPClientRespmodPrecache::freeVirgin()
{
    requestUnlink(virgin->data->cause);
    virgin->data->cause = NULL;
    virgin->data->header = NULL;
    virgin = NULL;	// refcounted
}

void ICAPClientRespmodPrecache::freeAdapted()
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

    adapted = NULL;	// refcounted
}

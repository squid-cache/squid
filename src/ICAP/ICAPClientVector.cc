#include "squid.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "HttpRequest.h"
#include "ICAPClientVector.h"
#include "ICAPClient.h"

ICAPClientVector::ICAPClientVector(ICAPServiceRep::Pointer aService, const char *aPoint):
    theOwner(0), vPoint(aPoint),
    service(aService), virgin(NULL), adapted(NULL)
{
    debug(93,3)("%s constructed, this=%p\n", vPoint, this);
}

ICAPClientVector::~ICAPClientVector()
{
    stop(notifyNone);
    debug(93,3)("%s destructed, this=%p\n", vPoint, this);
}

void ICAPClientVector::startMod(void *anOwner, HttpRequest *cause, HttpMsg *header)
{
    debug(93,5)("%s starting, this=%p\n", vPoint, this);

    theOwner = anOwner;

    virgin = new MsgPipe("virgin"); // this is the place to create a refcount ptr
    virgin->source = this;
    virgin->data = new MsgPipeData;
    virgin->data->setCause(cause);
    virgin->data->setHeader(header);
    virgin->data->body = new MemBuf;
    virgin->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);

    adapted = new MsgPipe("adapted");
    adapted->sink = this;

#if ICAP_ANCHOR_LOOPBACK
    adapted->data = new MsgPipeData;
    adapted->data->setCause(request); // should not hurt
#else
    ICAPInitXaction(service, virgin, adapted);
#endif

    virgin->sendSourceStart(); // we may have virgin data to provide
    adapted->sendSinkNeed();   // we want adapted response, eventially
}

void ICAPClientVector::sendMoreData(StoreIOBuffer buf)
{
    debug(93,7)("%s::sendMoreData(%p)\n", vPoint, this);
    //debugs(93,0,HERE << "appending " << buf.length << " bytes");
    //debugs(93,0,HERE << "body.contentSize = " << virgin->data->body->contentSize());
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
ICAPClientVector::potentialSpaceSize()
{
    if (virgin == NULL)
        return 0;

    return (int) virgin->data->body->potentialSpaceSize();
}

// Owner says we have the entire HTTP message
void ICAPClientVector::doneSending()
{
    debug(93,3)("%s::doneSending(%p)\n", vPoint, this);

#if ICAP_ANCHOR_LOOPBACK
    /* simple assignments are not the right way to do this */
    adapted->data->setHeader(virgin->data->header);
    adapted->data->body = virgin->data->body;
    noteSourceFinish(adapted);
    // checkDoneAdapting() does not support loopback mode
    return;
#else
    virgin->sendSourceFinish();
    checkDoneAdapting(); // may call the owner back, unfortunately
#endif
}

// Owner tells us to abort
void ICAPClientVector::ownerAbort()
{
    debug(93,3)("%s::ownerAbort(%p)\n", vPoint, this);
    stop(notifyIcap);
}

// ICAP client needs more virgin response data
void ICAPClientVector::noteSinkNeed(MsgPipe *p)
{
    debug(93,3)("%s::noteSinkNeed(%p)\n", vPoint, this);

    if (virgin->data->body->potentialSpaceSize())
        tellSpaceAvailable();
}

// ICAP client aborting
void ICAPClientVector::noteSinkAbort(MsgPipe *p)
{
    debug(93,3)("%s::noteSinkAbort(%p)\n", vPoint, this);
    stop(notifyOwner); // deletes us
}

// ICAP client is done sending adapted response
void ICAPClientVector::noteSourceFinish(MsgPipe *p)
{
    debug(93,3)("%s::noteSourceFinish(%p)\n", vPoint, this);
    checkDoneAdapting(); // may delete us
}

void ICAPClientVector::checkDoneAdapting() {
    debug(93,5)("%s::checkDoneAdapting(%p): %d & %d\n", vPoint, this,
        (int)!virgin->source, (int)!adapted->source);
    // done if we are not sending and are not receiving
    if (!virgin->source && !adapted->source)
        tellDoneAdapting(); // deletes us
}

// ICAP client is aborting
void ICAPClientVector::noteSourceAbort(MsgPipe *p)
{
    debug(93,3)("%s::noteSourceAbort(%p)\n", vPoint, this);
    stop(notifyOwner); // deletes us
}

void ICAPClientVector::stop(Notify notify)
{
    debug(93,3)("%s::stop(%p, %d)\n", vPoint, this, (int)notify);
    clean(notify, true);
}

void ICAPClientVector::clean(Notify notify, bool cleanAdapted)
{
    if (virgin != NULL) {
        if (notify == notifyIcap)
            virgin->sendSourceAbort();
        else
            virgin->source = NULL;
        virgin = NULL;  // refcounted
    }

    if (cleanAdapted && adapted != NULL) {
        if (notify == notifyIcap)
            adapted->sendSinkAbort();
        else
            adapted->sink = NULL;
        adapted = NULL; // refcounted
    }

    service = NULL;

    if (theOwner) {
        if (notify == notifyOwner)
            tellAbortAdapting(); // deletes us
        else
            cbdataReferenceDone(theOwner);
    }

    // not safe to do anything here because we may have been deleted.
}

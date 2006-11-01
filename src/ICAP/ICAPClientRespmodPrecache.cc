#include "squid.h"
#include "http.h"
#include "MsgPipeData.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ICAPClientRespmodPrecache.h"
#include "ICAPClient.h"
#include "ICAPServiceRep.h"

CBDATA_CLASS_INIT(ICAPClientRespmodPrecache);

ICAPClientRespmodPrecache::ICAPClientRespmodPrecache(ICAPServiceRep::Pointer aService):
    ICAPClientVector(aService, "ICAPClientRespmodPrecache"), serverState(NULL)
{
}

void ICAPClientRespmodPrecache::startRespMod(ServerStateData *aServerState, HttpRequest *request, HttpReply *reply)
{
    serverState = cbdataReference(aServerState);
    startMod(serverState, request, reply);
}

// ICAP client starts sending adapted response
// ICAP client has received new HTTP headers (if any) at this point
void ICAPClientRespmodPrecache::noteSourceStart(MsgPipe *p)
{
    debugs(93,3, HERE << "ICAPClientRespmodPrecache::noteSourceStart() called");

    HttpReply *reply = dynamic_cast<HttpReply*>(adapted->data->header);
    /*
     * The ICAP reply MUST have a new HTTP reply header, or else
     * it is an invalid ICAP message.  Invalid ICAP messages should
     * be handled prior to this point.
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

    if (!serverState->takeAdaptedHeaders(reply)) // deletes us
        return;

    if (expect_body)
        noteSourceProgress(p);
    else
        noteSourceFinish(p);
}

// ICAP client sends more data
void ICAPClientRespmodPrecache::noteSourceProgress(MsgPipe *p)
{
    debug(93,3)("ICAPClientRespmodPrecache::noteSourceProgress() called\n");
    //tell ServerStateData to store a fresh portion of the adapted response

    assert(serverState);

    if (p->data->body->hasContent()) {
        if (!serverState->takeAdaptedBody(p->data->body))
            return;

        // HttpStateData::takeAdaptedBody does not detect when we have enough,
        // so we always notify source that there more buffer space is available
        if (p->data->body->hasPotentialSpace())
            adapted->sendSinkNeed(); 
    }
}

void
ICAPClientRespmodPrecache::tellSpaceAvailable()
{
    serverState->icapSpaceAvailable();
}

void
ICAPClientRespmodPrecache::tellDoneAdapting()
{
    serverState->finishAdapting(); // deletes us
}

void
ICAPClientRespmodPrecache::tellAbortAdapting()
{
    debug(93,3)("ICAPClientReqmodPrecache::tellAbortAdapting() called\n");
    // tell ClientHttpRequest that we are aborting ICAP processing prematurely
    serverState->abortAdapting(); // deletes us
}


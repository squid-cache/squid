#include "squid.h"
#include "client_side.h"
#include "client_side_request.h"
#include "client_side_reply.h"
#include "Downloader.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"

CBDATA_CLASS_INIT(Downloader);

Downloader::Downloader(SBuf &url, const MasterXaction::Pointer &xact, AsyncCall::Pointer &aCallback, unsigned int level):
    AsyncJob("Downloader"),
    ConnStateData(xact),
    url_(url),
    callback(aCallback),
    status(Http::scNone),
    level_(level)
{
    transferProtocol = AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1);
}

Downloader::~Downloader()
{
    debugs(33 , 2, "Downloader Finished");
}

bool
Downloader::doneAll() const
{
    return (!callback || callback->canceled()) && AsyncJob::doneAll();
}

void
Downloader::start()
{
    ConnStateData::start();
    if (Http::Stream *context = parseOneRequest()) {
        context->registerWithConn();
        processParsedRequest(context);
        if (context->flags.deferred) {
            if (context != context->http->getConn()->pipeline.front().getRaw())
                context->deferRecipientForLater(context->deferredparams.node, context->deferredparams.rep, context->deferredparams.queuedBuffer);
            else
                context->http->getConn()->handleReply(context->deferredparams.rep, context->deferredparams.queuedBuffer); 
        }
    } else {
        status = Http::scInternalServerError;
        callBack();
    }
}

void
Downloader::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    // This method required only if we need to support uploading data to server.
    // Currently only GET requests are supported.
    assert(false);
}

void
Downloader::noteBodyConsumerAborted(BodyPipe::Pointer)
{
    // This method required only if we need to support uploading data to server.
    // Currently only GET requests are supported.
    assert(false);
}

Http::Stream *
Downloader::parseOneRequest()
{ 
    const HttpRequestMethod method = Http::METHOD_GET;

    char *uri = strdup(url_.c_str());
    HttpRequest *const request = HttpRequest::CreateFromUrl(uri, method);
    if (!request) {
        debugs(33, 5, "Invalid FTP URL: " << uri);
        safe_free(uri);
        return nullptr; //earlyError(...)
    }
    request->http_ver = Http::ProtocolVersion();
    request->header.putStr(Http::HdrType::HOST, request->url.host());
    request->header.putTime(Http::HdrType::DATE, squid_curtime);

    ClientHttpRequest *const http = new ClientHttpRequest(this);
    http->request = request;
    HTTPMSGLOCK(http->request);
    http->req_sz = 0;
    http->uri = uri;

    Http::Stream *const context = new Http::Stream(nullptr, http);
    StoreIOBuffer tempBuffer;
    tempBuffer.data = context->reqbuf;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = context;
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, clientSocketRecipient,
                     clientSocketDetach, newClient, tempBuffer);

    context->flags.parsed_ok = 1;
    return context;
}

void
Downloader::processParsedRequest(Http::Stream *context)
{
    Must(context);
    Must(pipeline.nrequests == 1);

    ClientHttpRequest *const http = context->http;
    Must(http);

    debugs(33, 4, "forwarding request to server side");
    Must(http->storeEntry() == nullptr);
    clientProcessRequest(this, Http1::RequestParserPointer(), context);
}

time_t
Downloader::idleTimeout() const
{
    // No need to be implemented for connection-less ConnStateData object.
    assert(false);
    return 0;
}

void
Downloader::writeControlMsgAndCall(HttpReply *rep, AsyncCall::Pointer &call)
{
    // nobody to forward the control message to
}

void
Downloader::handleReply(HttpReply *reply, StoreIOBuffer receivedData)
{
    Http::StreamPointer context = pipeline.front();
    bool existingContent = reply ? reply->content_length : 0;
    bool exceedSize = (context->startOfOutput() && existingContent > -1 && (size_t)existingContent > MaxObjectSize) || 
        ((object.length() + receivedData.length) > MaxObjectSize);

    if (exceedSize) {
        status = Http::scInternalServerError;
        callBack();
        return;
    }

    debugs(33, 4, "Received " << receivedData.length <<
           " object data, offset: " << receivedData.offset <<
           " error flag:" << receivedData.flags.error);

    if (receivedData.length > 0) {
        object.append(receivedData.data, receivedData.length);
        context->http->out.size += receivedData.length;
        context->noteSentBodyBytes(receivedData.length);
    }

    switch (context->socketState()) {
    case STREAM_NONE:
         debugs(33, 3, "Get more data");
        context->pullData();
        break;
    case STREAM_COMPLETE:
        debugs(33, 3, "Object data transfer successfully complete");
        status = Http::scOkay;
        callBack();
        break;
    case STREAM_UNPLANNED_COMPLETE:
        debugs(33, 3, "Object data transfer failed: STREAM_UNPLANNED_COMPLETE");
        status = Http::scInternalServerError;
        callBack();
        break;
    case STREAM_FAILED:
        debugs(33, 3, "Object data transfer failed: STREAM_FAILED");
        status = Http::scInternalServerError;
        callBack();
        break;
    default:
        fatal("unreachable code");
    }
}

void
Downloader::downloadFinished()
{
    debugs(33, 7, this);
    Must(done());
    // Not really needed. Squid will delete this object because "doneAll" is true.
    //deleteThis("completed");
}

void
Downloader::callBack()
{
     CbDialer *dialer = dynamic_cast<CbDialer*>(callback->getDialer());
     Must(dialer);
     dialer->status = status;
     if (status == Http::scOkay)
         dialer->object = object;
     ScheduleCallHere(callback);
     callback = nullptr;
     // Calling deleteThis method here to finish Downloader
     // may result to squid crash.
     // This method called by handleReply method which maybe called
     // by ClientHttpRequest::doCallouts. The doCallouts after this object
     // deleted, may operate on non valid objects.
     // Schedule a fake call here just to force squid to delete this object.
     CallJobHere(33, 7, CbcPointer<Downloader>(this), Downloader, downloadFinished);
}

bool
Downloader::isOpen() const
{
    return cbdataReferenceValid(this) && !doneAll();
}

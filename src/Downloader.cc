#include "squid.h"
#include "client_side.h"
#include "client_side_request.h"
#include "client_side_reply.h"
#include "ClientRequestContext.h"
#include "Downloader.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"

CBDATA_CLASS_INIT(DownloaderContext);
CBDATA_CLASS_INIT(Downloader);

DownloaderContext::~DownloaderContext()
{
    debugs(33, 5, HERE);
    cbdataReference(downloader);
    if (http)
        finished();
}

void
DownloaderContext::finished()
{
    cbdataReference(http);
    delete http;
    http = NULL;
}

Downloader::Downloader(SBuf &url, AsyncCall::Pointer &aCallback, unsigned int level):
    AsyncJob("Downloader"),
    url_(url),
    callback(aCallback),
    status(Http::scNone),
    level_(level)
{
}

Downloader::~Downloader()
{
    debugs(33 , 2, HERE);
}

bool
Downloader::doneAll() const
{
    return (!callback || callback->canceled()) && AsyncJob::doneAll();
}

static void
downloaderRecipient(clientStreamNode * node, ClientHttpRequest * http,
                    HttpReply * rep, StoreIOBuffer receivedData)
{
    debugs(33, 6, HERE);
     /* Test preconditions */
    assert(node != NULL);

    /* TODO: handle this rather than asserting
     * - it should only ever happen if we cause an abort and
     * the callback chain loops back to here, so we can simply return.
     * However, that itself shouldn't happen, so it stays as an assert for now.
     */
    assert(cbdataReferenceValid(node));
    assert(node->node.next == NULL);
    DownloaderContext::Pointer context = dynamic_cast<DownloaderContext *>(node->data.getRaw());
    assert(context != NULL);

    if (!cbdataReferenceValid(context->downloader))
        return;

    context->downloader->handleReply(node, http, rep, receivedData);
}

static void
downloaderDetach(clientStreamNode * node, ClientHttpRequest * http)
{
    debugs(33, 5, HERE);
    clientStreamDetach(node, http);
}

bool
Downloader::buildRequest()
{ 
    const HttpRequestMethod method = Http::METHOD_GET;

    char *uri = strdup(url_.c_str());
    HttpRequest *const request = HttpRequest::CreateFromUrl(uri, method);
    if (!request) {
        debugs(33, 5, "Invalid FTP URL: " << uri);
        safe_free(uri);
        return false; //earlyError(...)
    }
    request->http_ver = Http::ProtocolVersion();
    request->header.putStr(Http::HdrType::HOST, request->url.host());
    request->header.putTime(Http::HdrType::DATE, squid_curtime);
    request->flags.internalClient = true;
    request->client_addr.setNoAddr();
#if FOLLOW_X_FORWARDED_FOR
    request->indirect_client_addr.setNoAddr();
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr.setNoAddr();   /* undefined for internal requests */
    request->my_addr.port(0);
    request->downloader = this;

    ClientHttpRequest *const http = new ClientHttpRequest(NULL);
    http->request = request;
    HTTPMSGLOCK(http->request);
    http->req_sz = 0;
    http->uri = uri;

    context_ = new DownloaderContext(this, http);
    StoreIOBuffer tempBuffer;
    tempBuffer.data = context_->requestBuffer;
    tempBuffer.length = HTTP_REQBUF_SZ;

    ClientStreamData newServer = new clientReplyContext(http);
    ClientStreamData newClient = context_.getRaw();
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, newServer, downloaderRecipient,
                     downloaderDetach, newClient, tempBuffer);

    // Build a ClientRequestContext to start doCallouts
    http->calloutContext = new ClientRequestContext(http);

    // Do not check for redirect, tos,nfmark and sslBump
    http->calloutContext->redirect_done = true;
    http->calloutContext->tosToClientDone = true;
    http->calloutContext->nfmarkToClientDone = true;
    http->calloutContext->sslBumpCheckDone = true;
    http->al->ssl.bumpMode = Ssl::bumpEnd; // SslBump does not apply; log -

    http->doCallouts();
    return true;
}

void
Downloader::start()
{
    if (!buildRequest()) {
        status = Http::scInternalServerError;
        callBack();
    }
}

void
Downloader::handleReply(clientStreamNode * node, ClientHttpRequest *http, HttpReply *reply, StoreIOBuffer receivedData)
{
    // TODO: remove the following check:
    DownloaderContext::Pointer callerContext = dynamic_cast<DownloaderContext *>(node->data.getRaw());
    assert(callerContext == context_);

    bool existingContent = reply ? reply->content_length : 0;
    bool exceedSize = (existingContent > -1 && (size_t)existingContent > MaxObjectSize) || 
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
        http->out.size += receivedData.length;
        http->out.offset += receivedData.length;
    }

    switch (clientStreamStatus (node, http)) {
    case STREAM_NONE: {
        debugs(33, 3, HERE << "Get more data");
        StoreIOBuffer tempBuffer;
        tempBuffer.offset = http->out.offset;
        tempBuffer.data = context_->requestBuffer;
        tempBuffer.length = HTTP_REQBUF_SZ;
        clientStreamRead (node, http, tempBuffer);
    }
        break;
    case STREAM_COMPLETE:
        debugs(33, 3, HERE << "Object data transfer successfully complete");
        status = Http::scOkay;
        callBack();
        break;
    case STREAM_UNPLANNED_COMPLETE:
        debugs(33, 3, HERE << "Object data transfer failed: STREAM_UNPLANNED_COMPLETE");
        status = Http::scInternalServerError;
        callBack();
        break;
    case STREAM_FAILED:
        debugs(33, 3, HERE << "Object data transfer failed: STREAM_FAILED");
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
    context_->finished();
    context_ = NULL;
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


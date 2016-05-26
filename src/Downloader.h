#ifndef SQUID_DOWNLOADER_H
#define SQUID_DOWNLOADER_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "cbdata.h"
#include "defines.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"

class ClientHttpRequest;
class StoreIOBuffer;
class clientStreamNode;
class HttpReply;
class Downloader;

class DownloaderContext: public RefCountable
{
    CBDATA_CLASS(DownloaderContext);

public:
    typedef RefCount<DownloaderContext> Pointer;

    DownloaderContext(Downloader *dl, ClientHttpRequest *h):
        downloader(cbdataReference(dl)),
        http(cbdataReference(h))
        {}
    ~DownloaderContext();
    void finished();
    Downloader* downloader;
    ClientHttpRequest *http;
    char requestBuffer[HTTP_REQBUF_SZ];
};

class Downloader: virtual public AsyncJob
{
    CBDATA_CLASS(Downloader);
public:

    /// Callback data to use with Downloader callbacks.
    class CbDialer {
    public:
        CbDialer(): status(Http::scNone) {}
        virtual ~CbDialer() {}
        SBuf object;
        Http::StatusCode status;
    };

    Downloader(SBuf &url, AsyncCall::Pointer &aCallback, unsigned int level = 0);
    virtual ~Downloader();

    /// Fake call used internally by Downloader.
    void downloadFinished();

    /// The nested level of Downloader object (downloads inside downloads).
    unsigned int nestedLevel() const {return level_;}
    
    /* AsyncJob API */
    virtual bool doneAll() const;

    DownloaderContext::Pointer const &context() {return context_;};
    void handleReply(clientStreamNode * node, ClientHttpRequest *http, HttpReply *header, StoreIOBuffer receivedData);
protected:

    /* AsyncJob API */
    virtual void start();
    virtual void prepUserConnection() {};

private:

    bool buildRequest();

    /// Schedules for execution the "callback" with parameters the status
    /// and object.
    void callBack();

    /// The maximum allowed object size.
    static const size_t MaxObjectSize = 1*1024*1024;

    SBuf url_; ///< the url to download
    AsyncCall::Pointer callback; ///< callback to call when download finishes
    Http::StatusCode status; ///< the download status code
    SBuf object; ///< the object body data
    unsigned int level_; ///< holds the nested downloads level

    DownloaderContext::Pointer context_;
};

#endif

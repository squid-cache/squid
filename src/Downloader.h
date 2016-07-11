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
class DownloaderContext;
typedef RefCount<DownloaderContext> DownloaderContextPointer;

/// The Downloader class fetches SBuf-storable things for other Squid
/// components/transactions using internal requests. For example, it is used
/// to fetch missing intermediate certificates when validating origin server
/// certificate chains.
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

    void handleReply(clientStreamNode * node, ClientHttpRequest *http, HttpReply *header, StoreIOBuffer receivedData);
protected:

    /* AsyncJob API */
    virtual void start();

private:

    /// Initializes and starts the HTTP GET request to the remote server
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
    const unsigned int level_; ///< holds the nested downloads level

    /// Pointer to an object that stores the clientStream required info
    DownloaderContextPointer context_;
};

#endif

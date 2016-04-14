#ifndef SQUID_DOWNLOADER_H
#define SQUID_DOWNLOADER_H

#include "client_side.h"
#include "cbdata.h"

class Downloader: public ConnStateData
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

    Downloader(SBuf &url, const MasterXaction::Pointer &xact, AsyncCall::Pointer &aCallback, unsigned int level = 0);
    virtual ~Downloader();

    /// Fake call used internally by Downloader.
    void downloadFinished();

    /// The nested level of Downloader object (downloads inside downloads).
    unsigned int nestedLevel() const {return level_;}
    
    /* ConnStateData API */
    virtual bool isOpen() const;

    /* AsyncJob API */
    virtual bool doneAll() const;

    /*Bodypipe API*/
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

protected:
    /* ConnStateData API */
    virtual Http::Stream *parseOneRequest();
    virtual void processParsedRequest(Http::Stream *context);
    virtual time_t idleTimeout() const;
    virtual void writeControlMsgAndCall(HttpReply *rep, AsyncCall::Pointer &call);
    virtual void handleReply(HttpReply *header, StoreIOBuffer receivedData);

    /* AsyncJob API */
    virtual void start();
    virtual void prepUserConnection() {};

private:
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
};

#endif

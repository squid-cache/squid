#ifndef SQUID_DOWNLOADER_H
#define SQUID_DOWNLOADER_H

#include "client_side.h"
#include "cbdata.h"

class Downloader: public ConnStateData
{
    CBDATA_CLASS(Downloader);
    // XXX CBDATA_CLASS expands to nonvirtual toCbdata, AsyncJob::toCbdata
    //     is pure virtual. breaks build on clang if override is used

public:

    /// Callback data to use with Downloader callbacks;
    class CbDialer {
    public:
        CbDialer(): status(Http::scNone) {}
        virtual ~CbDialer() {}
        SBuf object;
        Http::StatusCode status;
    };

    explicit Downloader(SBuf &url, const MasterXaction::Pointer &xact, AsyncCall::Pointer &aCallback, unsigned int level = 0);
    virtual ~Downloader();

    /// Fake call used internally by Downloader.
    void downloadFinished();

    /// The nested level of Downloader object (downloads inside downloads)
    unsigned int nestedLevel() const {return level_;}
    
    /* ConnStateData API */
    virtual bool isOpen() const;

    /* AsyncJob API */
    virtual void callException(const std::exception &e);
    virtual bool doneAll() const;

    /*Bodypipe API*/
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

protected:
    /* ConnStateData API */
    virtual ClientSocketContext *parseOneRequest();
    virtual void processParsedRequest(ClientSocketContext *context);
    virtual time_t idleTimeout() const;
    virtual void writeControlMsgAndCall(HttpReply *rep, AsyncCall::Pointer &call);
    virtual void handleReply(HttpReply *header, StoreIOBuffer receivedData);

    /* AsyncJob API */
    virtual void start();

private:
    /// Schedules for execution the "callback" with parameters the status
    /// and object
    void callBack();

    static const size_t MaxObjectSize = 1*1024*1024; ///< The maximum allowed object size.

    SBuf url_; ///< The url to download
    AsyncCall::Pointer callback; ///< callback to call when download finishes
    Http::StatusCode status; ///< The download status code
    SBuf object; //object data
    unsigned int level_; ///< Holds the nested downloads level
};

#endif

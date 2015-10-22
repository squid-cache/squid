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
    class CbDialer {
    public:
        CbDialer(): status(Http::scNone) {}
        virtual ~CbDialer() {}
        SBuf object;
        Http::StatusCode status;
    };

    explicit Downloader(SBuf &url, const MasterXaction::Pointer &xact, AsyncCall::Pointer &aCallback);
    virtual ~Downloader();
    void downloadFinished();
    
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
    virtual void writeControlMsgAndCall(ClientSocketContext *context, HttpReply *rep, AsyncCall::Pointer &call);
    virtual void handleReply(HttpReply *header, StoreIOBuffer receivedData);

    /* AsyncJob API */
    virtual void start();

private:
    void callBack();
    SBuf url_;
    AsyncCall::Pointer callback;
    Http::StatusCode status;
    SBuf object; //object data
    size_t maxObjectSize;
};

#endif

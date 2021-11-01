/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DOWNLOADER_H
#define SQUID_DOWNLOADER_H

#include "base/AsyncJob.h"
#include "defines.h"
#include "http/forward.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"
#include "XactionInitiator.h"

class ClientHttpRequest;
class StoreIOBuffer;
class clientStreamNode;
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
    class CbDialer: public CallDialer {
    public:
        CbDialer(): status(Http::scNone) {}
        virtual ~CbDialer() {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) = 0;
        virtual void dial(AsyncCall &call) = 0;
        virtual void print(std::ostream &os) const;

        SBuf object;
        Http::StatusCode status;
    };

    Downloader(SBuf &url, AsyncCall::Pointer &aCallback, const XactionInitiator initiator, unsigned int level = 0);
    virtual ~Downloader();
    virtual void swanSong();

    /// delays destruction to protect doCallouts()
    void downloadFinished();

    /// The nested level of Downloader object (downloads inside downloads).
    unsigned int nestedLevel() const {return level_;}

    void handleReply(clientStreamNode *, ClientHttpRequest *, HttpReply *, StoreIOBuffer);

protected:

    /* AsyncJob API */
    virtual bool doneAll() const;
    virtual void start();

private:

    bool buildRequest();
    void callBack(Http::StatusCode const status);

    /// The maximum allowed object size.
    static const size_t MaxObjectSize = 1*1024*1024;

    SBuf url_; ///< the url to download
    AsyncCall::Pointer callback_; ///< callback to call when download finishes
    SBuf object_; ///< the object body data
    const unsigned int level_; ///< holds the nested downloads level
    /// The initiator of the download request.
    XactionInitiator initiator_;

    /// Pointer to an object that stores the clientStream required info
    DownloaderContextPointer context_;
};

#endif


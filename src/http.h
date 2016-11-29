/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_H
#define SQUID_HTTP_H

#include "clients/Client.h"
#include "comm.h"
#include "http/forward.h"
#include "http/StateFlags.h"
#include "sbuf/SBuf.h"

class FwdState;
class HttpHeader;

class HttpStateData : public Client
{
    CBDATA_CLASS(HttpStateData);

public:
    HttpStateData(FwdState *);
    ~HttpStateData();

    static void httpBuildRequestHeader(HttpRequest * request,
                                       StoreEntry * entry,
                                       const AccessLogEntryPointer &al,
                                       HttpHeader * hdr_out,
                                       const Http::StateFlags &flags);

    virtual const Comm::ConnectionPointer & dataConnection() const;
    /* should be private */
    bool sendRequest();
    void processReplyHeader();
    void processReplyBody();
    void readReply(const CommIoCbParams &io);
    virtual void maybeReadVirginBody(); // read response data from the network

    // Determine whether the response is a cacheable representation
    int cacheableReply();

    CachePeer *_peer;       /* CachePeer request made to */
    int eof;            /* reached end-of-object? */
    int lastChunk;      /* reached last chunk of a chunk-encoded reply */
    Http::StateFlags flags;
    size_t read_sz;
    SBuf inBuf;                ///< I/O buffer for receiving server responses
    bool ignoreCacheControl;
    bool surrogateNoStore;

    void processSurrogateControl(HttpReply *);

protected:
    void processReply();
    void proceedAfter1xx();
    void handle1xx(HttpReply *msg);

private:
    /**
     * The current server connection.
     * Maybe open, closed, or NULL.
     * Use doneWithServer() to check if the server is available for use.
     */
    Comm::ConnectionPointer serverConnection;
    AsyncCall::Pointer closeHandler;
    enum ConnectionStatus {
        INCOMPLETE_MSG,
        COMPLETE_PERSISTENT_MSG,
        COMPLETE_NONPERSISTENT_MSG
    };
    ConnectionStatus statusIfComplete() const;
    ConnectionStatus persistentConnStatus() const;
    void keepaliveAccounting(HttpReply *);
    void checkDateSkew(HttpReply *);

    bool continueAfterParsingHeader();
    void truncateVirginBody();

    virtual void start();
    virtual void haveParsedReplyHeaders();
    virtual bool getMoreRequestBody(MemBuf &buf);
    virtual void closeServer(); // end communication with the server
    virtual bool doneWithServer() const; // did we end communication?
    virtual void abortAll(const char *reason); // abnormal termination
    virtual bool mayReadVirginReplyBody() const;

    void abortTransaction(const char *reason) { abortAll(reason); } // abnormal termination

    /**
     * determine if read buffer can have space made available
     * for a read.
     *
     * \param grow  whether to actually expand the buffer
     *
     * \return whether the buffer can be grown to provide space
     *         regardless of whether the grow actually happened.
     */
    bool maybeMakeSpaceAvailable(bool grow);

    // consuming request body
    virtual void handleMoreRequestBodyAvailable();
    virtual void handleRequestBodyProducerAborted();

    void writeReplyBody();
    bool decodeAndWriteReplyBody();
    bool finishingBrokenPost();
    bool finishingChunkedRequest();
    void doneSendingRequestBody();
    void requestBodyHandler(MemBuf &);
    virtual void sentRequestBody(const CommIoCbParams &io);
    void wroteLast(const CommIoCbParams &io);
    void sendComplete();
    void httpStateConnClosed(const CommCloseCbParams &params);
    void httpTimeout(const CommTimeoutCbParams &params);

    mb_size_t buildRequestPrefix(MemBuf * mb);
    static bool decideIfWeDoRanges (HttpRequest * orig_request);
    bool peerSupportsConnectionPinning() const;

    /// Parser being used at present to parse the HTTP/ICY server response.
    Http1::ResponseParserPointer hp;
    Http1::TeChunkedParser *httpChunkDecoder;

    /// amount of message payload/body received so far.
    int64_t payloadSeen;
    /// positive when we read more than we wanted
    int64_t payloadTruncated;

    /// Whether we received a Date header older than that of a matching
    /// cached response.
    bool sawDateGoBack;
};

int httpCachable(const HttpRequestMethod&);
void httpStart(FwdState *);
SBuf httpMakeVaryMark(HttpRequest * request, HttpReply const * reply);

#endif /* SQUID_HTTP_H */


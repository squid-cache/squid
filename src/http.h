/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_H
#define SQUID_SRC_HTTP_H

#include "clients/Client.h"
#include "comm.h"
#include "http/forward.h"
#include "http/StateFlags.h"
#include "sbuf/SBuf.h"

#include <optional>

class FwdState;
class HttpHeader;
class String;

class HttpStateData : public Client
{
    CBDATA_CHILD(HttpStateData);

public:

    /// assists in making and relaying entry caching/sharing decision
    class ReuseDecision
    {
    public:
        enum Answers { reuseNot = 0, cachePositively, cacheNegatively, doNotCacheButShare };

        ReuseDecision(const StoreEntry *e, const Http::StatusCode code);
        /// stores the corresponding decision
        Answers make(const Answers ans, const char *why);

        Answers answer; ///< the decision id
        const char *reason; ///< the decision reason
        const StoreEntry *entry; ///< entry for debugging
        const Http::StatusCode statusCode; ///< HTTP status for debugging
    };

    HttpStateData(FwdState *);
    ~HttpStateData() override;

    static void httpBuildRequestHeader(HttpRequest * request,
                                       StoreEntry * entry,
                                       const AccessLogEntryPointer &al,
                                       HttpHeader * hdr_out,
                                       const Http::StateFlags &flags);

    const Comm::ConnectionPointer & dataConnection() const override;
    /* should be private */
    bool sendRequest();
    void processReplyHeader();
    void processReplyBody() override;
    void readReply(const CommIoCbParams &io);
    void maybeReadVirginBody() override; // read response data from the network

    // Checks whether the response is cacheable/shareable.
    ReuseDecision::Answers reusableReply(ReuseDecision &decision);

    CachePeer *_peer = nullptr;       /* CachePeer request made to */
    int eof = 0;            /* reached end-of-object? */
    int lastChunk = 0;      /* reached last chunk of a chunk-encoded reply */
    Http::StateFlags flags;
    SBuf inBuf;                ///< I/O buffer for receiving server responses
    bool ignoreCacheControl = false;
    bool surrogateNoStore = false;

    /// Upgrade header value sent to the origin server or cache peer.
    String *upgradeHeaderOut = nullptr;

    void processSurrogateControl(HttpReply *);

protected:
    /* Client API */
    void noteDelayAwareReadChance() override;

    void processReply();
    void proceedAfter1xx();
    void handle1xx(HttpReply *msg);
    void drop1xx(const char *reason);

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

    void start() override;
    void haveParsedReplyHeaders() override;
    bool getMoreRequestBody(MemBuf &buf) override;
    void closeServer() override; // end communication with the server
    bool doneWithServer() const override; // did we end communication?
    void abortAll(const char *reason) override; // abnormal termination
    bool mayReadVirginReplyBody() const override;

    void abortTransaction(const char *reason) { abortAll(reason); } // abnormal termination

    size_t calcReadBufferCapacityLimit() const;
    std::optional<size_t> canBufferMoreReplyBytes() const;
    size_t maybeMakeSpaceAvailable(size_t maxReadSize);

    // consuming request body
    virtual void handleMoreRequestBodyAvailable();
    void handleRequestBodyProducerAborted() override;

    void writeReplyBody();
    bool decodeAndWriteReplyBody();
    bool finishingBrokenPost();
    bool finishingChunkedRequest();
    void doneSendingRequestBody() override;
    void requestBodyHandler(MemBuf &);
    void sentRequestBody(const CommIoCbParams &io) override;
    void wroteLast(const CommIoCbParams &io);
    void sendComplete();
    void httpStateConnClosed(const CommCloseCbParams &params);
    void httpTimeout(const CommTimeoutCbParams &params);
    void markPrematureReplyBodyEofFailure();

    mb_size_t buildRequestPrefix(MemBuf * mb);
    void forwardUpgrade(HttpHeader&);
    static bool decideIfWeDoRanges (HttpRequest * orig_request);
    bool peerSupportsConnectionPinning() const;
    const char *blockSwitchingProtocols(const HttpReply&) const;

    /// Parser being used at present to parse the HTTP/ICY server response.
    Http1::ResponseParserPointer hp;
    Http1::TeChunkedParser *httpChunkDecoder = nullptr;

    /// amount of message payload/body received so far.
    int64_t payloadSeen = 0;
    /// positive when we read more than we wanted
    int64_t payloadTruncated = 0;

    /// Whether we received a Date header older than that of a matching
    /// cached response.
    bool sawDateGoBack = false;
};

std::ostream &operator <<(std::ostream &os, const HttpStateData::ReuseDecision &d);

int httpCachable(const HttpRequestMethod&);
void httpStart(FwdState *);
SBuf httpMakeVaryMark(HttpRequest * request, HttpReply const * reply);

#endif /* SQUID_SRC_HTTP_H */


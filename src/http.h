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
#include "HttpStateFlags.h"

class ChunkedCodingParser;
class FwdState;
class HttpHeader;

class HttpStateData : public Client
{

public:
    HttpStateData(FwdState *);
    ~HttpStateData();

    static void httpBuildRequestHeader(HttpRequest * request,
                                       StoreEntry * entry,
                                       const AccessLogEntryPointer &al,
                                       HttpHeader * hdr_out,
                                       const HttpStateFlags &flags);

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
    HttpStateFlags flags;
    size_t read_sz;
    int header_bytes_read;  // to find end of response,
    int64_t reply_bytes_read;   // without relying on StoreEntry
    int body_bytes_truncated; // positive when we read more than we wanted
    MemBuf *readBuf;
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

    // consuming request body
    virtual void handleMoreRequestBodyAvailable();
    virtual void handleRequestBodyProducerAborted();

    void abortTransaction(const char *reason) { abortAll(reason); } // abnormal termination
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

    ChunkedCodingParser *httpChunkDecoder;
private:
    CBDATA_CLASS2(HttpStateData);
};

int httpCachable(const HttpRequestMethod&);
void httpStart(FwdState *);
const char *httpMakeVaryMark(HttpRequest * request, HttpReply const * reply);

#endif /* SQUID_HTTP_H */


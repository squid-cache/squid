/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_CLIENT_H
#define SQUID_SRC_CLIENTS_CLIENT_H

#include "base/AsyncJob.h"
#include "BodyPipe.h"
#include "CommCalls.h"
#include "FwdState.h"
#include "http/forward.h"
#include "StoreIOBuffer.h"
#if USE_ADAPTATION
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"
#endif

/**
 * Client is a common base for classes such as HttpStateData and FtpStateData.
 * All such classes must be able to consume request bodies from a BodyPipe
 * or ICAP producer, adapt virgin responses using ICAP, and provide a
 * consumer with responses.
 */
class Client:
#if USE_ADAPTATION
    public Adaptation::Initiator,
    public BodyProducer,
#endif
    public BodyConsumer
{

public:
    Client(FwdState *);
    ~Client() override;

    /// \return primary or "request data connection"
    virtual const Comm::ConnectionPointer & dataConnection() const = 0;

    // BodyConsumer: consume request body or adapted response body.
    // The implementation just calls the corresponding HTTP or ICAP handle*()
    // method, depending on the pipe.
    void noteMoreBodyDataAvailable(BodyPipe::Pointer) override;
    void noteBodyProductionEnded(BodyPipe::Pointer) override;
    void noteBodyProducerAborted(BodyPipe::Pointer) override;

    /// read response data from the network
    virtual void maybeReadVirginBody() = 0;

    /// abnormal transaction termination; reason is for debugging only
    virtual void abortAll(const char *reason) = 0;

    /// abnormal data transfer termination
    /// \retval true the transaction will be terminated (abortAll called)
    /// \retval false the transaction will survive
    virtual bool abortOnData(const char *reason);

    /// a hack to reach HttpStateData::orignal_request
    virtual HttpRequestPointer originalRequest();

#if USE_ADAPTATION
    // Adaptation::Initiator API: start an ICAP transaction and receive adapted headers.
    void noteAdaptationAnswer(const Adaptation::Answer &answer) override;
    void noteAdaptationAclCheckDone(Adaptation::ServiceGroupPointer group) override;

    // BodyProducer: provide virgin response body to ICAP.
    void noteMoreBodySpaceAvailable(BodyPipe::Pointer ) override;
    void noteBodyConsumerAborted(BodyPipe::Pointer ) override;
#endif
    virtual bool getMoreRequestBody(MemBuf &buf);
    virtual void processReplyBody() = 0;

//AsyncJob virtual methods
    void swanSong() override;
    bool doneAll() const override;

public: // should be protected
    void serverComplete();     /**< call when no server communication is expected */

    /// remember that the received virgin reply was parsed in its entirety,
    /// including its body (if any)
    void markParsedVirginReplyAsWhole(const char *reasonWeAreSure);

private:
    void serverComplete2();    /**< Continuation of serverComplete */
    bool completed = false;            /**< serverComplete() has been called */

protected:
    // kids customize these
    virtual void haveParsedReplyHeaders(); /**< called when got final headers */
    virtual void completeForwarding(); /**< default calls fwd->complete() */

    // BodyConsumer for HTTP: consume request body.
    bool startRequestBodyFlow();
    void handleMoreRequestBodyAvailable();
    void handleRequestBodyProductionEnded();
    virtual void handleRequestBodyProducerAborted() = 0;

    // sending of the request body to the server
    void sendMoreRequestBody();
    // has body; kids overwrite to increment I/O stats counters
    virtual void sentRequestBody(const CommIoCbParams &io) = 0;
    virtual void doneSendingRequestBody() = 0;

    /// Use this to end communication with the server. The call cancels our
    /// closure handler and tells FwdState to forget about the connection.
    virtual void closeServer() = 0;
    virtual bool doneWithServer() const = 0;   /**< did we end communication? */
    /// whether we may receive more virgin response body bytes
    virtual bool mayReadVirginReplyBody() const = 0;

    /// Called when a previously delayed dataConnection() read may be possible.
    /// \sa delayRead()
    virtual void noteDelayAwareReadChance() = 0;

    /// Entry-dependent callbacks use this check to quit if the entry went bad
    bool abortOnBadEntry(const char *abortReason);

    bool blockCaching();

#if USE_ADAPTATION
    void startAdaptation(const Adaptation::ServiceGroupPointer &group, HttpRequest *cause);
    void adaptVirginReplyBody(const char *buf, ssize_t len);
    void cleanAdaptation();
    virtual bool doneWithAdaptation() const;   /**< did we end ICAP communication? */

    // BodyConsumer for ICAP: consume adapted response body.
    void handleMoreAdaptedBodyAvailable();
    void handleAdaptedBodyProductionEnded();
    void handleAdaptedBodyProducerAborted();

    void handleAdaptedHeader(Http::Message *msg);
    void handleAdaptationCompleted();
    void handleAdaptationBlocked(const Adaptation::Answer &answer);
    void handleAdaptationAborted(bool bypassable = false);
    bool handledEarlyAdaptationAbort();

    /// called by StoreEntry when it has more buffer space available
    void resumeBodyStorage();
    /// called when the entire adapted response body is consumed
    void endAdaptedBodyConsumption();
#endif

protected:
    const HttpReply *virginReply() const;
    HttpReply *virginReply();
    HttpReply *setVirginReply(HttpReply *r);

    HttpReply *finalReply();
    HttpReply *setFinalReply(HttpReply *r);

    // Kids use these to stuff data into the response instead of messing with the entry directly
    void adaptOrFinalizeReply();
    void addVirginReplyBody(const char *buf, ssize_t len);
    void storeReplyBody(const char *buf, ssize_t len);
    /// \deprecated use SBuf I/O API and calcBufferSpaceToReserve() instead
    size_t replyBodySpace(const MemBuf &readBuf, const size_t minSpace) const;
    /// determine how much space the buffer needs to reserve
    size_t calcBufferSpaceToReserve(const size_t space, const size_t wantSpace) const;

    void adjustBodyBytesRead(const int64_t delta);

    /// Defer reading until it is likely to become possible.
    /// Eventually, noteDelayAwareReadChance() will be called.
    void delayRead();

    // These should be private
    int64_t currentOffset = 0;  /**< Our current offset in the StoreEntry */
    MemBuf *responseBodyBuffer = nullptr; /**< Data temporarily buffered for ICAP */

public: // should not be
    StoreEntry *entry = nullptr;
    FwdState::Pointer fwd;
    HttpRequestPointer request;

protected:
    BodyPipe::Pointer requestBodySource;  /**< to consume request body */
    AsyncCall::Pointer requestSender;     /**< set if we are expecting Comm::Write to call us back */

#if USE_ADAPTATION
    BodyPipe::Pointer virginBodyDestination;  /**< to provide virgin response body */
    CbcPointer<Adaptation::Initiate> adaptedHeadSource;  /**< to get adapted response headers */
    BodyPipe::Pointer adaptedBodySource;      /**< to consume adated response body */

    bool adaptationAccessCheckPending = false;
    bool startedAdaptation = false;

    /// handleAdaptedBodyProductionEnded() was called
    bool receivedWholeAdaptedReply = false;
#endif
    bool receivedWholeRequestBody = false; ///< handleRequestBodyProductionEnded called

    /// whether we should not be talking to FwdState; XXX: clear fwd instead
    /// points to a string literal which is used only for debugging
    const char *doneWithFwd = nullptr;

private:
    void sendBodyIsTooLargeError();
    void maybePurgeOthers();

    HttpReply *theVirginReply = nullptr;       /**< reply received from the origin server */
    HttpReply *theFinalReply = nullptr;        /**< adapted reply from ICAP or virgin reply */
};

#endif /* SQUID_SRC_CLIENTS_CLIENT_H */


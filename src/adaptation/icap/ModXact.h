/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPMODXACT_H
#define SQUID_ICAPMODXACT_H

#include "AccessLogEntry.h"
#include "adaptation/icap/InOut.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Xaction.h"
#include "BodyPipe.h"
#include "http/one/forward.h"
#include "http/one/TeChunkedParser.h"

/*
 * ICAPModXact implements ICAP REQMOD and RESPMOD transaction using
 * ICAPXaction as the base. The ICAPModXact receives a virgin HTTP message
 * from an ICAP vecoring point, (a.k.a., initiator), communicates with the
 * ICAP server, and sends the adapted HTTP message headers back.
 * Virgin/adapted HTTP message body is reveived/sent using BodyPipe
 * interface. The initiator (or its associate) is expected to send and/or
 * receive the HTTP body.
 */

namespace Adaptation
{
namespace Icap
{

// estimated future presence and size of something (e.g., HTTP body)

class SizedEstimate
{

public:
    SizedEstimate(); // not expected by default
    void expect(int64_t aSize); // expect with any, even unknown size
    bool expected() const;

    /* other members can be accessed iff expected() */

    bool knownSize() const;
    uint64_t size() const; // can be accessed iff knownSize()

private:
    enum { dtUnexpected = -2, dtUnknown = -1 };
    int64_t theData; // combines expectation and size info to save RAM
};

// Virgin body may be used for two activities: (a) writing preview or prime
// body to the ICAP server and (b) sending the body back in the echo mode.
// Both activities use the same BodyPipe and may be active at the same time.
// This class is used to maintain the state of body writing or sending
// activity and to coordinate consumption of the shared virgin body buffer.
class VirginBodyAct
{

public:
    VirginBodyAct();

    void plan(); // the activity may happen; do not consume at or above offset
    void disable(); // the activity will not continue; no consumption restrictions

    bool active() const { return theState == stActive; }
    bool disabled() const { return theState == stDisabled; }

    // methods below require active()

    uint64_t offset() const; // the absolute beginning of not-yet-acted-on data
    void progress(size_t size); // note processed body bytes

private:
    int64_t theStart; // unprocessed virgin body data offset

    typedef enum { stUndecided, stActive, stDisabled } State;
    State theState;
};

// maintains preview-related sizes

class Preview
{

public:
    Preview();            // disabled
    void enable(size_t anAd); // enabled with advertised size
    bool enabled() const;

    /* other members can be accessed iff enabled() */

    size_t ad() const;      // advertised preview size
    size_t debt() const;    // remains to write
    bool done() const;      // wrote everything
    bool ieof() const;      // premature EOF

    void wrote(size_t size, bool wroteEof);

private:
    size_t theWritten;
    size_t theAd;
    enum State { stDisabled, stWriting, stIeof, stDone } theState;
};

/// Parses and stores ICAP trailer header block.
class TrailerParser
{
public:
    TrailerParser() : trailer(hoReply), hdr_sz(0) {}
    /// Parses trailers stored in a buffer.
    /// \returns true and sets hdr_sz on success
    /// \returns false and sets *error to zero when needs more data
    /// \returns false and sets *error to a positive Http::StatusCode on error
    bool parse(const char *buf, int len, int atEnd, Http::StatusCode *error);
    HttpHeader trailer;
    /// parsed trailer size if parse() was successful
    size_t hdr_sz; // pedantic XXX: wrong type dictated by HttpHeader::parse() API
};

/// handles ICAP-specific chunk extensions supported by Squid
class ChunkExtensionValueParser: public Http1::ChunkExtensionValueParser
{
public:
    /* Http1::ChunkExtensionValueParser API */
    virtual void parse(Tokenizer &tok, const SBuf &extName) override;

    bool sawUseOriginalBody() const { return useOriginalBody_ >= 0; }
    uint64_t useOriginalBody() const { assert(sawUseOriginalBody()); return static_cast<uint64_t>(useOriginalBody_); }

private:
    static const SBuf UseOriginalBodyName;

    /// the value of the parsed use-original-body chunk extension (or -1)
    int64_t useOriginalBody_ = -1;
};

class ModXact: public Xaction, public BodyProducer, public BodyConsumer
{
    CBDATA_CLASS(ModXact);

public:
    ModXact(Http::Message *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp, ServiceRep::Pointer &s);
    virtual ~ModXact();

    // BodyProducer methods
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

    // BodyConsumer methods
    virtual void noteMoreBodyDataAvailable(BodyPipe::Pointer);
    virtual void noteBodyProductionEnded(BodyPipe::Pointer);
    virtual void noteBodyProducerAborted(BodyPipe::Pointer);

    // comm handlers
    virtual void handleCommConnected();
    virtual void handleCommWrote(size_t size);
    virtual void handleCommRead(size_t size);
    void handleCommWroteHeaders();
    void handleCommWroteBody();

    // service waiting
    void noteServiceReady();
    void noteServiceAvailable();

public:
    InOut virgin;
    InOut adapted;

    // bypasses exceptions if needed and possible
    virtual void callException(const std::exception &e);

    /// record error detail in the virgin request if possible
    virtual void detailError(int errDetail);
    // Icap::Xaction API
    virtual void clearError();
    /// The master transaction log entry
    virtual AccessLogEntry::Pointer masterLogEntry() { return alMaster; }

private:
    virtual void start();

    /// locates the request, either as a cause or as a virgin message itself
    const HttpRequest &virginRequest() const; // Must always be available

    void estimateVirginBody();
    void makeAdaptedBodyPipe(const char *what);

    void waitForService();

    // will not send anything [else] on the adapted pipe
    bool doneSending() const;

    void startWriting();
    void writeMore();
    void writePreviewBody();
    void writePrimeBody();
    void writeSomeBody(const char *label, size_t size);
    void decideWritingAfterPreview(const char *previewKind);

    void startReading();
    void readMore();
    virtual bool doneReading() const { return commEof || state.doneParsing(); }
    virtual bool doneWriting() const { return state.doneWriting(); }

    size_t virginContentSize(const VirginBodyAct &act) const;
    const char *virginContentData(const VirginBodyAct &act) const;
    bool virginBodyEndReached(const VirginBodyAct &act) const;

    void makeRequestHeaders(MemBuf &buf);
    void makeAllowHeader(MemBuf &buf);
    void makeUsernameHeader(const HttpRequest *request, MemBuf &buf);
    void addLastRequestChunk(MemBuf &buf);
    void openChunk(MemBuf &buf, size_t chunkSize, bool ieof);
    void closeChunk(MemBuf &buf);
    void virginConsume();
    void finishNullOrEmptyBodyPreview(MemBuf &buf);

    void decideOnPreview();
    void decideOnRetries();
    bool shouldAllow204();
    bool shouldAllow206any();
    bool shouldAllow206in();
    bool shouldAllow206out();
    bool canBackupEverything() const;

    void prepBackup(size_t expectedSize);
    void backup(const MemBuf &buf);

    void parseMore();

    void parseHeaders();
    void parseIcapHead();
    void parseHttpHead();
    bool parseHead(Http::Message *head);

    void decideOnParsingBody();
    void parseBody();
    void parseIcapTrailer();
    void maybeAllocateHttpMsg();

    void handle100Continue();
    bool validate200Ok();
    void handle200Ok();
    void handle204NoContent();
    void handle206PartialContent();
    void handleUnknownScode();

    void bypassFailure();

    void startSending();
    void disableBypass(const char *reason, bool includeGroupBypass);

    void prepEchoing();
    void prepPartialBodyEchoing(uint64_t pos);
    void echoMore();
    void updateSources(); ///< Update the Http::Message sources

    virtual bool doneAll() const;
    virtual void swanSong();

    void stopReceiving();
    void stopSending(bool nicely);
    void stopWriting(bool nicely);
    void stopParsing(const bool checkUnparsedData = true);
    void stopBackup();

    virtual void fillPendingStatus(MemBuf &buf) const;
    virtual void fillDoneStatus(MemBuf &buf) const;
    virtual bool fillVirginHttpHeader(MemBuf&) const;

private:
    /// parses a message header or trailer
    /// \returns true on success
    /// \returns false if more data is needed
    /// \throw TextException on unrecoverable error
    template<class Part>
    bool parsePart(Part *part, const char *description);

    void packHead(MemBuf &httpBuf, const Http::Message *head);
    void encapsulateHead(MemBuf &icapBuf, const char *section, MemBuf &httpBuf, const Http::Message *head);
    bool gotEncapsulated(const char *section) const;
    /// whether ICAP response header indicates HTTP header presence
    bool expectHttpHeader() const;
    /// whether ICAP response header indicates HTTP body presence
    bool expectHttpBody() const;
    /// whether ICAP response header indicates ICAP trailers presence
    bool expectIcapTrailers() const;
    void checkConsuming();

    virtual void finalizeLogInfo();

    SizedEstimate virginBody;
    VirginBodyAct virginBodyWriting; // virgin body writing state
    VirginBodyAct virginBodySending;  // virgin body sending state
    uint64_t virginConsumed;        // virgin data consumed so far
    Preview preview; // use for creating (writing) the preview

    Http1::TeChunkedParser *bodyParser; // ICAP response body parser

    bool canStartBypass; // enables bypass of transaction failures
    bool protectGroupBypass; // protects ServiceGroup-wide bypass of failures

    /**
     * size of HTTP header in ICAP reply or -1 if there is not any encapsulated
     * message data
     */
    int64_t replyHttpHeaderSize;
    /**
     * size of dechunked HTTP body in ICAP reply or -1 if there is not any
     * encapsulated message data
     */
    int64_t replyHttpBodySize;

    int adaptHistoryId; ///< adaptation history slot reservation

    TrailerParser *trailerParser;

    ChunkExtensionValueParser extensionParser;

    class State
    {

    public:
        State();

    public:

        bool serviceWaiting; // waiting for ICAP service options
        bool allowedPostview204; // mmust handle 204 No Content outside preview
        bool allowedPostview206; // must handle 206 Partial Content outside preview
        bool allowedPreview206; // must handle 206 Partial Content inside preview
        bool readyForUob; ///< got a 206 response and expect a use-origin-body
        bool waitedForService; ///< true if was queued at least once

        // will not write anything [else] to the ICAP server connection
        bool doneWriting() const { return writing == writingReallyDone; }

        // will not use virgin.body_pipe
        bool doneConsumingVirgin() const {
            return writing >= writingAlmostDone
                   && ((sending == sendingAdapted && !readyForUob) ||
                       sending == sendingDone);
        }

        // parsed entire ICAP response from the ICAP server
        bool doneParsing() const { return parsing == psDone; }

        // is parsing ICAP or HTTP headers read from the ICAP server
        bool parsingHeaders() const {
            return parsing == psIcapHeader ||
                   parsing == psHttpHeader;
        }

        enum Parsing { psIcapHeader, psHttpHeader, psBody, psIcapTrailer, psDone } parsing;

        // measures ICAP request writing progress
        enum Writing { writingInit, writingConnect, writingHeaders,
                       writingPreview, writingPaused, writingPrime,
                       writingAlmostDone, // waiting for the last write() call to finish
                       writingReallyDone
                     } writing;

        enum Sending { sendingUndecided, sendingVirgin, sendingAdapted,
                       sendingDone
                     } sending;
    } state;

    AccessLogEntry::Pointer alMaster; ///< Master transaction AccessLogEntry
};

// An Launcher that stores ModXact construction info and
// creates ModXact when needed
class ModXactLauncher: public Launcher
{
    CBDATA_CLASS(ModXactLauncher);

public:
    ModXactLauncher(Http::Message *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp, Adaptation::ServicePointer s);

protected:
    virtual Xaction *createXaction();

    virtual void swanSong();

    /// starts or stops transaction accounting in ICAP history
    void updateHistory(bool start);

    InOut virgin;

    AccessLogEntry::Pointer al;
};

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPMOD_XACT_H */



/*
 * $Id$
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_ICAPMODXACT_H
#define SQUID_ICAPMODXACT_H

#include "BodyPipe.h"
#include "adaptation/icap/Xaction.h"
#include "adaptation/icap/InOut.h"
#include "adaptation/icap/Launcher.h"

/*
 * ICAPModXact implements ICAP REQMOD and RESPMOD transaction using
 * ICAPXaction as the base. The ICAPModXact receives a virgin HTTP message
 * from an ICAP vecoring point, (a.k.a., initiator), communicates with the
 * ICAP server, and sends the adapted HTTP message headers back.
 * Virgin/adapted HTTP message body is reveived/sent using BodyPipe
 * interface. The initiator (or its associate) is expected to send and/or
 * receive the HTTP body.
 */


class ChunkedCodingParser;

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
    void disable(); // the activity wont continue; no consumption restrictions

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

class ModXact: public Xaction, public BodyProducer, public BodyConsumer
{

public:
    ModXact(HttpMsg *virginHeader, HttpRequest *virginCause, ServiceRep::Pointer &s);
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

public:
    InOut virgin;
    InOut adapted;

    // bypasses exceptions if needed and possible
    virtual void callException(const std::exception &e);

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
    void makeUsernameHeader(const HttpRequest *request, MemBuf &buf);
    void addLastRequestChunk(MemBuf &buf);
    void openChunk(MemBuf &buf, size_t chunkSize, bool ieof);
    void closeChunk(MemBuf &buf);
    void virginConsume();
    void finishNullOrEmptyBodyPreview(MemBuf &buf);

    void decideOnPreview();
    void decideOnRetries();
    bool shouldAllow204();
    bool canBackupEverything() const;

    void prepBackup(size_t expectedSize);
    void backup(const MemBuf &buf);

    void parseMore();

    void parseHeaders();
    void parseIcapHead();
    void parseHttpHead();
    bool parseHead(HttpMsg *head);

    void decideOnParsingBody();
    void parseBody();
    void maybeAllocateHttpMsg();

    void handle100Continue();
    bool validate200Ok();
    void handle200Ok();
    void handle204NoContent();
    void handleUnknownScode();

    void bypassFailure();

    void startSending();
    void disableBypass(const char *reason, bool includeGroupBypass);

    void prepEchoing();
    void echoMore();

    virtual bool doneAll() const;
    virtual void swanSong();

    void stopReceiving();
    void stopSending(bool nicely);
    void stopWriting(bool nicely);
    void stopParsing();
    void stopBackup();

    virtual void fillPendingStatus(MemBuf &buf) const;
    virtual void fillDoneStatus(MemBuf &buf) const;
    virtual bool fillVirginHttpHeader(MemBuf&) const;

private:
    void packHead(MemBuf &httpBuf, const HttpMsg *head);
    void encapsulateHead(MemBuf &icapBuf, const char *section, MemBuf &httpBuf, const HttpMsg *head);
    bool gotEncapsulated(const char *section) const;
    void checkConsuming();

    virtual void finalizeLogInfo();

    SizedEstimate virginBody;
    VirginBodyAct virginBodyWriting; // virgin body writing state
    VirginBodyAct virginBodySending;  // virgin body sending state
    uint64_t virginConsumed;        // virgin data consumed so far
    Preview preview; // use for creating (writing) the preview

    ChunkedCodingParser *bodyParser; // ICAP response body parser

    bool canStartBypass; // enables bypass of transaction failures
    bool protectGroupBypass; // protects ServiceGroup-wide bypass of failures

    uint64_t replyBodySize; ///< dechunked ICAP reply body size

    int adaptHistoryId; ///< adaptation history slot reservation

    class State
    {

    public:
        State();

    public:

        bool serviceWaiting; // waiting for ICAP service options
        bool allowedPostview204; // mmust handle 204 No Content outside preview

        // will not write anything [else] to the ICAP server connection
        bool doneWriting() const { return writing == writingReallyDone; }

        // will not use virgin.body_pipe
        bool doneConsumingVirgin() const {
            return writing >= writingAlmostDone
                   && (sending == sendingAdapted || sending == sendingDone);
        }

        // parsed entire ICAP response from the ICAP server
        bool doneParsing() const { return parsing == psDone; }

        // is parsing ICAP or HTTP headers read from the ICAP server
        bool parsingHeaders() const {
            return parsing == psIcapHeader ||
                   parsing == psHttpHeader;
        }

        enum Parsing { psIcapHeader, psHttpHeader, psBody, psDone } parsing;

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

    CBDATA_CLASS2(ModXact);
};

// An Launcher that stores ModXact construction info and
// creates ModXact when needed
class ModXactLauncher: public Launcher
{
public:
    ModXactLauncher(HttpMsg *virginHeader, HttpRequest *virginCause, Adaptation::ServicePointer s);

protected:
    virtual Xaction *createXaction();

    virtual void swanSong();

    /// starts or stops transaction accounting in ICAP history
    void updateHistory(bool start);

    InOut virgin;

private:
    CBDATA_CLASS2(ModXactLauncher);
};


} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPMOD_XACT_H */

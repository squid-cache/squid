
/*
 * $Id: ICAPModXact.h,v 1.6 2006/10/31 23:30:58 wessels Exp $
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

#include "ICAPXaction.h"
#include "MsgPipe.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"

/* ICAPModXact implements ICAP REQMOD and RESPMOD transaction using ICAPXaction
 * as the base. It implements message pipe sink and source interfaces for
 * communication with various HTTP "anchors" and "hooks".  ICAPModXact receives
 * virgin HTTP messages, communicates with the ICAP server, and sends the
 * adapted messages back. ICAPClient is the "owner" of the ICAPModXact. */

class ChunkedCodingParser;

// estimated future presence and size of something (e.g., HTTP body)

class SizedEstimate
{

public:
    SizedEstimate(); // not expected by default
    void expect(ssize_t aSize); // expect with any, even unknown size
    bool expected() const;

    /* other members can be accessed iff expected() */

    bool knownSize() const;
    size_t size() const; // can be accessed iff knownSize()

private:
    enum { dtUnexpected = -2, dtUnknown = -1 };
    ssize_t theData; // combines expectation and size info to save RAM
};

// Protects buffer area. If area size is unknown, protects buffer suffix.
// Only "released" data can be consumed by the caller. Used to maintain
// write, preview, and 204 promises for ICAPModXact virgin->data-body buffer.

class MemBufClaim
{

public:
    MemBufClaim();

    void protectAll();
    void protectUpTo(size_t aGoal);
    void disable();
    bool active() const { return theStart >= 0; }

    // methods below require active()

    void release(size_t size); // stop protecting size more bytes
    size_t offset() const;     // protected area start
    bool limited() const;      // protects up to a known size goal

private:
    ssize_t theStart; // left area border
    ssize_t theGoal;  // "end" maximum, if any
};

// maintains preview-related sizes

class ICAPPreview
{

public:
    ICAPPreview();            // disabled
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

class ICAPModXact: public ICAPXaction, public MsgPipeSource, public MsgPipeSink
{

public:
    typedef RefCount<ICAPModXact> Pointer;

public:
    ICAPModXact();

    // called by ICAPClient
    void init(ICAPServiceRep::Pointer&, MsgPipe::Pointer &aVirgin, MsgPipe::Pointer &anAdapted, Pointer &aSelf);

    // pipe source methods; called by Anchor while receiving the adapted msg
    virtual void noteSinkNeed(MsgPipe *p);
    virtual void noteSinkAbort(MsgPipe *p);

    // pipe sink methods; called by ICAP while sending the virgin message
    virtual void noteSourceStart(MsgPipe *p);
    virtual void noteSourceProgress(MsgPipe *p);
    virtual void noteSourceFinish(MsgPipe *p);
    virtual void noteSourceAbort(MsgPipe *p);

    // comm handlers
    virtual void handleCommConnected();
    virtual void handleCommWrote(size_t size);
    virtual void handleCommRead(size_t size);
    void handleCommWroteHeaders();
    void handleCommWroteBody();

    // service waiting
    void noteServiceReady();

private:
    void estimateVirginBody();

    void waitForService();

    // will not send anything [else] on the adapted pipe
    bool doneSending() const;

    void startWriting();
    void writeMore();
    void writePriviewBody();
    void writePrimeBody();
    void writeSomeBody(const char *label, size_t size);

    void startReading();
    void readMore();
    virtual bool doneReading() const { return commEof || state.doneParsing(); }
    virtual bool doneWriting() const { return state.doneWriting(); }

    size_t claimSize(const MemBufClaim &claim) const;
    const char *claimContent(const MemBufClaim &claim) const;
    void makeRequestHeaders(MemBuf &buf);
    void moveRequestChunk(MemBuf &buf, size_t chunkSize);
    void addLastRequestChunk(MemBuf &buf);
    void openChunk(MemBuf &buf, size_t chunkSize, bool ieof);
    void closeChunk(MemBuf &buf);
    void virginConsume();

    bool shouldPreview(const String &urlPath);
    bool shouldAllow204();
    void prepBackup(size_t expectedSize);
    void backup(const MemBuf &buf);

    void parseMore();

    void parseHeaders();
    void parseIcapHead();
    void parseHttpHead();
    bool parseHead(HttpMsg *head);

    void parseBody();
    bool parsePresentBody();
    void maybeAllocateHttpMsg();

    void handle100Continue();
    bool validate200Ok();
    void handle200Ok();
    void handle204NoContent();
    void handleUnknownScode();

    void echoMore();

    virtual bool doneAll() const;

    virtual void doStop();
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

    Pointer self;
    MsgPipe::Pointer virgin;
    MsgPipe::Pointer adapted;

    HttpReply *icapReply;

    SizedEstimate virginBody;
    MemBufClaim virginWriteClaim; // preserve virgin data buffer for writing
    MemBufClaim virginSendClaim;  // ... for sending (previe and 204s)
    size_t virginConsumed;         // virgin data consumed so far
    ICAPPreview preview; // use for creating (writing) the preview

    ChunkedCodingParser *bodyParser; // ICAP response body parser

    class State
    {

    public:
        State();

    public:

    unsigned serviceWaiting:
        1; // waiting for the ICAPServiceRep preparing the ICAP service

    unsigned doneReceiving:
        1; // expect no new virgin info (from the virgin pipe)

        // will not write anything [else] to the ICAP server connection
        bool doneWriting() const { return writing == writingReallyDone; }

        // parsed entire ICAP response from the ICAP server
        bool doneParsing() const { return parsing == psDone; }

        // is parsing ICAP or HTTP headers read from the ICAP server
        bool parsingHeaders() const
        {
            return parsing == psIcapHeader ||
                   parsing == psHttpHeader;
        }

        enum Parsing { psIcapHeader, psHttpHeader, psBody, psDone } parsing;

        // measures ICAP request writing progress
        enum Writing { writingInit, writingConnect, writingHeaders,
            writingPreview, writingPaused, writingPrime,
            writingAlmostDone, // waiting for the last write() call to finish
            writingReallyDone } writing;

        enum Sending { sendingUndecided, sendingVirgin, sendingAdapted,
                       sendingDone } sending;
    }

    state;

    CBDATA_CLASS2(ICAPModXact);
};

// destroys the transaction; implemented in ICAPClient.cc (ick?)
extern void ICAPNoteXactionDone(ICAPModXact::Pointer x);

#endif /* SQUID_ICAPMOD_XACT_H */

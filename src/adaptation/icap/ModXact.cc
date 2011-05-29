/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpMsg.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "adaptation/Initiator.h"
#include "adaptation/icap/ServiceRep.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/ModXact.h"
#include "adaptation/icap/Client.h"
#include "ChunkedCodingParser.h"
#include "TextException.h"
#include "auth/UserRequest.h"
#include "adaptation/icap/Config.h"
#include "SquidTime.h"
#include "AccessLogEntry.h"
#include "adaptation/icap/History.h"
#include "adaptation/History.h"

// flow and terminology:
//     HTTP| --> receive --> encode --> write --> |network
//     end | <-- send    <-- parse  <-- read  <-- |end

// TODO: replace gotEncapsulated() with something faster; we call it often

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, ModXact);
CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, ModXactLauncher);

static const size_t TheBackupLimit = BodyPipe::MaxCapacity;

Adaptation::Icap::ModXact::State::State()
{
    memset(this, 0, sizeof(*this));
}

Adaptation::Icap::ModXact::ModXact(HttpMsg *virginHeader,
                                   HttpRequest *virginCause, Adaptation::Icap::ServiceRep::Pointer &aService):
        AsyncJob("Adaptation::Icap::ModXact"),
        Adaptation::Icap::Xaction("Adaptation::Icap::ModXact", aService),
        virginConsumed(0),
        bodyParser(NULL),
        canStartBypass(false), // too early
        protectGroupBypass(true),
        replyBodySize(0),
        adaptHistoryId(-1)
{
    assert(virginHeader);

    virgin.setHeader(virginHeader); // sets virgin.body_pipe if needed
    virgin.setCause(virginCause); // may be NULL

    // adapted header and body are initialized when we parse them

    // writing and reading ends are handled by Adaptation::Icap::Xaction

    // encoding
    // nothing to do because we are using temporary buffers

    // parsing; TODO: do not set until we parse, see ICAPOptXact
    icapReply = new HttpReply;
    icapReply->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    debugs(93,7, HERE << "initialized." << status());
}

// initiator wants us to start
void Adaptation::Icap::ModXact::start()
{
    Adaptation::Icap::Xaction::start();

    // reserve an adaptation history slot (attempts are known at this time)
    Adaptation::History::Pointer ah = virginRequest().adaptLogHistory();
    if (ah != NULL)
        adaptHistoryId = ah->recordXactStart(service().cfg().key, icap_tr_start, attempts > 1);

    estimateVirginBody(); // before virgin disappears!

    canStartBypass = service().cfg().bypass;

    // it is an ICAP violation to send request to a service w/o known OPTIONS

    if (service().up())
        startWriting();
    else
        waitForService();
}

void Adaptation::Icap::ModXact::waitForService()
{
    Must(!state.serviceWaiting);
    debugs(93, 7, HERE << "will wait for the ICAP service" << status());
    typedef NullaryMemFunT<ModXact> Dialer;
    AsyncCall::Pointer call = JobCallback(93,5,
                                          Dialer, this, Adaptation::Icap::ModXact::noteServiceReady);
    service().callWhenReady(call);
    state.serviceWaiting = true; // after callWhenReady() which may throw
}

void Adaptation::Icap::ModXact::noteServiceReady()
{
    Must(state.serviceWaiting);
    state.serviceWaiting = false;

    if (service().up()) {
        startWriting();
    } else {
        disableRetries();
        disableRepeats("ICAP service is unusable");
        throw TexcHere("ICAP service is unusable");
    }
}

void Adaptation::Icap::ModXact::startWriting()
{
    state.writing = State::writingConnect;

    decideOnPreview(); // must be decided before we decideOnRetries
    decideOnRetries();

    openConnection();
}

// connection with the ICAP service established
void Adaptation::Icap::ModXact::handleCommConnected()
{
    Must(state.writing == State::writingConnect);

    startReading(); // wait for early errors from the ICAP server

    MemBuf requestBuf;
    requestBuf.init();

    makeRequestHeaders(requestBuf);
    debugs(93, 9, HERE << "will write" << status() << ":\n" <<
           (requestBuf.terminate(), requestBuf.content()));

    // write headers
    state.writing = State::writingHeaders;
    icap_tio_start = current_time;
    scheduleWrite(requestBuf);
}

void Adaptation::Icap::ModXact::handleCommWrote(size_t sz)
{
    debugs(93, 5, HERE << "Wrote " << sz << " bytes");

    if (state.writing == State::writingHeaders)
        handleCommWroteHeaders();
    else
        handleCommWroteBody();
}

void Adaptation::Icap::ModXact::handleCommWroteHeaders()
{
    Must(state.writing == State::writingHeaders);

    // determine next step
    if (preview.enabled()) {
        if (preview.done())
            decideWritingAfterPreview("zero-size");
        else
            state.writing = State::writingPreview;
    } else if (virginBody.expected()) {
        state.writing = State::writingPrime;
    } else {
        stopWriting(true);
        return;
    }

    writeMore();
}

void Adaptation::Icap::ModXact::writeMore()
{
    debugs(93, 5, HERE << "checking whether to write more" << status());

    if (writer != NULL) // already writing something
        return;

    switch (state.writing) {

    case State::writingInit:    // waiting for service OPTIONS
        Must(state.serviceWaiting);

    case State::writingConnect: // waiting for the connection to establish

    case State::writingHeaders: // waiting for the headers to be written

    case State::writingPaused:  // waiting for the ICAP server response

    case State::writingReallyDone: // nothing more to write
        return;

    case State::writingAlmostDone: // was waiting for the last write
        stopWriting(false);
        return;

    case State::writingPreview:
        writePreviewBody();
        return;

    case State::writingPrime:
        writePrimeBody();
        return;

    default:
        throw TexcHere("Adaptation::Icap::ModXact in bad writing state");
    }
}

void Adaptation::Icap::ModXact::writePreviewBody()
{
    debugs(93, 8, HERE << "will write Preview body from " <<
           virgin.body_pipe << status());
    Must(state.writing == State::writingPreview);
    Must(virgin.body_pipe != NULL);

    const size_t sizeMax = (size_t)virgin.body_pipe->buf().contentSize();
    const size_t size = min(preview.debt(), sizeMax);
    writeSomeBody("preview body", size);

    // change state once preview is written

    if (preview.done())
        decideWritingAfterPreview("body");
}

/// determine state.writing after we wrote the entire preview
void Adaptation::Icap::ModXact::decideWritingAfterPreview(const char *kind)
{
    if (preview.ieof()) // nothing more to write
        stopWriting(true);
    else if (state.parsing == State::psIcapHeader) // did not get a reply yet
        state.writing = State::writingPaused; // wait for the ICAP server reply
    else
        stopWriting(true); // ICAP server reply implies no post-preview writing

    debugs(93, 6, HERE << "decided on writing after " << kind << " preview" <<
           status());
}

void Adaptation::Icap::ModXact::writePrimeBody()
{
    Must(state.writing == State::writingPrime);
    Must(virginBodyWriting.active());

    const size_t size = (size_t)virgin.body_pipe->buf().contentSize();
    writeSomeBody("prime virgin body", size);

    if (virginBodyEndReached(virginBodyWriting)) {
        debugs(93, 5, HERE << "wrote entire body");
        stopWriting(true);
    }
}

void Adaptation::Icap::ModXact::writeSomeBody(const char *label, size_t size)
{
    Must(!writer && state.writing < state.writingAlmostDone);
    Must(virgin.body_pipe != NULL);
    debugs(93, 8, HERE << "will write up to " << size << " bytes of " <<
           label);

    MemBuf writeBuf; // TODO: suggest a min size based on size and lastChunk

    writeBuf.init(); // note: we assume that last-chunk will fit

    const size_t writableSize = virginContentSize(virginBodyWriting);
    const size_t chunkSize = min(writableSize, size);

    if (chunkSize) {
        debugs(93, 7, HERE << "will write " << chunkSize <<
               "-byte chunk of " << label);

        openChunk(writeBuf, chunkSize, false);
        writeBuf.append(virginContentData(virginBodyWriting), chunkSize);
        closeChunk(writeBuf);

        virginBodyWriting.progress(chunkSize);
        virginConsume();
    } else {
        debugs(93, 7, HERE << "has no writable " << label << " content");
    }

    const bool wroteEof = virginBodyEndReached(virginBodyWriting);
    bool lastChunk = wroteEof;
    if (state.writing == State::writingPreview) {
        preview.wrote(chunkSize, wroteEof); // even if wrote nothing
        lastChunk = lastChunk || preview.done();
    }

    if (lastChunk) {
        debugs(93, 8, HERE << "will write last-chunk of " << label);
        addLastRequestChunk(writeBuf);
    }

    debugs(93, 7, HERE << "will write " << writeBuf.contentSize()
           << " raw bytes of " << label);

    if (writeBuf.hasContent()) {
        scheduleWrite(writeBuf); // comm will free the chunk
    } else {
        writeBuf.clean();
    }
}

void Adaptation::Icap::ModXact::addLastRequestChunk(MemBuf &buf)
{
    const bool ieof = state.writing == State::writingPreview && preview.ieof();
    openChunk(buf, 0, ieof);
    closeChunk(buf);
}

void Adaptation::Icap::ModXact::openChunk(MemBuf &buf, size_t chunkSize, bool ieof)
{
    buf.Printf((ieof ? "%x; ieof\r\n" : "%x\r\n"), (int) chunkSize);
}

void Adaptation::Icap::ModXact::closeChunk(MemBuf &buf)
{
    buf.append(ICAP::crlf, 2); // chunk-terminating CRLF
}

const HttpRequest &Adaptation::Icap::ModXact::virginRequest() const
{
    const HttpRequest *request = virgin.cause ?
                                 virgin.cause : dynamic_cast<const HttpRequest*>(virgin.header);
    Must(request);
    return *request;
}

// did the activity reached the end of the virgin body?
bool Adaptation::Icap::ModXact::virginBodyEndReached(const Adaptation::Icap::VirginBodyAct &act) const
{
    return
        !act.active() || // did all (assuming it was originally planned)
        !virgin.body_pipe->expectMoreAfter(act.offset()); // wont have more
}

// the size of buffered virgin body data available for the specified activity
// if this size is zero, we may be done or may be waiting for more data
size_t Adaptation::Icap::ModXact::virginContentSize(const Adaptation::Icap::VirginBodyAct &act) const
{
    Must(act.active());
    // asbolute start of unprocessed data
    const uint64_t dataStart = act.offset();
    // absolute end of buffered data
    const uint64_t dataEnd = virginConsumed + virgin.body_pipe->buf().contentSize();
    Must(virginConsumed <= dataStart && dataStart <= dataEnd);
    return static_cast<size_t>(dataEnd - dataStart);
}

// pointer to buffered virgin body data available for the specified activity
const char *Adaptation::Icap::ModXact::virginContentData(const Adaptation::Icap::VirginBodyAct &act) const
{
    Must(act.active());
    const uint64_t dataStart = act.offset();
    Must(virginConsumed <= dataStart);
    return virgin.body_pipe->buf().content() + static_cast<size_t>(dataStart-virginConsumed);
}

void Adaptation::Icap::ModXact::virginConsume()
{
    debugs(93, 9, HERE << "consumption guards: " << !virgin.body_pipe << isRetriable <<
           isRepeatable << canStartBypass << protectGroupBypass);

    if (!virgin.body_pipe)
        return; // nothing to consume

    if (isRetriable)
        return; // do not consume if we may have to retry later

    BodyPipe &bp = *virgin.body_pipe;
    const bool wantToPostpone = isRepeatable || canStartBypass || protectGroupBypass;

    // Why > 2? HttpState does not use the last bytes in the buffer
    // because delayAwareRead() is arguably broken. See
    // HttpStateData::maybeReadVirginBody for more details.
    if (wantToPostpone && bp.buf().spaceSize() > 2) {
        // Postponing may increase memory footprint and slow the HTTP side
        // down. Not postponing may increase the number of ICAP errors
        // if the ICAP service fails. We may also use "potential" space to
        // postpone more aggressively. Should the trade-off be configurable?
        debugs(93, 8, HERE << "postponing consumption from " << bp.status());
        return;
    }

    const size_t have = static_cast<size_t>(bp.buf().contentSize());
    const uint64_t end = virginConsumed + have;
    uint64_t offset = end;

    debugs(93, 9, HERE << "max virgin consumption offset=" << offset <<
           " acts " << virginBodyWriting.active() << virginBodySending.active() <<
           " consumed=" << virginConsumed <<
           " from " << virgin.body_pipe->status());

    if (virginBodyWriting.active())
        offset = min(virginBodyWriting.offset(), offset);

    if (virginBodySending.active())
        offset = min(virginBodySending.offset(), offset);

    Must(virginConsumed <= offset && offset <= end);

    if (const size_t size = static_cast<size_t>(offset - virginConsumed)) {
        debugs(93, 8, HERE << "consuming " << size << " out of " << have <<
               " virgin body bytes");
        bp.consume(size);
        virginConsumed += size;
        Must(!isRetriable); // or we should not be consuming
        disableRepeats("consumed content");
        disableBypass("consumed content", true);
    }
}

void Adaptation::Icap::ModXact::handleCommWroteBody()
{
    writeMore();
}

// Called when we do not expect to call comm_write anymore.
// We may have a pending write though.
// If stopping nicely, we will just wait for that pending write, if any.
void Adaptation::Icap::ModXact::stopWriting(bool nicely)
{
    if (state.writing == State::writingReallyDone)
        return;

    if (writer != NULL) {
        if (nicely) {
            debugs(93, 7, HERE << "will wait for the last write" << status());
            state.writing = State::writingAlmostDone; // may already be set
            checkConsuming();
            return;
        }
        debugs(93, 3, HERE << "will NOT wait for the last write" << status());

        // Comm does not have an interface to clear the writer callback nicely,
        // but without clearing the writer we cannot recycle the connection.
        // We prevent connection reuse and hope that we can handle a callback
        // call at any time, usually in the middle of the destruction sequence!
        // Somebody should add comm_remove_write_handler() to comm API.
        reuseConnection = false;
        ignoreLastWrite = true;
    }

    debugs(93, 7, HERE << "will no longer write" << status());
    if (virginBodyWriting.active()) {
        virginBodyWriting.disable();
        virginConsume();
    }
    state.writing = State::writingReallyDone;
    checkConsuming();
}

void Adaptation::Icap::ModXact::stopBackup()
{
    if (!virginBodySending.active())
        return;

    debugs(93, 7, HERE << "will no longer backup" << status());
    virginBodySending.disable();
    virginConsume();
}

bool Adaptation::Icap::ModXact::doneAll() const
{
    return Adaptation::Icap::Xaction::doneAll() && !state.serviceWaiting &&
           doneSending() &&
           doneReading() && state.doneWriting();
}

void Adaptation::Icap::ModXact::startReading()
{
    Must(connection >= 0);
    Must(!reader);
    Must(!adapted.header);
    Must(!adapted.body_pipe);

    // we use the same buffer for headers and body and then consume headers
    readMore();
}

void Adaptation::Icap::ModXact::readMore()
{
    if (reader != NULL || doneReading()) {
        debugs(93,3,HERE << "returning from readMore because reader or doneReading()");
        return;
    }

    // do not fill readBuf if we have no space to store the result
    if (adapted.body_pipe != NULL &&
            !adapted.body_pipe->buf().hasPotentialSpace()) {
        debugs(93,3,HERE << "not reading because ICAP reply pipe is full");
        return;
    }

    if (readBuf.hasSpace())
        scheduleRead();
    else
        debugs(93,3,HERE << "nothing to do because !readBuf.hasSpace()");
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::ModXact::handleCommRead(size_t)
{
    Must(!state.doneParsing());
    icap_tio_finish = current_time;
    parseMore();
    readMore();
}

void Adaptation::Icap::ModXact::echoMore()
{
    Must(state.sending == State::sendingVirgin);
    Must(adapted.body_pipe != NULL);
    Must(virginBodySending.active());

    const size_t sizeMax = virginContentSize(virginBodySending);
    debugs(93,5, HERE << "will echo up to " << sizeMax << " bytes from " <<
           virgin.body_pipe->status());
    debugs(93,5, HERE << "will echo up to " << sizeMax << " bytes to   " <<
           adapted.body_pipe->status());

    if (sizeMax > 0) {
        const size_t size = adapted.body_pipe->putMoreData(virginContentData(virginBodySending), sizeMax);
        debugs(93,5, HERE << "echoed " << size << " out of " << sizeMax <<
               " bytes");
        virginBodySending.progress(size);
        disableRepeats("echoed content");
        disableBypass("echoed content", true);
        virginConsume();
    }

    if (virginBodyEndReached(virginBodySending)) {
        debugs(93, 5, HERE << "echoed all" << status());
        stopSending(true);
    } else {
        debugs(93, 5, HERE << "has " <<
               virgin.body_pipe->buf().contentSize() << " bytes " <<
               "and expects more to echo" << status());
        // TODO: timeout if virgin or adapted pipes are broken
    }
}

bool Adaptation::Icap::ModXact::doneSending() const
{
    return state.sending == State::sendingDone;
}

// stop (or do not start) sending adapted message body
void Adaptation::Icap::ModXact::stopSending(bool nicely)
{
    debugs(93, 7, HERE << "Enter stop sending ");
    if (doneSending())
        return;
    debugs(93, 7, HERE << "Proceed with stop sending ");

    if (state.sending != State::sendingUndecided) {
        debugs(93, 7, HERE << "will no longer send" << status());
        if (adapted.body_pipe != NULL) {
            virginBodySending.disable();
            // we may leave debts if we were echoing and the virgin
            // body_pipe got exhausted before we echoed all planned bytes
            const bool leftDebts = adapted.body_pipe->needsMoreData();
            stopProducingFor(adapted.body_pipe, nicely && !leftDebts);
        }
    } else {
        debugs(93, 7, HERE << "will not start sending" << status());
        Must(!adapted.body_pipe);
    }

    state.sending = State::sendingDone;
    checkConsuming();
}

// should be called after certain state.writing or state.sending changes
void Adaptation::Icap::ModXact::checkConsuming()
{
    // quit if we already stopped or are still using the pipe
    if (!virgin.body_pipe || !state.doneConsumingVirgin())
        return;

    debugs(93, 7, HERE << "will stop consuming" << status());
    stopConsumingFrom(virgin.body_pipe);
}

void Adaptation::Icap::ModXact::parseMore()
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " bytes to parse" <<
           status());
    debugs(93, 5, HERE << "\n" << readBuf.content());

    if (state.parsingHeaders())
        parseHeaders();

    if (state.parsing == State::psBody)
        parseBody();
}

void Adaptation::Icap::ModXact::callException(const std::exception &e)
{
    if (!canStartBypass || isRetriable) {
        Adaptation::Icap::Xaction::callException(e);
        return;
    }

    try {
        debugs(93, 3, HERE << "bypassing " << inCall << " exception: " <<
               e.what() << ' ' << status());
        bypassFailure();
    } catch (const std::exception &bypassE) {
        Adaptation::Icap::Xaction::callException(bypassE);
    }
}

void Adaptation::Icap::ModXact::bypassFailure()
{
    disableBypass("already started to bypass", false);

    Must(!isRetriable); // or we should not be bypassing
    // TODO: should the same be enforced for isRepeatable? Check icap_repeat??

    prepEchoing();

    startSending();

    // end all activities associated with the ICAP server

    stopParsing();

    stopWriting(true); // or should we force it?
    if (connection >= 0) {
        reuseConnection = false; // be conservative
        cancelRead(); // may not work; and we cannot stop connecting either
        if (!doneWithIo())
            debugs(93, 7, HERE << "Warning: bypass failed to stop I/O" << status());
    }

    service().noteFailure(); // we are bypassing, but this is still a failure
}

void Adaptation::Icap::ModXact::disableBypass(const char *reason, bool includingGroupBypass)
{
    if (canStartBypass) {
        debugs(93,7, HERE << "will never start bypass because " << reason);
        canStartBypass = false;
    }
    if (protectGroupBypass && includingGroupBypass) {
        debugs(93,7, HERE << "not protecting group bypass because " << reason);
        protectGroupBypass = false;
    }
}



// note that allocation for echoing is done in handle204NoContent()
void Adaptation::Icap::ModXact::maybeAllocateHttpMsg()
{
    if (adapted.header) // already allocated
        return;

    if (gotEncapsulated("res-hdr")) {
        adapted.setHeader(new HttpReply);
        setOutcome(service().cfg().method == ICAP::methodReqmod ?
                   xoSatisfied : xoModified);
    } else if (gotEncapsulated("req-hdr")) {
        adapted.setHeader(new HttpRequest);
        setOutcome(xoModified);
    } else
        throw TexcHere("Neither res-hdr nor req-hdr in maybeAllocateHttpMsg()");
}

void Adaptation::Icap::ModXact::parseHeaders()
{
    Must(state.parsingHeaders());

    if (state.parsing == State::psIcapHeader) {
        debugs(93, 5, HERE << "parse ICAP headers");
        parseIcapHead();
    }

    if (state.parsing == State::psHttpHeader) {
        debugs(93, 5, HERE << "parse HTTP headers");
        parseHttpHead();
    }

    if (state.parsingHeaders()) { // need more data
        Must(mayReadMore());
        return;
    }

    startSending();
}

// called after parsing all headers or when bypassing an exception
void Adaptation::Icap::ModXact::startSending()
{
    disableRepeats("sent headers");
    disableBypass("sent headers", true);
    sendAnswer(adapted.header);

    if (state.sending == State::sendingVirgin)
        echoMore();
}

void Adaptation::Icap::ModXact::parseIcapHead()
{
    Must(state.sending == State::sendingUndecided);

    if (!parseHead(icapReply))
        return;

    if (httpHeaderHasConnDir(&icapReply->header, "close")) {
        debugs(93, 5, HERE << "found connection close");
        reuseConnection = false;
    }

    switch (icapReply->sline.status) {

    case 100:
        handle100Continue();
        break;

    case 200:
    case 201: // Symantec Scan Engine 5.0 and later when modifying HTTP msg

        if (!validate200Ok()) {
            throw TexcHere("Invalid ICAP Response");
        } else {
            handle200Ok();
        }

        break;

    case 204:
        handle204NoContent();
        break;

    default:
        debugs(93, 5, HERE << "ICAP status " << icapReply->sline.status);
        handleUnknownScode();
        break;
    }

    const HttpRequest *request = dynamic_cast<HttpRequest*>(adapted.header);
    if (!request)
        request = &virginRequest();

    // update the cross-transactional database if needed (all status codes!)
    if (const char *xxName = Adaptation::Config::masterx_shared_name) {
        Adaptation::History::Pointer ah = request->adaptHistory(true);
        if (ah != NULL) {
            const String val = icapReply->header.getByName(xxName);
            if (val.size() > 0) // XXX: HttpHeader lacks empty value detection
                ah->updateXxRecord(xxName, val);
        }
    }

    // update the adaptation plan if needed (all status codes!)
    if (service().cfg().routing) {
        String services;
        if (icapReply->header.getList(HDR_X_NEXT_SERVICES, &services)) {
            Adaptation::History::Pointer ah = request->adaptHistory(true);
            if (ah != NULL)
                ah->updateNextServices(services);
        }
    } // TODO: else warn (occasionally!) if we got HDR_X_NEXT_SERVICES

    // We need to store received ICAP headers for <icapLastHeader logformat option.
    // If we already have stored headers from previous ICAP transaction related to this
    // request, old headers will be replaced with the new one.

    Adaptation::Icap::History::Pointer h = request->icapHistory();
    if (h != NULL) {
        h->mergeIcapHeaders(&icapReply->header);
        h->setIcapLastHeader(&icapReply->header);
    }

    // handle100Continue() manages state.writing on its own.
    // Non-100 status means the server needs no postPreview data from us.
    if (state.writing == State::writingPaused)
        stopWriting(true);
}

bool Adaptation::Icap::ModXact::validate200Ok()
{
    if (ICAP::methodRespmod == service().cfg().method) {
        if (!gotEncapsulated("res-hdr"))
            return false;

        return true;
    }

    if (ICAP::methodReqmod == service().cfg().method) {
        if (!gotEncapsulated("res-hdr") && !gotEncapsulated("req-hdr"))
            return false;

        return true;
    }

    return false;
}

void Adaptation::Icap::ModXact::handle100Continue()
{
    Must(state.writing == State::writingPaused);
    // server must not respond before the end of preview: we may send ieof
    Must(preview.enabled() && preview.done() && !preview.ieof());

    // 100 "Continue" cancels our preview commitment, not 204s outside preview
    if (!state.allowedPostview204)
        stopBackup();

    state.parsing = State::psIcapHeader; // eventually
    icapReply->reset();

    state.writing = State::writingPrime;

    writeMore();
}

void Adaptation::Icap::ModXact::handle200Ok()
{
    state.parsing = State::psHttpHeader;
    state.sending = State::sendingAdapted;
    stopBackup();
    checkConsuming();
}

void Adaptation::Icap::ModXact::handle204NoContent()
{
    stopParsing();
    prepEchoing();
}

// Called when we receive a 204 No Content response and
// when we are trying to bypass a service failure.
// We actually start sending (echoig or not) in startSending.
void Adaptation::Icap::ModXact::prepEchoing()
{
    disableRepeats("preparing to echo content");
    disableBypass("preparing to echo content", true);
    setOutcome(xoEcho);

    // We want to clone the HTTP message, but we do not want
    // to copy some non-HTTP state parts that HttpMsg kids carry in them.
    // Thus, we cannot use a smart pointer, copy constructor, or equivalent.
    // Instead, we simply write the HTTP message and "clone" it by parsing.
    // TODO: use HttpMsg::clone()!

    HttpMsg *oldHead = virgin.header;
    debugs(93, 7, HERE << "cloning virgin message " << oldHead);

    MemBuf httpBuf;

    // write the virgin message into a memory buffer
    httpBuf.init();
    packHead(httpBuf, oldHead);

    // allocate the adapted message and copy metainfo
    Must(!adapted.header);
    {
        HttpMsg::Pointer newHead;
        if (const HttpRequest *oldR = dynamic_cast<const HttpRequest*>(oldHead)) {
            HttpRequest::Pointer newR(new HttpRequest);
            newR->canonical = oldR->canonical ?
                              xstrdup(oldR->canonical) : NULL; // parse() does not set it
            newHead = newR;
        } else if (dynamic_cast<const HttpReply*>(oldHead)) {
            newHead = new HttpReply;
        }
        Must(newHead != NULL);

        newHead->inheritProperties(oldHead);

        adapted.setHeader(newHead);
    }

    // parse the buffer back
    http_status error = HTTP_STATUS_NONE;

    Must(adapted.header->parse(&httpBuf, true, &error));

    Must(adapted.header->hdr_sz == httpBuf.contentSize()); // no leftovers

    httpBuf.clean();

    debugs(93, 7, HERE << "cloned virgin message " << oldHead << " to " <<
           adapted.header);

    // setup adapted body pipe if needed
    if (oldHead->body_pipe != NULL) {
        debugs(93, 7, HERE << "will echo virgin body from " <<
               oldHead->body_pipe);
        if (!virginBodySending.active())
            virginBodySending.plan(); // will throw if not possible
        state.sending = State::sendingVirgin;
        checkConsuming();

        // TODO: optimize: is it possible to just use the oldHead pipe and
        // remove ICAP from the loop? This echoing is probably a common case!
        makeAdaptedBodyPipe("echoed virgin response");
        if (oldHead->body_pipe->bodySizeKnown())
            adapted.body_pipe->setBodySize(oldHead->body_pipe->bodySize());
        debugs(93, 7, HERE << "will echo virgin body to " <<
               adapted.body_pipe);
    } else {
        debugs(93, 7, HERE << "no virgin body to echo");
        stopSending(true);
    }
}

void Adaptation::Icap::ModXact::handleUnknownScode()
{
    stopParsing();
    stopBackup();
    // TODO: mark connection as "bad"

    // Terminate the transaction; we do not know how to handle this response.
    throw TexcHere("Unsupported ICAP status code");
}

void Adaptation::Icap::ModXact::parseHttpHead()
{
    if (gotEncapsulated("res-hdr") || gotEncapsulated("req-hdr")) {
        maybeAllocateHttpMsg();

        if (!parseHead(adapted.header))
            return; // need more header data

        if (dynamic_cast<HttpRequest*>(adapted.header)) {
            const HttpRequest *oldR = dynamic_cast<const HttpRequest*>(virgin.header);
            Must(oldR);
            // TODO: the adapted request did not really originate from the
            // client; give proxy admin an option to prevent copying of
            // sensitive client information here. See the following thread:
            // http://www.squid-cache.org/mail-archive/squid-dev/200703/0040.html
        }

        // Maybe adapted.header==NULL if HttpReply and have Http 0.9 ....
        if (adapted.header)
            adapted.header->inheritProperties(virgin.header);
    }

    decideOnParsingBody();
}

// parses both HTTP and ICAP headers
bool Adaptation::Icap::ModXact::parseHead(HttpMsg *head)
{
    Must(head);
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " head bytes to parse" <<
           "; state: " << state.parsing);

    http_status error = HTTP_STATUS_NONE;
    const bool parsed = head->parse(&readBuf, commEof, &error);
    Must(parsed || !error); // success or need more data

    if (!parsed) { // need more data
        debugs(93, 5, HERE << "parse failed, need more data, return false");
        head->reset();
        return false;
    }

    if (HttpRequest *r = dynamic_cast<HttpRequest*>(head))
        urlCanonical(r); // parse does not set HttpRequest::canonical

    debugs(93, 5, HERE << "parse success, consume " << head->hdr_sz << " bytes, return true");
    readBuf.consume(head->hdr_sz);
    return true;
}

void Adaptation::Icap::ModXact::decideOnParsingBody()
{
    if (gotEncapsulated("res-body") || gotEncapsulated("req-body")) {
        debugs(93, 5, HERE << "expecting a body");
        state.parsing = State::psBody;
        bodyParser = new ChunkedCodingParser;
        makeAdaptedBodyPipe("adapted response from the ICAP server");
        Must(state.sending == State::sendingAdapted);
    } else {
        debugs(93, 5, HERE << "not expecting a body");
        stopParsing();
        stopSending(true);
    }
}

void Adaptation::Icap::ModXact::parseBody()
{
    Must(state.parsing == State::psBody);
    Must(bodyParser);

    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " body bytes to parse");

    // the parser will throw on errors
    BodyPipeCheckout bpc(*adapted.body_pipe);
    const bool parsed = bodyParser->parse(&readBuf, &bpc.buf);
    bpc.checkIn();

    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " body bytes after " <<
           "parse; parsed all: " << parsed);
    replyBodySize += adapted.body_pipe->buf().contentSize();

    // TODO: expose BodyPipe::putSize() to make this check simpler and clearer
    // TODO: do we really need this if we disable when sending headers?
    if (adapted.body_pipe->buf().contentSize() > 0) { // parsed something sometime
        disableRepeats("sent adapted content");
        disableBypass("sent adapted content", true);
    }

    if (parsed) {
        stopParsing();
        stopSending(true); // the parser succeeds only if all parsed data fits
        return;
    }

    debugs(93,3,HERE << this << " needsMoreData = " << bodyParser->needsMoreData());

    if (bodyParser->needsMoreData()) {
        debugs(93,3,HERE << this);
        Must(mayReadMore());
        readMore();
    }

    if (bodyParser->needsMoreSpace()) {
        Must(!doneSending()); // can hope for more space
        Must(adapted.body_pipe->buf().contentSize() > 0); // paranoid
        // TODO: there should be a timeout in case the sink is broken
        // or cannot consume partial content (while we need more space)
    }
}

void Adaptation::Icap::ModXact::stopParsing()
{
    if (state.parsing == State::psDone)
        return;

    debugs(93, 7, HERE << "will no longer parse" << status());

    delete bodyParser;

    bodyParser = NULL;

    state.parsing = State::psDone;
}

// HTTP side added virgin body data
void Adaptation::Icap::ModXact::noteMoreBodyDataAvailable(BodyPipe::Pointer)
{
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();
}

// HTTP side sent us all virgin info
void Adaptation::Icap::ModXact::noteBodyProductionEnded(BodyPipe::Pointer)
{
    Must(virgin.body_pipe->productionEnded());

    // push writer and sender in case we were waiting for the last-chunk
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();
}

// body producer aborted, but the initiator may still want to know
// the answer, even though the HTTP message has been truncated
void Adaptation::Icap::ModXact::noteBodyProducerAborted(BodyPipe::Pointer)
{
    Must(virgin.body_pipe->productionEnded());

    // push writer and sender in case we were waiting for the last-chunk
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();
}

// adapted body consumer wants more adapted data and
// possibly freed some buffer space
void Adaptation::Icap::ModXact::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    if (state.sending == State::sendingVirgin)
        echoMore();
    else if (state.sending == State::sendingAdapted)
        parseMore();
    else
        Must(state.sending == State::sendingUndecided);
}

// adapted body consumer aborted
void Adaptation::Icap::ModXact::noteBodyConsumerAborted(BodyPipe::Pointer)
{
    mustStop("adapted body consumer aborted");
}

Adaptation::Icap::ModXact::~ModXact()
{
    delete bodyParser;
}

// internal cleanup
void Adaptation::Icap::ModXact::swanSong()
{
    debugs(93, 5, HERE << "swan sings" << status());

    stopWriting(false);
    stopSending(false);

    // update adaptation history if start was called and we reserved a slot
    Adaptation::History::Pointer ah = virginRequest().adaptLogHistory();
    if (ah != NULL && adaptHistoryId >= 0)
        ah->recordXactFinish(adaptHistoryId);

    Adaptation::Icap::Xaction::swanSong();
}

void prepareLogWithRequestDetails(HttpRequest *, AccessLogEntry *);

void Adaptation::Icap::ModXact::finalizeLogInfo()
{
    HttpRequest * request_ = NULL;
    HttpReply * reply_ = NULL;
    if (!(request_ = dynamic_cast<HttpRequest*>(adapted.header))) {
        request_ = (virgin.cause? virgin.cause: dynamic_cast<HttpRequest*>(virgin.header));
        reply_ = dynamic_cast<HttpReply*>(adapted.header);
    }

    Adaptation::Icap::History::Pointer h = request_->icapHistory();
    Must(h != NULL); // ICAPXaction::maybeLog calls only if there is a log
    al.icp.opcode = ICP_INVALID;
    al.url = h->log_uri.termedBuf();
    const Adaptation::Icap::ServiceRep  &s = service();
    al.icap.reqMethod = s.cfg().method;

    al.cache.caddr = request_->client_addr;

    al.request = HTTPMSGLOCK(request_);
    if (reply_)
        al.reply = HTTPMSGLOCK(reply_);
    else
        al.reply = NULL;

    if (h->rfc931.size())
        al.cache.rfc931 = h->rfc931.termedBuf();

#if USE_SSL
    if (h->ssluser.size())
        al.cache.ssluser = h->ssluser.termedBuf();
#endif
    al.cache.code = h->logType;
    al.cache.requestSize = h->req_sz;
    if (reply_) {
        al.http.code = reply_->sline.status;
        al.http.content_type = reply_->content_type.termedBuf();
        al.cache.replySize = replyBodySize + reply_->hdr_sz;
        al.cache.highOffset = replyBodySize;
        //don't set al.cache.objectSize because it hasn't exist yet

        Packer p;
        MemBuf mb;

        mb.init();
        packerToMemInit(&p, &mb);

        reply_->header.packInto(&p);
        al.headers.reply = xstrdup(mb.buf);

        packerClean(&p);
        mb.clean();
    }
    prepareLogWithRequestDetails(request_, &al);
    Xaction::finalizeLogInfo();
}


void Adaptation::Icap::ModXact::makeRequestHeaders(MemBuf &buf)
{
    char ntoabuf[MAX_IPSTRLEN];
    /*
     * XXX These should use HttpHdr interfaces instead of Printfs
     */
    const Adaptation::ServiceConfig &s = service().cfg();
    buf.Printf("%s " SQUIDSTRINGPH " ICAP/1.0\r\n", s.methodStr(), SQUIDSTRINGPRINT(s.uri));
    buf.Printf("Host: " SQUIDSTRINGPH ":%d\r\n", SQUIDSTRINGPRINT(s.host), s.port);
    buf.Printf("Date: %s\r\n", mkrfc1123(squid_curtime));

    if (!TheConfig.reuse_connections)
        buf.Printf("Connection: close\r\n");

    // we must forward "Proxy-Authenticate" and "Proxy-Authorization"
    // as ICAP headers.
    if (virgin.header->header.has(HDR_PROXY_AUTHENTICATE)) {
        String vh=virgin.header->header.getByName("Proxy-Authenticate");
        buf.Printf("Proxy-Authenticate: " SQUIDSTRINGPH "\r\n",SQUIDSTRINGPRINT(vh));
    }

    if (virgin.header->header.has(HDR_PROXY_AUTHORIZATION)) {
        String vh=virgin.header->header.getByName("Proxy-Authorization");
        buf.Printf("Proxy-Authorization: " SQUIDSTRINGPH "\r\n", SQUIDSTRINGPRINT(vh));
    }

    const HttpRequest *request = &virginRequest();

    // share the cross-transactional database records if needed
    if (Adaptation::Config::masterx_shared_name) {
        Adaptation::History::Pointer ah = request->adaptHistory(true);
        if (ah != NULL) {
            String name, value;
            if (ah->getXxRecord(name, value)) {
                buf.Printf(SQUIDSTRINGPH ": " SQUIDSTRINGPH "\r\n",
                           SQUIDSTRINGPRINT(name), SQUIDSTRINGPRINT(value));
            }
        }
    }


    buf.Printf("Encapsulated: ");

    MemBuf httpBuf;

    httpBuf.init();

    // build HTTP request header, if any
    ICAP::Method m = s.method;

    // to simplify, we could assume that request is always available

    String urlPath;
    if (request) {
        urlPath = request->urlpath;
        if (ICAP::methodRespmod == m)
            encapsulateHead(buf, "req-hdr", httpBuf, request);
        else if (ICAP::methodReqmod == m)
            encapsulateHead(buf, "req-hdr", httpBuf, virgin.header);
    }

    if (ICAP::methodRespmod == m)
        if (const HttpMsg *prime = virgin.header)
            encapsulateHead(buf, "res-hdr", httpBuf, prime);

    if (!virginBody.expected())
        buf.Printf("null-body=%d", (int) httpBuf.contentSize());
    else if (ICAP::methodReqmod == m)
        buf.Printf("req-body=%d", (int) httpBuf.contentSize());
    else
        buf.Printf("res-body=%d", (int) httpBuf.contentSize());

    buf.append(ICAP::crlf, 2); // terminate Encapsulated line

    if (preview.enabled()) {
        buf.Printf("Preview: %d\r\n", (int)preview.ad());
        if (virginBody.expected()) // there is a body to preview
            virginBodySending.plan();
        else
            finishNullOrEmptyBodyPreview(httpBuf);
    }

    if (shouldAllow204()) {
        debugs(93,5, HERE << "will allow 204s outside of preview");
        state.allowedPostview204 = true;
        buf.Printf("Allow: 204\r\n");
        if (virginBody.expected()) // there is a body to echo
            virginBodySending.plan();
    }

    if (TheConfig.send_client_ip && request) {
        IpAddress client_addr;
#if FOLLOW_X_FORWARDED_FOR
        if (TheConfig.icap_uses_indirect_client) {
            client_addr = request->indirect_client_addr;
        } else
#endif
            client_addr = request->client_addr;
        if (!client_addr.IsAnyAddr() && !client_addr.IsNoAddr())
            buf.Printf("X-Client-IP: %s\r\n", client_addr.NtoA(ntoabuf,MAX_IPSTRLEN));
    }

    if (TheConfig.send_client_username && request)
        makeUsernameHeader(request, buf);

    // fprintf(stderr, "%s\n", buf.content());

    buf.append(ICAP::crlf, 2); // terminate ICAP header

    // fill icapRequest for logging
    Must(icapRequest->parseCharBuf(buf.content(), buf.contentSize()));

    // start ICAP request body with encapsulated HTTP headers
    buf.append(httpBuf.content(), httpBuf.contentSize());

    httpBuf.clean();
}

void Adaptation::Icap::ModXact::makeUsernameHeader(const HttpRequest *request, MemBuf &buf)
{
    if (const AuthUserRequest *auth = request->auth_user_request) {
        if (char const *name = auth->username()) {
            const char *value = TheConfig.client_username_encode ?
                                base64_encode(name) : name;
            buf.Printf("%s: %s\r\n", TheConfig.client_username_header,
                       value);
        }
    }
}

void Adaptation::Icap::ModXact::encapsulateHead(MemBuf &icapBuf, const char *section, MemBuf &httpBuf, const HttpMsg *head)
{
    // update ICAP header
    icapBuf.Printf("%s=%d, ", section, (int) httpBuf.contentSize());

    // begin cloning
    HttpMsg::Pointer headClone;

    if (const HttpRequest* old_request = dynamic_cast<const HttpRequest*>(head)) {
        HttpRequest::Pointer new_request(new HttpRequest);
        Must(old_request->canonical);
        urlParse(old_request->method, old_request->canonical, new_request);
        new_request->http_ver = old_request->http_ver;
        headClone = new_request;
    } else if (const HttpReply *old_reply = dynamic_cast<const HttpReply*>(head)) {
        HttpReply::Pointer new_reply(new HttpReply);
        new_reply->sline = old_reply->sline;
        headClone = new_reply;
    }
    Must(headClone != NULL);
    headClone->inheritProperties(head);

    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry* p_head_entry = NULL;
    while (NULL != (p_head_entry = head->header.getEntry(&pos)) )
        headClone->header.addEntry(p_head_entry->clone());

    // end cloning

    // remove all hop-by-hop headers from the clone
    headClone->header.delById(HDR_PROXY_AUTHENTICATE);
    headClone->header.removeHopByHopEntries();

    // pack polished HTTP header
    packHead(httpBuf, headClone);

    // headClone unlocks and, hence, deletes the message we packed
}

void Adaptation::Icap::ModXact::packHead(MemBuf &httpBuf, const HttpMsg *head)
{
    Packer p;
    packerToMemInit(&p, &httpBuf);
    head->packInto(&p, true);
    packerClean(&p);
}

// decides whether to offer a preview and calculates its size
void Adaptation::Icap::ModXact::decideOnPreview()
{
    if (!TheConfig.preview_enable) {
        debugs(93, 5, HERE << "preview disabled by squid.conf");
        return;
    }

    const String urlPath = virginRequest().urlpath;
    size_t wantedSize;
    if (!service().wantsPreview(urlPath, wantedSize)) {
        debugs(93, 5, HERE << "should not offer preview for " << urlPath);
        return;
    }

    // we decided to do preview, now compute its size

    // cannot preview more than we can backup
    size_t ad = min(wantedSize, TheBackupLimit);

    if (!virginBody.expected())
        ad = 0;
    else if (virginBody.knownSize())
        ad = min(static_cast<uint64_t>(ad), virginBody.size()); // not more than we have

    debugs(93, 5, HERE << "should offer " << ad << "-byte preview " <<
           "(service wanted " << wantedSize << ")");

    preview.enable(ad);
    Must(preview.enabled());
}

// decides whether to allow 204 responses
bool Adaptation::Icap::ModXact::shouldAllow204()
{
    if (!service().allows204())
        return false;

    return canBackupEverything();
}

// used by shouldAllow204 and decideOnRetries
bool Adaptation::Icap::ModXact::canBackupEverything() const
{
    if (!virginBody.expected())
        return true; // no body means no problems with backup

    // if there is a body, check whether we can backup it all

    if (!virginBody.knownSize())
        return false;

    // or should we have a different backup limit?
    // note that '<' allows for 0-termination of the "full" backup buffer
    return virginBody.size() < TheBackupLimit;
}

// Decide whether this transaction can be retried if pconn fails
// Must be called after decideOnPreview and before openConnection()
void Adaptation::Icap::ModXact::decideOnRetries()
{
    if (!isRetriable)
        return; // no, already decided

    if (preview.enabled())
        return; // yes, because preview provides enough guarantees

    if (canBackupEverything())
        return; // yes, because we can back everything up

    disableRetries(); // no, because we cannot back everything up
}

// Normally, the body-writing code handles preview body. It can deal with
// bodies of unexpected size, including those that turn out to be empty.
// However, that code assumes that the body was expected and body control
// structures were initialized. This is not the case when there is no body
// or the body is known to be empty, because the virgin message will lack a
// body_pipe. So we handle preview of null-body and zero-size bodies here.
void Adaptation::Icap::ModXact::finishNullOrEmptyBodyPreview(MemBuf &buf)
{
    Must(!virginBodyWriting.active()); // one reason we handle it here
    Must(!virgin.body_pipe);          // another reason we handle it here
    Must(!preview.ad());

    // do not add last-chunk because our Encapsulated header says null-body
    // addLastRequestChunk(buf);
    preview.wrote(0, true);

    Must(preview.done());
    Must(preview.ieof());
}

void Adaptation::Icap::ModXact::fillPendingStatus(MemBuf &buf) const
{
    Adaptation::Icap::Xaction::fillPendingStatus(buf);

    if (state.serviceWaiting)
        buf.append("U", 1);

    if (virgin.body_pipe != NULL)
        buf.append("R", 1);

    if (connection > 0 && !doneReading())
        buf.append("r", 1);

    if (!state.doneWriting() && state.writing != State::writingInit)
        buf.Printf("w(%d)", state.writing);

    if (preview.enabled()) {
        if (!preview.done())
            buf.Printf("P(%d)", (int) preview.debt());
    }

    if (virginBodySending.active())
        buf.append("B", 1);

    if (!state.doneParsing() && state.parsing != State::psIcapHeader)
        buf.Printf("p(%d)", state.parsing);

    if (!doneSending() && state.sending != State::sendingUndecided)
        buf.Printf("S(%d)", state.sending);

    if (canStartBypass)
        buf.append("Y", 1);

    if (protectGroupBypass)
        buf.append("G", 1);
}

void Adaptation::Icap::ModXact::fillDoneStatus(MemBuf &buf) const
{
    Adaptation::Icap::Xaction::fillDoneStatus(buf);

    if (!virgin.body_pipe)
        buf.append("R", 1);

    if (state.doneWriting())
        buf.append("w", 1);

    if (preview.enabled()) {
        if (preview.done())
            buf.Printf("P%s", preview.ieof() ? "(ieof)" : "");
    }

    if (doneReading())
        buf.append("r", 1);

    if (state.doneParsing())
        buf.append("p", 1);

    if (doneSending())
        buf.append("S", 1);
}

bool Adaptation::Icap::ModXact::gotEncapsulated(const char *section) const
{
    return icapReply->header.getByNameListMember("Encapsulated",
            section, ',').size() > 0;
}

// calculate whether there is a virgin HTTP body and
// whether its expected size is known
// TODO: rename because we do not just estimate
void Adaptation::Icap::ModXact::estimateVirginBody()
{
    // note: lack of size info may disable previews and 204s

    HttpMsg *msg = virgin.header;
    Must(msg);

    HttpRequestMethod method;

    if (virgin.cause)
        method = virgin.cause->method;
    else if (HttpRequest *req = dynamic_cast<HttpRequest*>(msg))
        method = req->method;
    else
        method = METHOD_NONE;

    int64_t size;
    // expectingBody returns true for zero-sized bodies, but we will not
    // get a pipe for that body, so we treat the message as bodyless
    if (method != METHOD_NONE && msg->expectingBody(method, size) && size) {
        debugs(93, 6, HERE << "expects virgin body from " <<
               virgin.body_pipe << "; size: " << size);

        virginBody.expect(size);
        virginBodyWriting.plan();

        // sign up as a body consumer
        Must(msg->body_pipe != NULL);
        Must(msg->body_pipe == virgin.body_pipe);
        Must(virgin.body_pipe->setConsumerIfNotLate(this));

        // make sure TheBackupLimit is in-sync with the buffer size
        Must(TheBackupLimit <= static_cast<size_t>(msg->body_pipe->buf().max_capacity));
    } else {
        debugs(93, 6, HERE << "does not expect virgin body");
        Must(msg->body_pipe == NULL);
        checkConsuming();
    }
}

void Adaptation::Icap::ModXact::makeAdaptedBodyPipe(const char *what)
{
    Must(!adapted.body_pipe);
    Must(!adapted.header->body_pipe);
    adapted.header->body_pipe = new BodyPipe(this);
    adapted.body_pipe = adapted.header->body_pipe;
    debugs(93, 7, HERE << "will supply " << what << " via " <<
           adapted.body_pipe << " pipe");
}


// TODO: Move SizedEstimate and Preview elsewhere

Adaptation::Icap::SizedEstimate::SizedEstimate()
        : theData(dtUnexpected)
{}

void Adaptation::Icap::SizedEstimate::expect(int64_t aSize)
{
    theData = (aSize >= 0) ? aSize : (int64_t)dtUnknown;
}

bool Adaptation::Icap::SizedEstimate::expected() const
{
    return theData != dtUnexpected;
}

bool Adaptation::Icap::SizedEstimate::knownSize() const
{
    Must(expected());
    return theData != dtUnknown;
}

uint64_t Adaptation::Icap::SizedEstimate::size() const
{
    Must(knownSize());
    return static_cast<uint64_t>(theData);
}



Adaptation::Icap::VirginBodyAct::VirginBodyAct(): theStart(0), theState(stUndecided)
{}

void Adaptation::Icap::VirginBodyAct::plan()
{
    Must(!disabled());
    Must(!theStart); // not started
    theState = stActive;
}

void Adaptation::Icap::VirginBodyAct::disable()
{
    theState = stDisabled;
}

void Adaptation::Icap::VirginBodyAct::progress(size_t size)
{
    Must(active());
#if SIZEOF_SIZE_T > 4
    /* always true for smaller size_t's */
    Must(static_cast<int64_t>(size) >= 0);
#endif
    theStart += static_cast<int64_t>(size);
}

uint64_t Adaptation::Icap::VirginBodyAct::offset() const
{
    Must(active());
    return static_cast<uint64_t>(theStart);
}


Adaptation::Icap::Preview::Preview(): theWritten(0), theAd(0), theState(stDisabled)
{}

void Adaptation::Icap::Preview::enable(size_t anAd)
{
    // TODO: check for anAd not exceeding preview size limit
    Must(!enabled());
    theAd = anAd;
    theState = stWriting;
}

bool Adaptation::Icap::Preview::enabled() const
{
    return theState != stDisabled;
}

size_t Adaptation::Icap::Preview::ad() const
{
    Must(enabled());
    return theAd;
}

bool Adaptation::Icap::Preview::done() const
{
    Must(enabled());
    return theState >= stIeof;
}

bool Adaptation::Icap::Preview::ieof() const
{
    Must(enabled());
    return theState == stIeof;
}

size_t Adaptation::Icap::Preview::debt() const
{
    Must(enabled());
    return done() ? 0 : (theAd - theWritten);
}

void Adaptation::Icap::Preview::wrote(size_t size, bool wroteEof)
{
    Must(enabled());

    theWritten += size;

    Must(theWritten <= theAd);

    if (wroteEof)
        theState = stIeof; // written size is irrelevant
    else if (theWritten >= theAd)
        theState = stDone;
}

bool Adaptation::Icap::ModXact::fillVirginHttpHeader(MemBuf &mb) const
{
    if (virgin.header == NULL)
        return false;

    virgin.header->firstLineBuf(mb);

    return true;
}


/* Adaptation::Icap::ModXactLauncher */

Adaptation::Icap::ModXactLauncher::ModXactLauncher(HttpMsg *virginHeader, HttpRequest *virginCause, Adaptation::ServicePointer aService):
        AsyncJob("Adaptation::Icap::ModXactLauncher"),
        Adaptation::Icap::Launcher("Adaptation::Icap::ModXactLauncher", aService)
{
    virgin.setHeader(virginHeader);
    virgin.setCause(virginCause);
    updateHistory(true);
}

Adaptation::Icap::Xaction *Adaptation::Icap::ModXactLauncher::createXaction()
{
    Adaptation::Icap::ServiceRep::Pointer s =
        dynamic_cast<Adaptation::Icap::ServiceRep*>(theService.getRaw());
    Must(s != NULL);
    return new Adaptation::Icap::ModXact(virgin.header, virgin.cause, s);
}

void Adaptation::Icap::ModXactLauncher::swanSong()
{
    debugs(93, 5, HERE << "swan sings");
    updateHistory(false);
    Adaptation::Icap::Launcher::swanSong();
}

void Adaptation::Icap::ModXactLauncher::updateHistory(bool doStart)
{
    HttpRequest *r = virgin.cause ?
                     virgin.cause : dynamic_cast<HttpRequest*>(virgin.header);

    // r should never be NULL but we play safe; TODO: add Should()
    if (r) {
        Adaptation::Icap::History::Pointer h = r->icapHistory();
        if (h != NULL) {
            if (doStart)
                h->start("ICAPModXactLauncher");
            else
                h->stop("ICAPModXactLauncher");
        }
    }
}

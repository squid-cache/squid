/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpMsg.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ICAPServiceRep.h"
#include "ICAPInitiator.h"
#include "ICAPLauncher.h"
#include "ICAPModXact.h"
#include "ICAPClient.h"
#include "ChunkedCodingParser.h"
#include "TextException.h"
#include "AuthUserRequest.h"
#include "ICAPConfig.h"
#include "SquidTime.h"

// flow and terminology:
//     HTTP| --> receive --> encode --> write --> |network
//     end | <-- send    <-- parse  <-- read  <-- |end

// TODO: replace gotEncapsulated() with something faster; we call it often

CBDATA_CLASS_INIT(ICAPModXact);
CBDATA_CLASS_INIT(ICAPModXactLauncher);

static const size_t TheBackupLimit = BodyPipe::MaxCapacity;

extern ICAPConfig TheICAPConfig;


ICAPModXact::State::State()
{
    memset(this, sizeof(*this), 0);
}

ICAPModXact::ICAPModXact(ICAPInitiator *anInitiator, HttpMsg *virginHeader,
    HttpRequest *virginCause, ICAPServiceRep::Pointer &aService):
    ICAPXaction("ICAPModXact", anInitiator, aService),
    icapReply(NULL),
    virginConsumed(0),
    bodyParser(NULL),
    canStartBypass(false) // too early
{
    assert(virginHeader);

    virgin.setHeader(virginHeader); // sets virgin.body_pipe if needed
    virgin.setCause(virginCause); // may be NULL

    // adapted header and body are initialized when we parse them

    // writing and reading ends are handled by ICAPXaction

    // encoding
    // nothing to do because we are using temporary buffers

    // parsing
    icapReply = new HttpReply;
    icapReply->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    debugs(93,7, "ICAPModXact initialized." << status());
}

// initiator wants us to start
void ICAPModXact::start()
{
    ICAPXaction::start();

    estimateVirginBody(); // before virgin disappears!

    canStartBypass = service().bypass;

    // it is an ICAP violation to send request to a service w/o known OPTIONS

    if (service().up())
        startWriting();
    else
        waitForService();

    // XXX: If commConnectStart in startWriting fails, we may get here
    //_after_ the object got destroyed. Somebody please fix commConnectStart!
    // TODO: Does re-entrance protection in callStart() solve the above?
}

static
void ICAPModXact_noteServiceReady(void *data, ICAPServiceRep::Pointer &)
{
    ICAPModXact *x = static_cast<ICAPModXact*>(data);
    assert(x);
    x->noteServiceReady();
}

void ICAPModXact::waitForService()
{
    Must(!state.serviceWaiting);
    debugs(93, 7, "ICAPModXact will wait for the ICAP service" << status());
    state.serviceWaiting = true;
    service().callWhenReady(&ICAPModXact_noteServiceReady, this);
}

void ICAPModXact::noteServiceReady()
{
    ICAPXaction_Enter(noteServiceReady);

    Must(state.serviceWaiting);
    state.serviceWaiting = false;

    if (service().up()) {
        startWriting();
    } else {
        disableRetries();
        throw TexcHere("ICAP service is unusable");
    }

    ICAPXaction_Exit();
}

void ICAPModXact::startWriting()
{
    state.writing = State::writingConnect;

    decideOnPreview(); // must be decided before we decideOnRetries
    decideOnRetries();

    openConnection();
    // put nothing here as openConnection calls commConnectStart
    // and that may call us back without waiting for the next select loop
}

// connection with the ICAP service established
void ICAPModXact::handleCommConnected()
{
    Must(state.writing == State::writingConnect);

    startReading(); // wait for early errors from the ICAP server

    MemBuf requestBuf;
    requestBuf.init();

    makeRequestHeaders(requestBuf);
    debugs(93, 9, "ICAPModXact ICAP will write" << status() << ":\n" <<
           (requestBuf.terminate(), requestBuf.content()));

    // write headers
    state.writing = State::writingHeaders;
    scheduleWrite(requestBuf);
}

void ICAPModXact::handleCommWrote(size_t sz)
{
    debugs(93, 5, HERE << "Wrote " << sz << " bytes");

    if (state.writing == State::writingHeaders)
        handleCommWroteHeaders();
    else
        handleCommWroteBody();
}

void ICAPModXact::handleCommWroteHeaders()
{
    Must(state.writing == State::writingHeaders);

    // determine next step
    if (preview.enabled())
        state.writing = preview.done() ? State::writingPaused : State::writingPreview;
    else
    if (virginBody.expected())
        state.writing = State::writingPrime;
    else {
        stopWriting(true);
        return;
    }

    writeMore();
}

void ICAPModXact::writeMore()
{
    debugs(93, 5, HERE << "checking whether to write more" << status());

    if (writer) // already writing something
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
        throw TexcHere("ICAPModXact in bad writing state");
    }
}

void ICAPModXact::writePreviewBody()
{
    debugs(93, 8, HERE << "will write Preview body from " <<
        virgin.body_pipe << status());
    Must(state.writing == State::writingPreview);
    Must(virgin.body_pipe != NULL);

    const size_t sizeMax = (size_t)virgin.body_pipe->buf().contentSize();
    const size_t size = XMIN(preview.debt(), sizeMax);
    writeSomeBody("preview body", size);

    // change state once preview is written

    if (preview.done()) {
        debugs(93, 7, "ICAPModXact wrote entire Preview body" << status());

        if (preview.ieof())
            stopWriting(true);
        else
            state.writing = State::writingPaused;
    }
}

void ICAPModXact::writePrimeBody()
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

void ICAPModXact::writeSomeBody(const char *label, size_t size)
{
    Must(!writer && state.writing < state.writingAlmostDone);
    Must(virgin.body_pipe != NULL);
    debugs(93, 8, HERE << "will write up to " << size << " bytes of " <<
           label);

    MemBuf writeBuf; // TODO: suggest a min size based on size and lastChunk

    writeBuf.init(); // note: we assume that last-chunk will fit

    const size_t writableSize = virginContentSize(virginBodyWriting);
    const size_t chunkSize = XMIN(writableSize, size);

    if (chunkSize) {
        debugs(93, 7, HERE << "will write " << chunkSize <<
               "-byte chunk of " << label);

        openChunk(writeBuf, chunkSize, false);
        writeBuf.append(virginContentData(virginBodyWriting), chunkSize);
        closeChunk(writeBuf);

        virginBodyWriting.progress(chunkSize);
        virginConsume();
    } else {
        debugs(93, 7, "ICAPModXact has no writable " << label << " content");
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

void ICAPModXact::addLastRequestChunk(MemBuf &buf)
{
    const bool ieof = state.writing == State::writingPreview && preview.ieof();
    openChunk(buf, 0, ieof);
    closeChunk(buf);
}

void ICAPModXact::openChunk(MemBuf &buf, size_t chunkSize, bool ieof)
{
    buf.Printf((ieof ? "%x; ieof\r\n" : "%x\r\n"), (int) chunkSize);
}

void ICAPModXact::closeChunk(MemBuf &buf)
{
    buf.append(ICAP::crlf, 2); // chunk-terminating CRLF
}

// did the activity reached the end of the virgin body?
bool ICAPModXact::virginBodyEndReached(const VirginBodyAct &act) const
{
    return 
        !act.active() || // did all (assuming it was originally planned)
        !virgin.body_pipe->expectMoreAfter(act.offset()); // wont have more
}

// the size of buffered virgin body data available for the specified activity
// if this size is zero, we may be done or may be waiting for more data
size_t ICAPModXact::virginContentSize(const VirginBodyAct &act) const
{
    Must(act.active());
    // asbolute start of unprocessed data
    const uint64_t start = act.offset();
    // absolute end of buffered data
    const uint64_t end = virginConsumed + virgin.body_pipe->buf().contentSize();
    Must(virginConsumed <= start && start <= end);
    return static_cast<size_t>(end - start);
}

// pointer to buffered virgin body data available for the specified activity
const char *ICAPModXact::virginContentData(const VirginBodyAct &act) const
{
    Must(act.active());
    const uint64_t start = act.offset();
    Must(virginConsumed <= start);
    return virgin.body_pipe->buf().content() + static_cast<size_t>(start-virginConsumed);
}

void ICAPModXact::virginConsume()
{
    debugs(93, 9, "consumption guards: " << !virgin.body_pipe << isRetriable);

    if (!virgin.body_pipe)
        return; // nothing to consume

    if (isRetriable)
        return; // do not consume if we may have to retry later

    BodyPipe &bp = *virgin.body_pipe;

    // Why > 2? HttpState does not use the last bytes in the buffer
    // because delayAwareRead() is arguably broken. See 
    // HttpStateData::maybeReadVirginBody for more details.
    if (canStartBypass && bp.buf().spaceSize() > 2) {
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
        offset = XMIN(virginBodyWriting.offset(), offset);

    if (virginBodySending.active())
        offset = XMIN(virginBodySending.offset(), offset);

    Must(virginConsumed <= offset && offset <= end);

    if (const size_t size = static_cast<size_t>(offset - virginConsumed)) {
        debugs(93, 8, HERE << "consuming " << size << " out of " << have <<
               " virgin body bytes");
        bp.consume(size);
        virginConsumed += size;
        Must(!isRetriable); // or we should not be consuming
        disableBypass("consumed content");
    }
}

void ICAPModXact::handleCommWroteBody()
{
    writeMore();
}

// Called when we do not expect to call comm_write anymore.
// We may have a pending write though.
// If stopping nicely, we will just wait for that pending write, if any.
void ICAPModXact::stopWriting(bool nicely)
{
    if (state.writing == State::writingReallyDone)
        return;

    if (writer) {
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

void ICAPModXact::stopBackup()
{
    if (!virginBodySending.active())
        return;

    debugs(93, 7, "ICAPModXact will no longer backup" << status());
    virginBodySending.disable();
    virginConsume();
}

bool ICAPModXact::doneAll() const
{
    return ICAPXaction::doneAll() && !state.serviceWaiting &&
           doneSending() &&
           doneReading() && state.doneWriting();
}

void ICAPModXact::startReading()
{
    Must(connection >= 0);
    Must(!reader);
    Must(!adapted.header);
    Must(!adapted.body_pipe);

    // we use the same buffer for headers and body and then consume headers
    readMore();
}

void ICAPModXact::readMore()
{
    if (reader || doneReading()) {
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
void ICAPModXact::handleCommRead(size_t)
{
    Must(!state.doneParsing());
    parseMore();
    readMore();
}

void ICAPModXact::echoMore()
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
        virginConsume();
        disableBypass("echoed content");
    }

    if (virginBodyEndReached(virginBodySending)) {
        debugs(93, 5, "ICAPModXact echoed all" << status());
        stopSending(true);
    } else {
        debugs(93, 5, "ICAPModXact has " <<
            virgin.body_pipe->buf().contentSize() << " bytes " <<
            "and expects more to echo" << status());
        // TODO: timeout if virgin or adapted pipes are broken
    }
}

bool ICAPModXact::doneSending() const
{
    return state.sending == State::sendingDone;
}

// stop (or do not start) sending adapted message body
void ICAPModXact::stopSending(bool nicely)
{
    if (doneSending())
        return;

    if (state.sending != State::sendingUndecided) {
        debugs(93, 7, "ICAPModXact will no longer send" << status());
        if (adapted.body_pipe != NULL) {
            virginBodySending.disable();
            // we may leave debts if we were echoing and the virgin
            // body_pipe got exhausted before we echoed all planned bytes
            const bool leftDebts = adapted.body_pipe->needsMoreData();
            stopProducingFor(adapted.body_pipe, nicely && !leftDebts);
        }
    } else {
        debugs(93, 7, "ICAPModXact will not start sending" << status());
        Must(!adapted.body_pipe);
    }

    state.sending = State::sendingDone;
    checkConsuming();
}

// should be called after certain state.writing or state.sending changes
void ICAPModXact::checkConsuming()
{
    // quit if we already stopped or are still using the pipe
    if (!virgin.body_pipe || !state.doneConsumingVirgin())
        return;

    debugs(93, 7, HERE << "will stop consuming" << status());
    stopConsumingFrom(virgin.body_pipe);
}

void ICAPModXact::parseMore()
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " bytes to parse" <<
           status());
    debugs(93, 5, HERE << "\n" << readBuf.content());

    if (state.parsingHeaders())
        parseHeaders();

    if (state.parsing == State::psBody)
        parseBody();
}

void ICAPModXact::callException(const TextException &e)
{
    if (!canStartBypass || isRetriable) {
        ICAPXaction::callException(e);
        return;
    }

    try {
        debugs(93, 3, "bypassing ICAPModXact::" << inCall << " exception: " <<
           e.message << ' ' << status());
        bypassFailure();
    }
    catch (const TextException &bypassE) {
        ICAPXaction::callException(bypassE);
    }
}

void ICAPModXact::bypassFailure()
{
    disableBypass("already started to bypass");

    Must(!isRetriable); // or we should not be bypassing

    prepEchoing();

    startSending();

    // end all activities associated with the ICAP server

    stopParsing();

    stopWriting(true); // or should we force it?
    if (connection >= 0) {
        reuseConnection = false; // be conservative
        cancelRead(); // may not work; and we cannot stop connecting either
        if (!doneWithIo())
            debugs(93, 7, "Warning: bypass failed to stop I/O" << status());
    }
}

void ICAPModXact::disableBypass(const char *reason)
{
    if (canStartBypass) {
        debugs(93,7, HERE << "will never start bypass because " << reason);
        canStartBypass = false;
    }
}



// note that allocation for echoing is done in handle204NoContent()
void ICAPModXact::maybeAllocateHttpMsg()
{
    if (adapted.header) // already allocated
        return;

    if (gotEncapsulated("res-hdr")) {
        adapted.setHeader(new HttpReply);
    } else if (gotEncapsulated("req-hdr")) {
        adapted.setHeader(new HttpRequest);
    } else
        throw TexcHere("Neither res-hdr nor req-hdr in maybeAllocateHttpMsg()");
}

void ICAPModXact::parseHeaders()
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
void ICAPModXact::startSending()
{
    disableBypass("sent headers");
    sendAnswer(adapted.header);

    if (state.sending == State::sendingVirgin)
        echoMore();
}

void ICAPModXact::parseIcapHead()
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

    // handle100Continue() manages state.writing on its own.
    // Non-100 status means the server needs no postPreview data from us.
    if (state.writing == State::writingPaused)
        stopWriting(true);
}

bool ICAPModXact::validate200Ok()
{
    if (ICAP::methodRespmod == service().method) {
        if (!gotEncapsulated("res-hdr"))
            return false;

        return true;
    }

    if (ICAP::methodReqmod == service().method) {
        if (!gotEncapsulated("res-hdr") && !gotEncapsulated("req-hdr"))
            return false;

        return true;
    }

    return false;
}

void ICAPModXact::handle100Continue()
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

void ICAPModXact::handle200Ok()
{
    state.parsing = State::psHttpHeader;
    state.sending = State::sendingAdapted;
    stopBackup();
    checkConsuming();
}

void ICAPModXact::handle204NoContent()
{
    stopParsing();
    prepEchoing();
}

// Called when we receive a 204 No Content response and
// when we are trying to bypass a service failure.
// We actually start sending (echoig or not) in startSending.
void ICAPModXact::prepEchoing()
{
    disableBypass("preparing to echo content");

    // We want to clone the HTTP message, but we do not want
    // to copy some non-HTTP state parts that HttpMsg kids carry in them.
    // Thus, we cannot use a smart pointer, copy constructor, or equivalent.
    // Instead, we simply write the HTTP message and "clone" it by parsing.

    HttpMsg *oldHead = virgin.header;
    debugs(93, 7, "ICAPModXact cloning virgin message " << oldHead);

    MemBuf httpBuf;

    // write the virgin message into a memory buffer
    httpBuf.init();
    packHead(httpBuf, oldHead);

    // allocate the adapted message and copy metainfo
    Must(!adapted.header);
    HttpMsg *newHead = NULL;
    if (const HttpRequest *oldR = dynamic_cast<const HttpRequest*>(oldHead)) {
        HttpRequest *newR = new HttpRequest;
        inheritVirginProperties(*newR, *oldR);
        newHead = newR;
    } else
    if (dynamic_cast<const HttpReply*>(oldHead))
        newHead = new HttpReply;
    Must(newHead);

    adapted.setHeader(newHead);

    // parse the buffer back
    http_status error = HTTP_STATUS_NONE;

    Must(newHead->parse(&httpBuf, true, &error));

    Must(newHead->hdr_sz == httpBuf.contentSize()); // no leftovers

    httpBuf.clean();

    debugs(93, 7, "ICAPModXact cloned virgin message " << oldHead << " to " <<
        newHead);

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

void ICAPModXact::handleUnknownScode()
{
    stopParsing();
    stopBackup();
    // TODO: mark connection as "bad"

    // Terminate the transaction; we do not know how to handle this response.
    throw TexcHere("Unsupported ICAP status code");
}

void ICAPModXact::parseHttpHead()
{
    if (gotEncapsulated("res-hdr") || gotEncapsulated("req-hdr")) {
        maybeAllocateHttpMsg();

        if (!parseHead(adapted.header))
            return; // need more header data

        if (HttpRequest *newHead = dynamic_cast<HttpRequest*>(adapted.header)) {
            const HttpRequest *oldR = dynamic_cast<const HttpRequest*>(virgin.header);
            Must(oldR);
            // TODO: the adapted request did not really originate from the 
            // client; give proxy admin an option to prevent copying of 
            // sensitive client information here. See the following thread:
            // http://www.squid-cache.org/mail-archive/squid-dev/200703/0040.html
            inheritVirginProperties(*newHead, *oldR);
        }
    }

    decideOnParsingBody();
}

// parses both HTTP and ICAP headers
bool ICAPModXact::parseHead(HttpMsg *head)
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

    debugs(93, 5, HERE << "parse success, consume " << head->hdr_sz << " bytes, return true");
    readBuf.consume(head->hdr_sz);
    return true;
}

// TODO: Move this method to HttpRequest?
void ICAPModXact::inheritVirginProperties(HttpRequest &newR, const HttpRequest &oldR) {

    newR.client_addr = oldR.client_addr;
    newR.client_port = oldR.client_port;

    newR.my_addr = oldR.my_addr;
    newR.my_port = oldR.my_port;

    // This may be too conservative for the 204 No Content case
    // may eventually need cloneNullAdaptationImmune() for that.
    newR.flags = oldR.flags.cloneAdaptationImmune();

    if (oldR.auth_user_request) {
        newR.auth_user_request = oldR.auth_user_request;
	AUTHUSERREQUESTLOCK(newR.auth_user_request, "newR in ICAPModXact");
    }
}

void ICAPModXact::decideOnParsingBody() {
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

void ICAPModXact::parseBody()
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

    // TODO: expose BodyPipe::putSize() to make this check simpler and clearer
    if (adapted.body_pipe->buf().contentSize() > 0) // parsed something sometime
        disableBypass("sent adapted content");

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

void ICAPModXact::stopParsing()
{
    if (state.parsing == State::psDone)
        return;

    debugs(93, 7, "ICAPModXact will no longer parse" << status());

    delete bodyParser;

    bodyParser = NULL;

    state.parsing = State::psDone;
}

// HTTP side added virgin body data
void ICAPModXact::noteMoreBodyDataAvailable(BodyPipe &)
{
    ICAPXaction_Enter(noteMoreBodyDataAvailable);

    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();

    ICAPXaction_Exit();
}

// HTTP side sent us all virgin info
void ICAPModXact::noteBodyProductionEnded(BodyPipe &)
{
    ICAPXaction_Enter(noteBodyProductionEnded);

    Must(virgin.body_pipe->productionEnded());

    // push writer and sender in case we were waiting for the last-chunk
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();

    ICAPXaction_Exit();
}

// body producer aborted, but the initiator may still want to know 
// the answer, even though the HTTP message has been truncated
void ICAPModXact::noteBodyProducerAborted(BodyPipe &)
{
    ICAPXaction_Enter(noteBodyProducerAborted);

    Must(virgin.body_pipe->productionEnded());

    // push writer and sender in case we were waiting for the last-chunk
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();

    ICAPXaction_Exit();
}

// adapted body consumer wants more adapted data and 
// possibly freed some buffer space
void ICAPModXact::noteMoreBodySpaceAvailable(BodyPipe &)
{
    ICAPXaction_Enter(noteMoreBodySpaceAvailable);

    if (state.sending == State::sendingVirgin)
        echoMore();
    else if (state.sending == State::sendingAdapted)
        parseMore();
    else
        Must(state.sending == State::sendingUndecided);

    ICAPXaction_Exit();
}

// adapted body consumer aborted
void ICAPModXact::noteBodyConsumerAborted(BodyPipe &)
{
    ICAPXaction_Enter(noteBodyConsumerAborted);

    mustStop("adapted body consumer aborted");

    ICAPXaction_Exit();
}

// internal cleanup
void ICAPModXact::swanSong()
{
    debugs(93, 5, HERE << "swan sings" << status());

    stopWriting(false);
    stopSending(false);

    if (icapReply) {
        delete icapReply;
        icapReply = NULL;
    }

    ICAPXaction::swanSong();
}

void ICAPModXact::makeRequestHeaders(MemBuf &buf)
{
    /*
     * XXX These should use HttpHdr interfaces instead of Printfs
     */
    const ICAPServiceRep &s = service();
    buf.Printf("%s %s ICAP/1.0\r\n", s.methodStr(), s.uri.buf());
    buf.Printf("Host: %s:%d\r\n", s.host.buf(), s.port);
    buf.Printf("Date: %s\r\n", mkrfc1123(squid_curtime));

    if (!TheICAPConfig.reuse_connections)
        buf.Printf("Connection: close\r\n");

    buf.Printf("Encapsulated: ");

    MemBuf httpBuf;

    httpBuf.init();

    // build HTTP request header, if any
    ICAP::Method m = s.method;

    const HttpRequest *request = virgin.cause ?
        virgin.cause :
        dynamic_cast<const HttpRequest*>(virgin.header);

    // to simplify, we could assume that request is always available

    String urlPath;
    if (request) {
        urlPath = request->urlpath;
        if (ICAP::methodRespmod == m)
            encapsulateHead(buf, "req-hdr", httpBuf, request);
        else
        if (ICAP::methodReqmod == m)
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

    if (TheICAPConfig.send_client_ip && request)
        if (request->client_addr.s_addr != any_addr.s_addr &&
            request->client_addr.s_addr != no_addr.s_addr)
            buf.Printf("X-Client-IP: %s\r\n", inet_ntoa(request->client_addr));

    if (TheICAPConfig.send_client_username && request)
        makeUsernameHeader(request, buf);

    // fprintf(stderr, "%s\n", buf.content());

    buf.append(ICAP::crlf, 2); // terminate ICAP header

    // start ICAP request body with encapsulated HTTP headers
    buf.append(httpBuf.content(), httpBuf.contentSize());

    httpBuf.clean();
}

void ICAPModXact::makeUsernameHeader(const HttpRequest *request, MemBuf &buf) {
    if (const AuthUserRequest *auth = request->auth_user_request) {
        if (char const *name = auth->username()) {
            const char *value = TheICAPConfig.client_username_encode ?
                base64_encode(name) : name;
            buf.Printf("%s: %s\r\n", TheICAPConfig.client_username_header,
                value);
        }
    }
}

void ICAPModXact::encapsulateHead(MemBuf &icapBuf, const char *section, MemBuf &httpBuf, const HttpMsg *head)
{
    // update ICAP header
    icapBuf.Printf("%s=%d, ", section, (int) httpBuf.contentSize());

    // pack HTTP head
    packHead(httpBuf, head);
}

void ICAPModXact::packHead(MemBuf &httpBuf, const HttpMsg *head)
{
    Packer p;
    packerToMemInit(&p, &httpBuf);
    head->packInto(&p, true);
    packerClean(&p);
}

// decides whether to offer a preview and calculates its size
void ICAPModXact::decideOnPreview()
{
    if (!TheICAPConfig.preview_enable) {
        debugs(93, 5, HERE << "preview disabled by squid.conf");
        return;
    }

    const HttpRequest *request = virgin.cause ?
        virgin.cause :
        dynamic_cast<const HttpRequest*>(virgin.header);
    const String urlPath = request ? request->urlpath : String();
    size_t wantedSize;
    if (!service().wantsPreview(urlPath, wantedSize)) {
        debugs(93, 5, "ICAPModXact should not offer preview for " << urlPath);
        return;
    }

    // we decided to do preview, now compute its size

    Must(wantedSize >= 0);

    // cannot preview more than we can backup
    size_t ad = XMIN(wantedSize, TheBackupLimit);

    if (!virginBody.expected())
        ad = 0;
    else
    if (virginBody.knownSize())
        ad = XMIN(static_cast<uint64_t>(ad), virginBody.size()); // not more than we have

    debugs(93, 5, "ICAPModXact should offer " << ad << "-byte preview " <<
           "(service wanted " << wantedSize << ")");

    preview.enable(ad);
    Must(preview.enabled());
}

// decides whether to allow 204 responses
bool ICAPModXact::shouldAllow204()
{
    if (!service().allows204())
        return false;

    return canBackupEverything();
}

// used by shouldAllow204 and decideOnRetries
bool ICAPModXact::canBackupEverything() const
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
void ICAPModXact::decideOnRetries()
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
void ICAPModXact::finishNullOrEmptyBodyPreview(MemBuf &buf)
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

void ICAPModXact::fillPendingStatus(MemBuf &buf) const
{
    ICAPXaction::fillPendingStatus(buf);

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
}

void ICAPModXact::fillDoneStatus(MemBuf &buf) const
{
    ICAPXaction::fillDoneStatus(buf);

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

bool ICAPModXact::gotEncapsulated(const char *section) const
{
    return icapReply->header.getByNameListMember("Encapsulated",
            section, ',').size() > 0;
}

// calculate whether there is a virgin HTTP body and
// whether its expected size is known
// TODO: rename because we do not just estimate
void ICAPModXact::estimateVirginBody()
{
    // note: lack of size info may disable previews and 204s

    HttpMsg *msg = virgin.header;
    Must(msg);

    method_t method;

    if (virgin.cause)
        method = virgin.cause->method;
    else
    if (HttpRequest *req = dynamic_cast<HttpRequest*>(msg))
        method = req->method;
    else
        method = METHOD_NONE;

    int64_t size;
    // expectingBody returns true for zero-sized bodies, but we will not
    // get a pipe for that body, so we treat the message as bodyless
    if (method != METHOD_NONE && msg->expectingBody(method, size) && size) {
        debugs(93, 6, "ICAPModXact expects virgin body from " << 
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
        debugs(93, 6, "ICAPModXact does not expect virgin body");
        Must(msg->body_pipe == NULL);
        checkConsuming();
    }
}

void ICAPModXact::makeAdaptedBodyPipe(const char *what) {
    Must(!adapted.body_pipe);
    Must(!adapted.header->body_pipe);
    adapted.header->body_pipe = new BodyPipe(this);
    adapted.body_pipe = adapted.header->body_pipe;
    debugs(93, 7, HERE << "will supply " << what << " via " <<
        adapted.body_pipe << " pipe");
}


// TODO: Move SizedEstimate, MemBufBackup, and ICAPPreview elsewhere

SizedEstimate::SizedEstimate()
        : theData(dtUnexpected)
{}

void SizedEstimate::expect(int64_t aSize)
{
    theData = (aSize >= 0) ? aSize : (int64_t)dtUnknown;
}

bool SizedEstimate::expected() const
{
    return theData != dtUnexpected;
}

bool SizedEstimate::knownSize() const
{
    Must(expected());
    return theData != dtUnknown;
}

uint64_t SizedEstimate::size() const
{
    Must(knownSize());
    return static_cast<uint64_t>(theData);
}



VirginBodyAct::VirginBodyAct(): theStart(0), theState(stUndecided)
{}

void VirginBodyAct::plan()
{
    Must(!disabled());
    Must(!theStart); // not started
    theState = stActive;
}

void VirginBodyAct::disable()
{
    theState = stDisabled;
}

void VirginBodyAct::progress(size_t size)
{
    Must(active());
    Must(size >= 0);
    theStart += static_cast<int64_t>(size);
}

uint64_t VirginBodyAct::offset() const
{
    Must(active());
    return static_cast<uint64_t>(theStart);
}


ICAPPreview::ICAPPreview(): theWritten(0), theAd(0), theState(stDisabled)
{}

void ICAPPreview::enable(size_t anAd)
{
    // TODO: check for anAd not exceeding preview size limit
    Must(anAd >= 0);
    Must(!enabled());
    theAd = anAd;
    theState = stWriting;
}

bool ICAPPreview::enabled() const
{
    return theState != stDisabled;
}

size_t ICAPPreview::ad() const
{
    Must(enabled());
    return theAd;
}

bool ICAPPreview::done() const
{
    Must(enabled());
    return theState >= stIeof;
}

bool ICAPPreview::ieof() const
{
    Must(enabled());
    return theState == stIeof;
}

size_t ICAPPreview::debt() const
{
    Must(enabled());
    return done() ? 0 : (theAd - theWritten);
}

void ICAPPreview::wrote(size_t size, bool wroteEof)
{
    Must(enabled());

    theWritten += size;

	Must(theWritten <= theAd);

	if (wroteEof)
		theState = stIeof; // written size is irrelevant
	else
    if (theWritten >= theAd)
        theState = stDone;
}

bool ICAPModXact::fillVirginHttpHeader(MemBuf &mb) const
{
    if (virgin.header == NULL)
        return false;

    virgin.header->firstLineBuf(mb);

    return true;
}


/* ICAPModXactLauncher */

ICAPModXactLauncher::ICAPModXactLauncher(ICAPInitiator *anInitiator, HttpMsg *virginHeader, HttpRequest *virginCause, ICAPServiceRep::Pointer &aService):
    ICAPLauncher("ICAPModXactLauncher", anInitiator, aService)
{
    virgin.setHeader(virginHeader);
    virgin.setCause(virginCause);
}

ICAPXaction *ICAPModXactLauncher::createXaction()
{
    return new ICAPModXact(this, virgin.header, virgin.cause, theService);
}

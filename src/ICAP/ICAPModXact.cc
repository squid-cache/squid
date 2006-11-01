/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "MsgPipe.h"
#include "MsgPipeData.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ICAPServiceRep.h"
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

// TODO: doneSending()/doneReceving() data members should probably be in sync
// with this->adapted/virgin pointers. Make adapted/virgin methods?

// TODO: replace gotEncapsulated() with something faster; we call it often

CBDATA_CLASS_INIT(ICAPModXact);

static const size_t TheBackupLimit = ICAP::MsgPipeBufSizeMax;

extern ICAPConfig TheICAPConfig;


ICAPModXact::State::State()
{
    memset(this, sizeof(*this), 0);
}

ICAPModXact::ICAPModXact(): ICAPXaction("ICAPModXact"),
        self(NULL), virgin(NULL), adapted(NULL),
        icapReply(NULL), virginConsumed(0),
        bodyParser(NULL)
{}

void ICAPModXact::init(ICAPServiceRep::Pointer &aService, MsgPipe::Pointer &aVirgin, MsgPipe::Pointer &anAdapted, Pointer &aSelf)
{
    assert(!self.getRaw() && !virgin.getRaw() && !adapted.getRaw());
    assert(aSelf.getRaw() && aVirgin.getRaw() && anAdapted.getRaw());

    self = aSelf;
    service(aService);

    virgin = aVirgin;
    adapted = anAdapted;

    // receiving end
    virgin->sink = this; // should be 'self' and refcounted
    // virgin pipe data is initiated by the source

    // sending end
    adapted->source = this; // should be 'self' and refcounted
    adapted->data = new MsgPipeData;

    adapted->data->body = new MemBuf; // XXX: make body a non-pointer?
    adapted->data->body->init(ICAP::MsgPipeBufSizeMin, ICAP::MsgPipeBufSizeMax);
    // headers are initialized when we parse them

    // writing and reading ends are handled by ICAPXaction

    // encoding
    // nothing to do because we are using temporary buffers

    // parsing
    icapReply = new HttpReply;
    icapReply->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    // XXX: make sure stop() cleans all buffers
}

// HTTP side starts sending virgin data
void ICAPModXact::noteSourceStart(MsgPipe *p)
{
    ICAPXaction_Enter(noteSourceStart);

    // make sure TheBackupLimit is in-sync with the buffer size
    Must(TheBackupLimit <= static_cast<size_t>(virgin->data->body->max_capacity));

    estimateVirginBody(); // before virgin disappears!

    // it is an ICAP violation to send request to a service w/o known OPTIONS

    if (service().up())
        startWriting();
    else
        waitForService();

    // XXX: but this has to be here to catch other errors. Thus, if
    // commConnectStart in startWriting fails, we may get here
    //_after_ the object got destroyed. Somebody please fix commConnectStart!
    ICAPXaction_Exit();
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
    debugs(93, 7, "ICAPModXact will wait for the ICAP service " << status());
    state.serviceWaiting = true;
    service().callWhenReady(&ICAPModXact_noteServiceReady, this);
}

void ICAPModXact::noteServiceReady()
{
    ICAPXaction_Enter(noteServiceReady);

    Must(state.serviceWaiting);
    state.serviceWaiting = false;

    Must(service().up());

    startWriting();

    ICAPXaction_Exit();
}

void ICAPModXact::startWriting()
{
    state.writing = State::writingConnect;
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
    debugs(93, 9, "ICAPModXact ICAP status " << status() << " will write:\n" <<
           (requestBuf.terminate(), requestBuf.content()));

    // write headers
    state.writing = State::writingHeaders;
    scheduleWrite(requestBuf);
    virgin->sendSinkNeed();
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

    if (virginBody.expected()) {
        state.writing = preview.enabled() ?
                        State::writingPreview : State::writingPrime;
        virginWriteClaim.protectAll();
        writeMore();
    } else {
        stopWriting(true);
    }
}

void ICAPModXact::writeMore()
{
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
        writePriviewBody();
        return;

    case State::writingPrime:
        writePrimeBody();
        return;

    default:
        throw TexcHere("ICAPModXact in bad writing state");
    }
}

void ICAPModXact::writePriviewBody()
{
    debugs(93, 8, "ICAPModXact will write Preview body " << status());
    Must(state.writing == State::writingPreview);

    MsgPipeData::Body *body = virgin->data->body;
    const size_t size = XMIN(preview.debt(), (size_t)body->contentSize());
    writeSomeBody("preview body", size);

    // change state once preview is written

    if (preview.done()) {
        debugs(93, 7, "ICAPModXact wrote entire Preview body " << status());

        if (preview.ieof())
            stopWriting(true);
        else
            state.writing = State::writingPaused;
    }
}

void ICAPModXact::writePrimeBody()
{
    Must(state.writing == State::writingPrime);
    Must(virginWriteClaim.active());

    MsgPipeData::Body *body = virgin->data->body;
    const size_t size = body->contentSize();
    writeSomeBody("prime virgin body", size);

    if (state.doneReceiving && claimSize(virginWriteClaim) <= 0) {
        debugs(93, 5, HERE << "state.doneReceiving is set and wrote all");
        stopWriting(true);
    }
}

void ICAPModXact::writeSomeBody(const char *label, size_t size)
{
    Must(!writer && state.writing < state.writingAlmostDone);
    debugs(93, 8, HERE << "will write up to " << size << " bytes of " <<
           label);

    MemBuf writeBuf; // TODO: suggest a min size based on size and lastChunk

    writeBuf.init(); // note: we assume that last-chunk will fit

    const size_t writableSize = claimSize(virginWriteClaim);
    const size_t chunkSize = XMIN(writableSize, size);

    if (chunkSize) {
        debugs(93, 7, HERE << "will write " << chunkSize <<
               "-byte chunk of " << label);
    } else {
        debugs(93, 7, "ICAPModXact has no writable " << label << " content");
    }

    moveRequestChunk(writeBuf, chunkSize);

    const bool lastChunk =
        (state.writing == State::writingPreview && preview.done()) ||
        (state.doneReceiving && claimSize(virginWriteClaim) <= 0);

    if (lastChunk && virginBody.expected()) {
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

void ICAPModXact::moveRequestChunk(MemBuf &buf, size_t chunkSize)
{
    if (chunkSize > 0) {
        openChunk(buf, chunkSize, false);
        buf.append(claimContent(virginWriteClaim), chunkSize);
        closeChunk(buf);

        virginWriteClaim.release(chunkSize);
        virginConsume();
    }

    if (state.writing == State::writingPreview) {
        // even if we are doneReceiving, we may not have written everything
        const bool wroteEof = state.doneReceiving &&
            claimSize(virginWriteClaim) <= 0;
        preview.wrote(chunkSize, wroteEof); // even if wrote nothing
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

size_t ICAPModXact::claimSize(const MemBufClaim &claim) const
{
    Must(claim.active());
    const size_t start = claim.offset();
    const size_t end = virginConsumed + virgin->data->body->contentSize();
    Must(virginConsumed <= start && start <= end);
    return end - start;
}

const char *ICAPModXact::claimContent(const MemBufClaim &claim) const
{
    Must(claim.active());
    const size_t start = claim.offset();
    Must(virginConsumed <= start);
    return virgin->data->body->content() + (start - virginConsumed);
}

void ICAPModXact::virginConsume()
{
    MemBuf &buf = *virgin->data->body;
    const size_t have = static_cast<size_t>(buf.contentSize());
    const size_t end = virginConsumed + have;
    size_t offset = end;

    if (virginWriteClaim.active())
        offset = XMIN(virginWriteClaim.offset(), offset);

    if (virginSendClaim.active())
        offset = XMIN(virginSendClaim.offset(), offset);

    Must(virginConsumed <= offset && offset <= end);

    if (const size_t size = offset - virginConsumed) {
        debugs(93, 8, HERE << "consuming " << size << " out of " << have <<
               " virgin body bytes");
        buf.consume(size);
        virginConsumed += size;

        if (!state.doneReceiving)
            virgin->sendSinkNeed();
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
            debugs(93, 7, HERE << "will wait for the last write " << status());
            state.writing = State::writingAlmostDone; // may already be set
            return;
        }
        debugs(93, 2, HERE << "will NOT wait for the last write " << status());

        // Comm does not have an interface to clear the writer callback nicely,
        // but without clearing the writer we cannot recycle the connection.
        // We prevent connection reuse and hope that we can handle a callback
        // call at any time. Somebody should either fix this code or add
        // comm_remove_write_handler() to comm API.
        reuseConnection = false;
    }

    debugs(93, 7, HERE << "will no longer write " << status());
    state.writing = State::writingReallyDone;

    virginWriteClaim.disable();

    virginConsume();
}

void ICAPModXact::stopBackup()
{
    if (!virginSendClaim.active())
        return;

    debugs(93, 7, "ICAPModXact will no longer backup " << status());

    virginSendClaim.disable();

    virginConsume();
}

bool ICAPModXact::doneAll() const
{
    return ICAPXaction::doneAll() && !state.serviceWaiting &&
           state.doneReceiving && doneSending() &&
           doneReading() && state.doneWriting();
}

void ICAPModXact::startReading()
{
    Must(connection >= 0);
    Must(!reader);
    Must(adapted.getRaw());
    Must(adapted->data);
    Must(adapted->data->body);

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
    if (!adapted->data->body->hasPotentialSpace()) {
        debugs(93,3,HERE << "not reading because ICAP reply buffer is full");
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
    Must(virginSendClaim.active());

    MemBuf &from = *virgin->data->body;
    MemBuf &to = *adapted->data->body;

    const size_t sizeMax = claimSize(virginSendClaim);
    const size_t size = XMIN(static_cast<size_t>(to.potentialSpaceSize()),
                             sizeMax);
    debugs(93, 5, "ICAPModXact echos " << size << " out of " << sizeMax <<
           " bytes");

    if (size > 0) {
        to.append(claimContent(virginSendClaim), size);
        virginSendClaim.release(size);
        virginConsume();
        adapted->sendSourceProgress();
    }

    if (state.doneReceiving && claimSize(virginSendClaim) <= 0) {
        debugs(93, 5, "ICAPModXact echoed all " << status());
        stopSending(true);
    } else {
        debugs(93, 5, "ICAPModXact has " << from.contentSize() << " bytes " <<
               "and expects more to echo " << status());
        virgin->sendSinkNeed(); // TODO: timeout if sink is broken
    }
}

bool ICAPModXact::doneSending() const
{
    Must((state.sending == State::sendingDone) == (!adapted));
    return state.sending == State::sendingDone;
}

void ICAPModXact::stopSending(bool nicely)
{
    if (doneSending())
        return;

    if (state.sending != State::sendingUndecided) {
        debugs(93, 7, "ICAPModXact will no longer send " << status());

        if (nicely)
            adapted->sendSourceFinish();
        else
            adapted->sendSourceAbort();
    } else {
        debugs(93, 7, "ICAPModXact will not start sending " << status());
        adapted->sendSourceAbort(); // or the sink may wait forever
    }

    state.sending = State::sendingDone;

    adapted = NULL; // refcounted
}

void ICAPModXact::stopReceiving()
{
    // stopSending NULLifies adapted but we do not NULLify virgin.
    // This is assymetric because we want to keep virgin->data even
    // though we are not expecting any more virgin->data->body.
    // TODO: can we cache just the needed headers info instead?

    // If they closed first, there is not point (or means) to notify them.

    if (state.doneReceiving)
        return;

    // There is no sendSinkFinished() to notify the other side.
    debugs(93, 7, "ICAPModXact will not receive " << status());

    state.doneReceiving = true;
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

// note that allocation for echoing is done in handle204NoContent()
void ICAPModXact::maybeAllocateHttpMsg()
{
    if (adapted->data->header) // already allocated
        return;

    if (gotEncapsulated("res-hdr")) {
        adapted->data->setHeader(new HttpReply);
    } else if (gotEncapsulated("req-hdr")) {
        adapted->data->setHeader(new HttpRequest);
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

    adapted->sendSourceStart();

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

    // TODO: Consider applying a Squid 2.5 patch to recognize 201 responses
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
    Must(preview.enabled() && preview.done() && !preview.ieof());
    Must(virginSendClaim.active());

    if (virginSendClaim.limited()) // preview only
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
}

void ICAPModXact::handle204NoContent()
{
    stopParsing();
    Must(virginSendClaim.active());
    virginSendClaim.protectAll(); // extends protection if needed
    state.sending = State::sendingVirgin;

    // We want to clone the HTTP message, but we do not want
    // to copy non-HTTP state parts that HttpMsg kids carry in them.
    // Thus, we cannot use a smart pointer, copy constructor, or equivalent.
    // Instead, we simply write the HTTP message and "clone" it by parsing.

    HttpMsg *oldHead = virgin->data->header;
    debugs(93, 7, "ICAPModXact cloning virgin message " << oldHead);

    MemBuf httpBuf;

    // write the virgin message into a memory buffer
    httpBuf.init();
    packHead(httpBuf, oldHead);

    // allocate the adapted message and copy metainfo
    Must(!adapted->data->header);
    HttpMsg *newHead = NULL;
    if (const HttpRequest *oldR = dynamic_cast<const HttpRequest*>(oldHead)) {
        HttpRequest *newR = new HttpRequest;
        newR->client_addr = oldR->client_addr;
        newHead = newR;
    } else
    if (dynamic_cast<const HttpReply*>(oldHead))
        newHead = new HttpReply;
    Must(newHead);

    adapted->data->setHeader(newHead);

    // parse the buffer back
    http_status error = HTTP_STATUS_NONE;

    Must(newHead->parse(&httpBuf, true, &error));

    Must(newHead->hdr_sz == httpBuf.contentSize()); // no leftovers

    httpBuf.clean();

    debugs(93, 7, "ICAPModXact cloned virgin message " << oldHead << " to " << newHead);
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

        if (!parseHead(adapted->data->header))
            return; // need more header data
    }

    state.parsing = State::psBody;
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

void ICAPModXact::parseBody()
{
    Must(state.parsing == State::psBody);

    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " body bytes to parse");

    if (gotEncapsulated("res-body") || gotEncapsulated("req-body")) {
        if (!parsePresentBody()) // need more body data
            return;
    } else {
        debugs(93, 5, HERE << "not expecting a body");
    }

    stopParsing();
    stopSending(true);
}

// returns true iff complete body was parsed
bool ICAPModXact::parsePresentBody()
{
    if (!bodyParser)
        bodyParser = new ChunkedCodingParser;

    // the parser will throw on errors
    const bool parsed = bodyParser->parse(&readBuf, adapted->data->body);

    adapted->sendSourceProgress(); // TODO: do not send if parsed nothing

    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " body bytes after " <<
           "parse; parsed all: " << parsed);

    if (parsed)
        return true;

    debugs(93,3,HERE << this << " needsMoreData = " << bodyParser->needsMoreData());

    if (bodyParser->needsMoreData()) {
        debugs(93,3,HERE << this);
        Must(mayReadMore());
        readMore();
    }

    if (bodyParser->needsMoreSpace()) {
        Must(!doneSending()); // can hope for more space
        Must(adapted->data->body->hasContent()); // paranoid
        // TODO: there should be a timeout in case the sink is broken.
    }

    return false;
}

void ICAPModXact::stopParsing()
{
    if (state.parsing == State::psDone)
        return;

    debugs(93, 7, "ICAPModXact will no longer parse " << status());

    delete bodyParser;

    bodyParser = NULL;

    state.parsing = State::psDone;
}

// HTTP side added virgin body data
void ICAPModXact::noteSourceProgress(MsgPipe *p)
{
    ICAPXaction_Enter(noteSourceProgress);

    Must(!state.doneReceiving);
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();

    ICAPXaction_Exit();
}

// HTTP side sent us all virgin info
void ICAPModXact::noteSourceFinish(MsgPipe *p)
{
    ICAPXaction_Enter(noteSourceFinish);

    Must(!state.doneReceiving);
    stopReceiving();

    // push writer and sender in case we were waiting for the last-chunk
    writeMore();

    if (state.sending == State::sendingVirgin)
        echoMore();

    ICAPXaction_Exit();
}

// HTTP side is aborting
void ICAPModXact::noteSourceAbort(MsgPipe *p)
{
    ICAPXaction_Enter(noteSourceAbort);

    Must(!state.doneReceiving);
    stopReceiving();
    mustStop("HTTP source quit");

    ICAPXaction_Exit();
}

// HTTP side wants more adapted data and possibly freed some buffer space
void ICAPModXact::noteSinkNeed(MsgPipe *p)
{
    ICAPXaction_Enter(noteSinkNeed);

    if (state.sending == State::sendingVirgin)
        echoMore();
    else if (state.sending == State::sendingAdapted)
        parseMore();
    else
        Must(state.sending == State::sendingUndecided);

    ICAPXaction_Exit();
}

// HTTP side aborted
void ICAPModXact::noteSinkAbort(MsgPipe *p)
{
    ICAPXaction_Enter(noteSinkAbort);

    mustStop("HTTP sink quit");

    ICAPXaction_Exit();
}

// internal cleanup
void ICAPModXact::doStop()
{
    debugs(93, 5, HERE << "doStop() called");
    ICAPXaction::doStop();

    stopWriting(false);
    stopBackup();

    if (icapReply) {
        delete icapReply;
        icapReply = NULL;
    }

    stopSending(false);

    // see stopReceiving() for reasons it cannot NULLify virgin there

    if (virgin != NULL) {
        if (!state.doneReceiving)
            virgin->sendSinkAbort();
        else
            virgin->sink = NULL;

        virgin = NULL; // refcounted
    }

    if (self != NULL) {
        Pointer s = self;
        self = NULL;
        ICAPNoteXactionDone(s);
        /* this object may be destroyed when 's' is cleared */
    }
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

    const HttpRequest *request = virgin->data->cause ?
                                 virgin->data->cause :
                                 dynamic_cast<const HttpRequest*>(virgin->data->header);

    // to simplify, we could we assume that request is always available

    String urlPath;
    if (request) {
        urlPath = request->urlpath;
        if (ICAP::methodRespmod == m)
            encapsulateHead(buf, "req-hdr", httpBuf, request);
        else
        if (ICAP::methodReqmod == m)
            encapsulateHead(buf, "req-hdr", httpBuf, virgin->data->header);
    }

    if (ICAP::methodRespmod == m)
        if (const MsgPipeData::Header *prime = virgin->data->header)
            encapsulateHead(buf, "res-hdr", httpBuf, prime);

    if (!virginBody.expected())
        buf.Printf("null-body=%d", (int) httpBuf.contentSize());
    else if (ICAP::methodReqmod == m)
        buf.Printf("req-body=%d", (int) httpBuf.contentSize());
    else
        buf.Printf("res-body=%d", (int) httpBuf.contentSize());

    buf.append(ICAP::crlf, 2); // terminate Encapsulated line

    if (shouldPreview(urlPath)) {
        buf.Printf("Preview: %d\r\n", (int)preview.ad());
        virginSendClaim.protectUpTo(preview.ad());
    }

    if (shouldAllow204()) {
        buf.Printf("Allow: 204\r\n");
        // be robust: do not rely on the expected body size
        virginSendClaim.protectAll();
    }

    if (TheICAPConfig.send_client_ip && request)
        if (request->client_addr.s_addr != any_addr.s_addr &&
            request->client_addr.s_addr != no_addr.s_addr)
            buf.Printf("X-Client-IP: %s\r\n", inet_ntoa(request->client_addr));

    if (TheICAPConfig.send_client_username && request)
        if (request->auth_user_request)
            if (request->auth_user_request->username())
                buf.Printf("X-Client-Username: %s\r\n", request->auth_user_request->username());

    // fprintf(stderr, "%s\n", buf.content());

    buf.append(ICAP::crlf, 2); // terminate ICAP header

    // start ICAP request body with encapsulated HTTP headers
    buf.append(httpBuf.content(), httpBuf.contentSize());

    httpBuf.clean();
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
bool ICAPModXact::shouldPreview(const String &urlPath)
{
    size_t wantedSize;

    if (!TheICAPConfig.preview_enable) {
        debugs(93, 5, HERE << "preview disabled by squid.conf");
        return false;
    }

    if (!service().wantsPreview(urlPath, wantedSize)) {
        debugs(93, 5, "ICAPModXact should not offer preview for " << urlPath);
        return false;
    }

    Must(wantedSize >= 0);

    // cannot preview more than we can backup
    size_t ad = XMIN(wantedSize, TheBackupLimit);

    if (virginBody.expected() && virginBody.knownSize())
        ad = XMIN(ad, virginBody.size()); // not more than we have
    else
        ad = 0; // questionable optimization?

    debugs(93, 5, "ICAPModXact should offer " << ad << "-byte preview " <<
           "(service wanted " << wantedSize << ")");

    preview.enable(ad);

    return preview.enabled();
}

// decides whether to allow 204 responses
bool ICAPModXact::shouldAllow204()
{
    if (!service().allows204())
        return false;

    if (!virginBody.expected())
        return true; // no body means no problems with supporting 204s.

    // if there is a body, make sure we can backup it all

    if (!virginBody.knownSize())
        return false;

    // or should we have a different backup limit?
    // note that '<' allows for 0-termination of the "full" backup buffer
    return virginBody.size() < TheBackupLimit;
}

void ICAPModXact::fillPendingStatus(MemBuf &buf) const
{
    ICAPXaction::fillPendingStatus(buf);

    if (state.serviceWaiting)
        buf.append("U", 1);

    if (!state.doneReceiving)
        buf.append("R", 1);

    if (!doneReading())
        buf.append("r", 1);

    if (!state.doneWriting() && state.writing != State::writingInit)
        buf.Printf("w(%d)", state.writing);

    if (preview.enabled()) {
        if (!preview.done())
            buf.Printf("P(%d)", (int) preview.debt());
    }

    if (virginSendClaim.active())
        buf.append("B", 1);

    if (!state.doneParsing() && state.parsing != State::psIcapHeader)
        buf.Printf("p(%d)", state.parsing);

    if (!doneSending() && state.sending != State::sendingUndecided)
        buf.Printf("S(%d)", state.sending);
}

void ICAPModXact::fillDoneStatus(MemBuf &buf) const
{
    ICAPXaction::fillDoneStatus(buf);

    if (state.doneReceiving)
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
void ICAPModXact::estimateVirginBody()
{
    // note: defaults should be fine but will disable previews and 204s

    Must(virgin != NULL && virgin->data->header);

    method_t method;

    if (virgin->data->cause)
        method = virgin->data->cause->method;
    else
        if (HttpRequest *req = dynamic_cast<HttpRequest*>(virgin->data->
                               header))
            method = req->method;
        else
            return;

    ssize_t size;
    if (virgin->data->header->expectingBody(method, size)) {
        virginBody.expect(size)
        ;
        debugs(93, 6, "ICAPModXact expects virgin body; size: " << size);
    } else {
        debugs(93, 6, "ICAPModXact does not expect virgin body");
    }
}


// TODO: Move SizedEstimate, MemBufBackup, and ICAPPreview elsewhere

SizedEstimate::SizedEstimate()
        : theData(dtUnexpected)
{}

void SizedEstimate::expect(ssize_t aSize)
{
    theData = (aSize >= 0) ? aSize : (ssize_t)dtUnknown;
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

size_t SizedEstimate::size() const
{
    Must(knownSize());
    return static_cast<size_t>(theData);
}



MemBufClaim::MemBufClaim(): theStart(-1), theGoal(-1)
{}

void MemBufClaim::protectAll()
{
    if (theStart < 0)
        theStart = 0;

    theGoal = -1; // no specific goal
}

void MemBufClaim::protectUpTo(size_t aGoal)
{
    if (theStart < 0)
        theStart = 0;

    Must(aGoal >= 0);

    theGoal = (theGoal < 0) ? static_cast<ssize_t>(aGoal) :
              XMIN(static_cast<ssize_t>(aGoal), theGoal);
}

void MemBufClaim::disable()
{
    theStart = -1;
}

void MemBufClaim::release(size_t size)
{
    Must(active());
    Must(size >= 0);
    theStart += static_cast<ssize_t>(size);

    if (limited() && theStart >= theGoal)
        disable();
}

size_t MemBufClaim::offset() const
{
    Must(active());
    return static_cast<size_t>(theStart);
}

bool MemBufClaim::limited() const
{
    Must(active());
    return theGoal >= 0;
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

    if (theWritten >= theAd)
        theState = stDone; // wroteEof is irrelevant
    else
        if (wroteEof)
            theState = stIeof;
}

bool ICAPModXact::fillVirginHttpHeader(MemBuf &mb) const
{
    if (virgin == NULL)
        return false;

    if (virgin->data == NULL)
        return false;

    if (virgin->data->header == NULL)
        return false;

    virgin->data->header->firstLineBuf(mb);

    return true;
}

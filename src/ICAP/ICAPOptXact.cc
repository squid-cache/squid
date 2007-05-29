/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpReply.h"

#include "ICAPOptXact.h"
#include "ICAPOptions.h"
#include "TextException.h"

CBDATA_CLASS_INIT(ICAPOptXact);
CBDATA_CLASS_INIT(ICAPOptXactLauncher);


ICAPOptXact::ICAPOptXact(ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService):
    ICAPXaction("ICAPOptXact", anInitiator, aService)
{
}

void ICAPOptXact::start()
{
    ICAPXaction::start();

    openConnection();
}

void ICAPOptXact::handleCommConnected()
{
    scheduleRead();

    MemBuf requestBuf;
    requestBuf.init();
    makeRequest(requestBuf);
    debugs(93, 9, "ICAPOptXact request " << status() << ":\n" <<
           (requestBuf.terminate(), requestBuf.content()));

    scheduleWrite(requestBuf);
}

void ICAPOptXact::makeRequest(MemBuf &buf)
{
    const ICAPServiceRep &s = service();
    buf.Printf("OPTIONS %s ICAP/1.0\r\n", s.uri.buf());
    buf.Printf("Host: %s:%d\r\n", s.host.buf(), s.port);
    buf.append(ICAP::crlf, 2);
}

void ICAPOptXact::handleCommWrote(size_t size)
{
    debugs(93, 9, "ICAPOptXact finished writing " << size <<
           "-byte request " << status());
}

// comm module read a portion of the ICAP response for us
void ICAPOptXact::handleCommRead(size_t)
{
    if (HttpMsg *r = parseResponse()) {
        sendAnswer(r);
        Must(done()); // there should be nothing else to do
        return;
    }

    scheduleRead();
}

HttpMsg *ICAPOptXact::parseResponse()
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " bytes to parse" <<
           status());
    debugs(93, 5, HERE << "\n" << readBuf.content());

    HttpReply *r = new HttpReply;
    r->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    if (!parseHttpMsg(r)) { // throws on errors
        delete r;
        return 0;
    }

    if (httpHeaderHasConnDir(&r->header, "close"))
        reuseConnection = false;

    return r;
}

/* ICAPOptXactLauncher */

ICAPOptXactLauncher::ICAPOptXactLauncher(ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService):
    ICAPLauncher("ICAPOptXactLauncher", anInitiator, aService)
{
}

ICAPXaction *ICAPOptXactLauncher::createXaction()
{
    return new ICAPOptXact(this, theService);
}

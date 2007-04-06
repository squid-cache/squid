/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpReply.h"

#include "ICAPOptXact.h"
#include "ICAPOptions.h"
#include "TextException.h"

CBDATA_CLASS_INIT(ICAPOptXact);

ICAPOptXact::ICAPOptXact(ICAPServiceRep::Pointer &aService, Callback *aCbAddr, void *aCbData):
    ICAPXaction("ICAPOptXact"),
    cbAddr(aCbAddr), cbData(cbdataReference(aCbData))
{
    Must(aCbAddr && aCbData);
    service(aService);
}

ICAPOptXact::~ICAPOptXact()
{
    if (cbAddr) {
        debugs(93, 1, HERE << "BUG: exiting without sending options");
        cbdataReferenceDone(cbData);
    }
}

void ICAPOptXact::start()
{
    ICAPXaction_Enter(start);

    ICAPXaction::start();

    Must(self != NULL); // set by AsyncStart;

    openConnection();

    ICAPXaction_Exit();
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
    if (ICAPOptions *options = parseResponse()) {
        sendOptions(options);
        Must(done()); // there should be nothing else to do
        return;
    }

    scheduleRead();
}

ICAPOptions *ICAPOptXact::parseResponse()
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

    ICAPOptions *options = new ICAPOptions;
    options->configure(r);

    delete r;

    return options;
}

void ICAPOptXact::swanSong() {
    if (cbAddr) {
        debugs(93, 3, HERE << "probably failed; sending NULL options");
        sendOptions(0);
    }
    ICAPXaction::swanSong();
}

void ICAPOptXact::sendOptions(ICAPOptions *options) {
    debugs(93, 3, HERE << "sending options " << options << " to " << cbData <<
        " at " << (void*)cbAddr << status());

    Must(cbAddr);
    Callback *addr = cbAddr;
    cbAddr = NULL; // in case the callback calls us or throws

    void *data = NULL;
    if (cbdataReferenceValidDone(cbData, &data))
        (*addr)(options, data); // callee takes ownership of the options
    else
        debugs(93, 2, HERE << "sending options " << options << " to " <<
            data << " failed" << status());
}

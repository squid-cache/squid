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

ICAPOptXact::ICAPOptXact(): ICAPXaction("ICAPOptXact"), options(NULL),
        cb(NULL), cbData(NULL)

{
    debug(93,9)("ICAPOptXact constructed, this=%p\n", this);
}

ICAPOptXact::~ICAPOptXact()
{
    Must(!options); // the caller must set to NULL
    debug(93,9)("ICAPOptXact destructed, this=%p\n", this);
}

void ICAPOptXact::start(ICAPServiceRep::Pointer &aService, Callback *aCb, void *aCbData)
{
    service(aService);

    Must(!cb && aCb && aCbData);
    cb = aCb;
    cbData = cbdataReference(aCbData);

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

void ICAPOptXact::doStop()
{
    ICAPXaction::doStop();

    if (Callback *call = cb) {
        cb = NULL;
        void *data = NULL;

        if (cbdataReferenceValidDone(cbData, &data)) {
            (*call)(this, data); // will delete us
            return;
        }
    }

    // get rid of options if we did call the callback
    delete options;

    options = NULL;
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
    if (parseResponse())
        Must(done()); // there should be nothing else to do
    else
        scheduleRead();
}

bool ICAPOptXact::parseResponse()
{
    HttpReply *r = new HttpReply;
    r->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    if (!parseHttpMsg(r)) {
        delete r;
        return false;
    }

    options = new ICAPOptions;

    options->configure(r);

    delete r;
    return true;
}

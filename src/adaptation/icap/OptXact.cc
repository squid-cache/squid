/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "comm.h"
#include "HttpReply.h"

#include "adaptation/icap/OptXact.h"
#include "adaptation/icap/Options.h"
#include "TextException.h"
#include "SquidTime.h"
#include "HttpRequest.h"

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, OptXact);
CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, OptXactLauncher);


Adaptation::Icap::OptXact::OptXact(Adaptation::Initiator *anInitiator, Adaptation::Icap::ServiceRep::Pointer &aService):
        AsyncJob("Adaptation::Icap::OptXact"),
        Adaptation::Icap::Xaction("Adaptation::Icap::OptXact", anInitiator, aService)
{
}

void Adaptation::Icap::OptXact::start()
{
    Adaptation::Icap::Xaction::start();

    openConnection();
}

void Adaptation::Icap::OptXact::handleCommConnected()
{
    scheduleRead();

    MemBuf requestBuf;
    requestBuf.init();
    makeRequest(requestBuf);
    debugs(93, 9, HERE << "request " << status() << ":\n" <<
           (requestBuf.terminate(), requestBuf.content()));
    icap_tio_start = current_time;
    scheduleWrite(requestBuf);
}

void Adaptation::Icap::OptXact::makeRequest(MemBuf &buf)
{
    const Adaptation::Service &s = service();
    const String uri = s.cfg().uri;
    buf.Printf("OPTIONS " SQUIDSTRINGPH " ICAP/1.0\r\n", SQUIDSTRINGPRINT(uri));
    const String host = s.cfg().host;
    buf.Printf("Host: " SQUIDSTRINGPH ":%d\r\n", SQUIDSTRINGPRINT(host), s.cfg().port);
    buf.append(ICAP::crlf, 2);

    // XXX: HttpRequest cannot fully parse ICAP Request-Line
    http_status status;
    Must(icapRequest->parse(&buf, true, &status) > 0);
}

void Adaptation::Icap::OptXact::handleCommWrote(size_t size)
{
    debugs(93, 9, HERE << "finished writing " << size <<
           "-byte request " << status());
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::OptXact::handleCommRead(size_t)
{
    if (HttpMsg *r = parseResponse()) {
        icap_tio_finish = current_time;
        setOutcome(xoOpt);
        sendAnswer(r);
        icapReply = HTTPMSGLOCK(dynamic_cast<HttpReply*>(r));
        Must(done()); // there should be nothing else to do
        return;
    }

    scheduleRead();
}

HttpMsg *Adaptation::Icap::OptXact::parseResponse()
{
    debugs(93, 5, HERE << "have " << readBuf.contentSize() << " bytes to parse" <<
           status());
    debugs(93, 5, HERE << "\n" << readBuf.content());

    HttpReply *r = HTTPMSGLOCK(new HttpReply);
    r->protoPrefix = "ICAP/"; // TODO: make an IcapReply class?

    if (!parseHttpMsg(r)) { // throws on errors
        HTTPMSGUNLOCK(r);
        return 0;
    }

    if (httpHeaderHasConnDir(&r->header, "close"))
        reuseConnection = false;

    return r;
}

void Adaptation::Icap::OptXact::swanSong()
{
    Adaptation::Icap::Xaction::swanSong();
}

void Adaptation::Icap::OptXact::finalizeLogInfo()
{
    //    al.cache.caddr = 0;
    al.icap.reqMethod = Adaptation::methodOptions;
    Adaptation::Icap::Xaction::finalizeLogInfo();
}

/* Adaptation::Icap::OptXactLauncher */

Adaptation::Icap::OptXactLauncher::OptXactLauncher(Adaptation::Initiator *anInitiator, Adaptation::ServicePointer aService):
        AsyncJob("Adaptation::Icap::OptXactLauncher"),
        Adaptation::Icap::Launcher("Adaptation::Icap::OptXactLauncher", anInitiator, aService)
{
}

Adaptation::Icap::Xaction *Adaptation::Icap::OptXactLauncher::createXaction()
{
    Adaptation::Icap::ServiceRep::Pointer s =
        dynamic_cast<Adaptation::Icap::ServiceRep*>(theService.getRaw());
    Must(s != NULL);
    return new Adaptation::Icap::OptXact(this, s);
}

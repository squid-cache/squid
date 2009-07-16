#include "adaptation/icap/History.h"
#include "squid.h"
#include "globals.h"
#include "SquidTime.h"

Adaptation::Icap::History::History(): mergeOfIcapHeaders(hoRequest),
    lastIcapHeader(hoRequest), logType(LOG_TAG_NONE), req_sz(0),
    pastTime(0), concurrencyLevel(0)
{
}

Adaptation::Icap::History::History(const Adaptation::Icap::History& ih)
{
    assign(ih);
}

Adaptation::Icap::History::~History()
{
    mergeOfIcapHeaders.clean();
    lastIcapHeader.clean();
    rfc931.clean();
#if USE_SSL
    ssluser.clean();
#endif 
    log_uri.clean();
}

void Adaptation::Icap::History::assign(const Adaptation::Icap::History& ih)
{
    mergeOfIcapHeaders.clean();
    mergeOfIcapHeaders.update(&ih.mergeOfIcapHeaders, NULL);
    lastIcapHeader.clean();
    lastIcapHeader.update(&ih.lastIcapHeader, NULL);
    rfc931 = ih.rfc931;

#if USE_SSL
    ssluser = ih.ssluser;
#endif

    logType = ih.logType;
    log_uri = ih.log_uri;
    req_sz = ih.req_sz;
    pastTime = ih.pastTime;
    currentStart = ih.currentStart;
    concurrencyLevel = ih.concurrencyLevel;
    debugs(93,7, HERE << this << " = " << &ih);
}

Adaptation::Icap::History& Adaptation::Icap::History::operator=(const History& ih)
{
    if (this != &ih)
        assign(ih);
    return *this;
}

void Adaptation::Icap::History::setIcapLastHeader(const HttpHeader * lih)
{
    lastIcapHeader.clean();
    lastIcapHeader.update(lih, NULL);
}

void Adaptation::Icap::History::mergeIcapHeaders(const HttpHeader * lih)
{
    mergeOfIcapHeaders.update(lih, NULL);
    mergeOfIcapHeaders.compact();
}

void Adaptation::Icap::History::start(const char *context) 
{
    if (!concurrencyLevel++)
        currentStart = current_time;

    debugs(93,4, HERE << "start " << context << " level=" << concurrencyLevel
        << " time=" << pastTime << ' ' << this);
}

void Adaptation::Icap::History::stop(const char *context) 
{
    if (!concurrencyLevel) {
        debugs(93,1, HERE << "Internal error: poor history accounting " << this);
        return;
    }

    const int current = currentTime();
    debugs(93,4, HERE << "stop " << context << " level=" << concurrencyLevel <<
        " time=" << pastTime << '+' << current << ' ' << this);
    
    if (!--concurrencyLevel)
        pastTime += current;
}

int Adaptation::Icap::History::processingTime() const
{
    const int total = pastTime + currentTime();
    debugs(93,7, HERE << " current total: " << total << ' ' << this);
    return total;
}

int Adaptation::Icap::History::currentTime() const
{
    return concurrencyLevel > 0 ?
        max(0, tvSubMsec(currentStart, current_time)) : 0;
}

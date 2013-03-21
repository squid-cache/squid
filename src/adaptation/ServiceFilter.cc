#include "squid.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "adaptation/ServiceFilter.h"

Adaptation::ServiceFilter::ServiceFilter(Method aMethod, VectPoint aPoint, HttpRequest *aReq, HttpReply *aRep):
        method(aMethod),
        point(aPoint),
        request(aReq),
        reply(aRep)
{
    if (reply)
        HTTPMSGLOCK(reply);

    // a lot of code assumes that there is always a virgin request or cause
    assert(request);
    HTTPMSGLOCK(request);
}

Adaptation::ServiceFilter::ServiceFilter(const ServiceFilter &f):
        method(f.method),
        point(f.point),
        request(f.request),
        reply(f.reply)
{
    if (request)
        HTTPMSGLOCK(request);

    if (reply)
        HTTPMSGLOCK(reply);
}

Adaptation::ServiceFilter::~ServiceFilter()
{
    HTTPMSGUNLOCK(request);
    HTTPMSGUNLOCK(reply);
}

Adaptation::ServiceFilter &Adaptation::ServiceFilter::operator =(const ServiceFilter &f)
{
    if (this != &f) {
        method = f.method;
        point = f.point;
        HTTPMSGUNLOCK(request);
        HTTPMSGUNLOCK(reply);
        request = f.request;
        HTTPMSGLOCK(request);
        reply = f.reply;
        if (reply)
            HTTPMSGLOCK(reply);
    }
    return *this;
}

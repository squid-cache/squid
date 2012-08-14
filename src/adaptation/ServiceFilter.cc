#include "squid.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "adaptation/ServiceFilter.h"


Adaptation::ServiceFilter::ServiceFilter(Method aMethod, VectPoint aPoint,
        HttpRequest *aReq, HttpReply *aRep): method(aMethod), point(aPoint),
        request(HTTPMSGLOCK(aReq)),
        reply(aRep ? HTTPMSGLOCK(aRep) : NULL)
{
    // a lot of code assumes that there is always a virgin request or cause
    assert(request);
}

Adaptation::ServiceFilter::ServiceFilter(const ServiceFilter &f):
        method(f.method), point(f.point),
        request(HTTPMSGLOCK(f.request)),
        reply(f.reply ? HTTPMSGLOCK(f.reply) : NULL)
{
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
        request = HTTPMSGLOCK(f.request);
        reply = f.reply ? HTTPMSGLOCK(f.reply) : NULL;
    }
    return *this;
}

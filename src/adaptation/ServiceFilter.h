#ifndef SQUID_ADAPTATION__SERVICE_FILTER_H
#define SQUID_ADAPTATION__SERVICE_FILTER_H

#include "adaptation/Elements.h"

class HttpRequest;
class HttpReply;

namespace Adaptation
{

/// information used to search for adaptation services
class ServiceFilter
{
public:
    ServiceFilter(Method, VectPoint, HttpRequest *, HttpReply *); // locks
    ServiceFilter(const ServiceFilter &f);
    ~ServiceFilter(); // unlocks

    ServiceFilter &operator =(const ServiceFilter &f);

public:
    Method method; ///< adaptation direction
    VectPoint point; ///< adaptation location
    HttpRequest *request; ///< HTTP request being adapted or cause; may be nil
    HttpReply *reply; ///< HTTP response being adapted; may be nil
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_FILTER_H */

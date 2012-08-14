#ifndef SQUID_ICAPHISTORY_H
#define SQUID_ICAPHISTORY_H

#include "enums.h"
#include "RefCount.h"
#include "SquidString.h"

namespace Adaptation
{
namespace Icap
{

/// collects information about ICAP processing related to an HTTP transaction
class History: public RefCountable
{
public:
    typedef RefCount<History> Pointer;

    History();

    /// record the start of an ICAP processing interval
    void start(const char *context);
    /// note the end of an ICAP processing interval
    void stop(const char *context);

    /// returns the total time of all ICAP processing intervals
    int processingTime() const;

    String rfc931; ///< the username from ident
#if USE_SSL
    String ssluser; ///< the username from SSL
#endif
    log_type logType; ///< the squid request status (TCP_MISS etc)

    String log_uri; ///< the request uri
    size_t req_sz; ///< the request size

private:
    int currentTime() const; ///< time since current start or zero

    timeval currentStart; ///< when the current processing interval started
    int pastTime;         ///< sum of closed processing interval durations
    int concurrencyLevel; ///< number of concurrent processing threads
};

} // namespace Icap
} // namespace Adaptation

#endif /*SQUID_HISTORY_H*/

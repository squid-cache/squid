#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"

#if USE_SSL
#include "ssl/support.h"

AccessLogEntry::SslDetails::SslDetails(): user(NULL), bumpMode(::Ssl::bumpEnd)
{
}
#endif /* USE_SSL */

void
AccessLogEntry::getLogClientIp(char *buf, size_t bufsz) const
{
#if FOLLOW_X_FORWARDED_FOR
    if (Config.onoff.log_uses_indirect_client && request)
        request->indirect_client_addr.NtoA(buf, bufsz);
    else
#endif
        if (tcpClient != NULL)
            tcpClient->remote.NtoA(buf, bufsz);
        else if (cache.caddr.IsNoAddr()) // e.g., ICAP OPTIONS lack client
            strncpy(buf, "-", bufsz);
        else
            cache.caddr.NtoA(buf, bufsz);
}

AccessLogEntry::~AccessLogEntry()
{
    safe_free(headers.request);

#if ICAP_CLIENT
    safe_free(adapt.last_meta);
#endif

    safe_free(headers.reply);
    safe_free(cache.authuser);

    safe_free(headers.adapted_request);
    HTTPMSGUNLOCK(adapted_request);

    HTTPMSGUNLOCK(reply);
    HTTPMSGUNLOCK(request);
#if ICAP_CLIENT
    HTTPMSGUNLOCK(icap.reply);
    HTTPMSGUNLOCK(icap.request);
#endif
    cbdataReferenceDone(cache.port);
}

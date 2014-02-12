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
    Ip::Address log_ip;

#if FOLLOW_X_FORWARDED_FOR
    if (Config.onoff.log_uses_indirect_client && request)
        log_ip = request->indirect_client_addr;
    else
#endif
        if (tcpClient != NULL)
            log_ip = tcpClient->remote;
        else if (cache.caddr.isNoAddr()) { // e.g., ICAP OPTIONS lack client
            strncpy(buf, "-", bufsz);
            return;
        } else
            log_ip = cache.caddr;

    // Apply so-called 'privacy masking' to IPv4 clients
    // - localhost IP is always shown in full
    // - IPv4 clients masked with client_netmask
    // - IPv6 clients use 'privacy addressing' instead.

    if (!log_ip.isLocalhost() && log_ip.isIPv4())
        log_ip.applyMask(Config.Addrs.client_netmask);

    log_ip.toStr(buf, bufsz);
}

AccessLogEntry::~AccessLogEntry()
{
    safe_free(headers.request);

#if USE_ADAPTATION
    safe_free(adapt.last_meta);
#endif

    safe_free(headers.reply);

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

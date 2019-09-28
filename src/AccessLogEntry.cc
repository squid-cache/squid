/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "proxyp/Header.h"
#include "SquidConfig.h"
#include "ssl/support.h"

void
AccessLogEntry::getLogClientIp(char *buf, size_t bufsz) const
{
    Ip::Address log_ip;

#if FOLLOW_X_FORWARDED_FOR
    if (Config.onoff.log_uses_indirect_client && request)
        log_ip = request->indirect_client_addr;
    else
#endif
        if (tcpClient)
            log_ip = tcpClient->remote;
        else
            log_ip = cache.caddr;

    // internally generated requests (and some ICAP) lack client IP
    if (log_ip.isNoAddr()) {
        strncpy(buf, "-", bufsz);
        return;
    }

    // Apply so-called 'privacy masking' to IPv4 clients
    // - localhost IP is always shown in full
    // - IPv4 clients masked with client_netmask
    // - IPv6 clients use 'privacy addressing' instead.

    log_ip.applyClientMask(Config.Addrs.client_netmask);

    log_ip.toStr(buf, bufsz);
}

SBuf
AccessLogEntry::getLogMethod() const
{
    static const SBuf dash("-");
    SBuf method;
    if (icp.opcode)
        method.append(icp_opcode_str[icp.opcode]);
    else if (htcp.opcode)
        method.append(htcp.opcode);
    else if (http.method)
        method = http.method.image();
    else
        method = dash;
    return method;
}

void
AccessLogEntry::syncNotes(HttpRequest *req)
{
    // XXX: auth code only has access to HttpRequest being authenticated
    // so we must handle the case where HttpRequest is set without ALE being set.
    assert(req);
    if (!notes)
        notes = req->notes();
    else
        assert(notes == req->notes());
}

const char *
AccessLogEntry::getClientIdent() const
{
    if (tcpClient)
        return tcpClient->rfc931;

    if (cache.rfc931 && *cache.rfc931)
        return cache.rfc931;

    return nullptr;
}

const char *
AccessLogEntry::getExtUser() const
{
    if (request && request->extacl_user.size())
        return request->extacl_user.termedBuf();

    if (cache.extuser && *cache.extuser)
        return cache.extuser;

    return nullptr;
}

AccessLogEntry::AccessLogEntry() {}

AccessLogEntry::~AccessLogEntry()
{
    safe_free(headers.request);

#if USE_ADAPTATION
    safe_free(adapt.last_meta);
#endif

    safe_free(headers.adapted_request);
    HTTPMSGUNLOCK(adapted_request);

    safe_free(lastAclName);

    HTTPMSGUNLOCK(request);
#if ICAP_CLIENT
    HTTPMSGUNLOCK(icap.reply);
    HTTPMSGUNLOCK(icap.request);
#endif
}

const SBuf *
AccessLogEntry::effectiveVirginUrl() const
{
    const SBuf *effectiveUrl = request ? &request->effectiveRequestUri() : &virginUrlForMissingRequest_;
    if (effectiveUrl && !effectiveUrl->isEmpty())
        return effectiveUrl;
    // We can not use ALE::url here because it may contain a request URI after
    // adaptation/redirection. When the request is missing, a non-empty ALE::url
    // means that we missed a setVirginUrlForMissingRequest() call somewhere.
    return nullptr;
}

void
AccessLogEntry::packReplyHeaders(MemBuf &mb) const
{
    if (reply)
        reply->packHeadersUsingFastPacker(mb);
}


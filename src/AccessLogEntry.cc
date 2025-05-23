/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "fqdncache.h"
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

const char *
AccessLogEntry::getLogClientFqdn(char * const buf, const size_t bufSize) const
{
    // TODO: Use indirect client and tcpClient like getLogClientIp() does.
    const auto &client = cache.caddr;

    // internally generated (and ICAP OPTIONS) requests lack client IP
    if (client.isAnyAddr())
        return "-";

    // If we are here, Squid was configured to use %>A or equivalent.
    // Improve our chances of getting FQDN by resolving client IPs ASAP.
    Dns::ResolveClientAddressesAsap = true; // may already be true

    // Too late for ours, but FQDN_LOOKUP_IF_MISS might help the next caller.
    if (const auto fqdn = fqdncache_gethostbyaddr(client, FQDN_LOOKUP_IF_MISS))
        return fqdn; // TODO: Return a safe SBuf from fqdncache_gethostbyaddr().

    return client.toStr(buf, bufSize);
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

    HTTPMSGUNLOCK(request);
#if ICAP_CLIENT
    HTTPMSGUNLOCK(icap.reply);
    HTTPMSGUNLOCK(icap.request);
#endif
}

ScopedId
AccessLogEntry::codeContextGist() const
{
    if (request) {
        if (const auto &mx = request->masterXaction)
            return mx->id.detach();
    }
    // TODO: Carefully merge ALE and MasterXaction.
    return ScopedId("ALE w/o master");
}

std::ostream &
AccessLogEntry::detailCodeContext(std::ostream &os) const
{
    // TODO: Consider printing all instead of the first most important detail.

    if (request) {
        if (const auto &mx = request->masterXaction)
            return os << Debug::Extra << "current master transaction: " << mx->id;
    }

    // provide helpful details since we cannot identify the transaction exactly

    if (tcpClient)
        return os << Debug::Extra << "current from-client connection: " << tcpClient;
    else if (!cache.caddr.isNoAddr())
        return os << Debug::Extra << "current client: " << cache.caddr;

    const auto optionalMethod = [this,&os]() {
        if (hasLogMethod())
            os << getLogMethod() << ' ';
        return "";
    };
    if (const auto uri = effectiveVirginUrl())
        return os << Debug::Extra << "current client request: " << optionalMethod() << *uri;
    else if (!url.isEmpty())
        return os << Debug::Extra << "current request: " << optionalMethod() << url;
    else if (hasLogMethod())
        return os << Debug::Extra << "current request method: " << getLogMethod();

    return os;
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

const Error *
AccessLogEntry::error() const
{
    // the order ensures that the first-imported error is returned
    if (error_) // updateError() was called before importing the request
        return &error_;
    if (request && request->error) // request was imported before updateError()
        return &request->error;
    return nullptr; // we imported no errors and no requests
}

void
AccessLogEntry::updateError(const Error &err)
{
    // the order ensures that error() returns the first-imported error
    if (request)
        request->error.update(err);
    else
        error_.update(err);
}

void
AccessLogEntry::packReplyHeaders(MemBuf &mb) const
{
    if (reply)
        reply->packHeadersUsingFastPacker(mb);
}


/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid CEF format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "comm/Connection.h"
#include "error/Error.h"
#include "globals.h"
#include "hier_code.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "sbuf/SBuf.h"
#include "time/gadgets.h"
#include "tools.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif

namespace {

/// Transport protocol Squid used for this transaction, derived from the log
/// tag prefix (TCP_*, UDP_*, ICP_*).
const char *
cefTransport(const LogTags_ot tag)
{
    switch (tag) {
    case LOG_UDP_HIT:
    case LOG_UDP_MISS:
    case LOG_UDP_DENIED:
    case LOG_UDP_INVALID:
    case LOG_UDP_MISS_NOFETCH:
    case LOG_ICP_QUERY:
        return "UDP";
    default:
        return "TCP";
    }
}

/// CEF severity (0..10) describing what Squid did with the transaction.
/// We prefer Squid's own signals (LogTags, error category) over the upstream
/// HTTP status, since they reflect proxy behavior rather than origin replies.
int
cefSeverity(const AccessLogEntry &al)
{
    const auto httpCode = al.http.code;

    if (const auto err = al.error()) {
        switch (err->category) {
        case ERR_CONNECT_FAIL:
        case ERR_SECURE_CONNECT_FAIL:
        case ERR_SOCKET_FAILURE:
        case ERR_DNS_FAIL:
        case ERR_READ_TIMEOUT:
        case ERR_LIFETIME_EXP:
        case ERR_READ_ERROR:
        case ERR_WRITE_ERROR:
        case ERR_GATEWAY_FAILURE:
        case ERR_CANNOT_FORWARD:
        case ERR_NO_RELAY:
        case ERR_FORWARDING_DENIED:
        case ERR_ICAP_FAILURE:
        case ERR_INVALID_RESP:
        case ERR_TOO_BIG:
            return 4;

        case ERR_ACCESS_DENIED:
        case ERR_CACHE_ACCESS_DENIED:
        case ERR_CACHE_MGR_ACCESS_DENIED:
        case ERR_INVALID_REQ:
        case ERR_INVALID_URL:
        case ERR_UNSUP_REQ:
        case ERR_UNSUP_HTTPVERSION:
            return 3;

        default:
            break;
        }
    }

    switch (al.cache.code.oldType) {
    case LOG_TCP_HIT:
    case LOG_TCP_IMS_HIT:
    case LOG_TCP_INM_HIT:
    case LOG_TCP_MEM_HIT:
    case LOG_TCP_NEGATIVE_HIT:
    case LOG_TCP_OFFLINE_HIT:
    case LOG_TCP_REFRESH_UNMODIFIED:
    case LOG_TCP_REFRESH_FAIL_OLD:
    case LOG_UDP_HIT:
        return 0;

    case LOG_TCP_MISS:
    case LOG_TCP_REFRESH:
    case LOG_TCP_REFRESH_MODIFIED:
    case LOG_TCP_CLIENT_REFRESH_MISS:
    case LOG_TCP_TUNNEL:
    case LOG_UDP_MISS:
    case LOG_UDP_MISS_NOFETCH:
    case LOG_ICP_QUERY:
        return 1;

    case LOG_TCP_REDIRECT:
        return 2;

    case LOG_TCP_DENIED:
    case LOG_TCP_DENIED_REPLY:
        // 401/407 are routine auth handshakes; 403 et al. are policy blocks
        return (httpCode == 401 || httpCode == 407) ? 2 : 3;

    case LOG_UDP_DENIED:
        return 3;

    case LOG_TCP_SWAPFAIL_MISS:
    case LOG_TCP_REFRESH_FAIL_ERR:
    case LOG_UDP_INVALID:
        return 4;

    case LOG_TAG_NONE:
    case LOG_TYPE_MAX:
        break;
    }

    if (httpCode >= 500) return 4;
    if (httpCode >= 400) return 3;
    return 1;
}

/// Append `[data, data+len)` to `out`, escaping the CEF header-reserved bytes
/// '\\' and '|' with a leading backslash.
/// Reference: https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Character_encoding
void
appendHeader(SBuf &out, const char *data, const size_t len)
{
    if (!data) return;
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (c == '\\' || c == '|')
            out.append('\\');
        out.append(c);
    }
}

void
appendHeader(SBuf &out, const char *cstr)
{
    if (cstr) appendHeader(out, cstr, strlen(cstr));
}

/// Append `[data, data+len)` to `out`, escaping the CEF extension-reserved
/// bytes '\\', '=', CR, LF.
/// Reference: https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Character_encoding
void
appendExt(SBuf &out, const char *data, const size_t len)
{
    if (!data) return;
    for (size_t i = 0; i < len; ++i) {
        switch (data[i]) {
        case '\\':
            out.append("\\\\", 2);
            break;
        case '=':
            out.append("\\=", 2);
            break;
        case '\r':
            out.append("\\r", 2);
            break;
        case '\n':
            out.append("\\n", 2);
            break;
        default:
            out.append(data[i]);
            break;
        }
    }
}

void
appendExt(SBuf &out, const char *cstr)
{
    if (cstr) appendExt(out, cstr, strlen(cstr));
}

void
appendExt(SBuf &out, const SBuf &s)
{
    appendExt(out, s.rawContent(), s.length());
}

class FieldWriter
{
public:
    explicit FieldWriter(SBuf &o): out(o) {}

    void str(const char *key, const char *value) {
        if (!value || !*value) return;
        prefix(key);
        appendExt(out, value);
    }

    void str(const char *key, const SBuf &value) {
        if (value.isEmpty()) return;
        prefix(key);
        appendExt(out, value);
    }

    void literal(const char *key, const char *value) {
        if (!value || !*value) return;
        prefix(key);
        out.append(value);
    }

    void integer(const char *key, const int64_t value) {
        prefix(key);
        out.appendf("%" PRId64, value);
    }

private:
    void prefix(const char *key) {
        if (!first)
            out.append(' ');
        first = false;
        out.append(key);
        out.append('=');
    }

    SBuf &out;
    bool first = true;
};

} // namespace

void
Log::Format::SquidCEF(const AccessLogEntry::Pointer &al, Logfile *logfile)
{
    char clientIp[MAX_IPSTRLEN];
    al->getLogClientIp(clientIp, MAX_IPSTRLEN);

    int clientPort = 0;
    char dvcAddr[MAX_IPSTRLEN] = "";
    if (al->tcpClient) {
        clientPort = al->tcpClient->remote.port();
        al->tcpClient->local.toStr(dvcAddr, sizeof(dvcAddr));
    }

    char serverIp[MAX_IPSTRLEN] = "";
    int serverPort = 0;
    if (al->hier.tcpServer != nullptr) {
        al->hier.tcpServer->remote.toStr(serverIp, sizeof(serverIp));
        serverPort = al->hier.tcpServer->remote.port();
    }

    const SBuf method(al->getLogMethod());

    const char *user = nullptr;
#if USE_AUTH
    if (al->request && al->request->auth_user_request != nullptr)
        user = al->request->auth_user_request->username();
#endif
    if (!user)
        user = al->getExtUser();

    const char *referer = nullptr;
    const char *agent = nullptr;
    SBuf urlScheme;
    const char *urlHost = nullptr;
    if (al->request) {
        referer = al->request->header.getStr(Http::HdrType::REFERER);
        agent = al->request->header.getStr(Http::HdrType::USER_AGENT);
        urlScheme = al->request->url.getScheme().image();
        urlHost = al->request->url.host();
    }

    // CEF "app" is the application-level protocol; combine URL scheme with the
    // HTTP version when known (e.g., "https/1.1") so SIEMs can filter by both.
    SBuf appProto(urlScheme);
    if (al->http.version.protocol == AnyP::PROTO_HTTP && al->http.version.major) {
        appProto.appendf("/%u.%u", al->http.version.major, al->http.version.minor);
    }

    const char *cacheCode = al->cache.code.c_str();
    const char *hierCode = hier_code_str[al->hier.code];

    const auto startMs = static_cast<long long>(al->cache.start_time.tv_sec) * 1000LL +
                         (al->cache.start_time.tv_usec / 1000);
    const auto trtMs = tvToMsec(al->cache.trTime);
    const auto endMs = (trtMs >= 0) ? (startMs + trtMs) : -1;

    SBuf out;
    // Most CEF lines fall in the 512-1024 byte range; reserve once to avoid
    // re-grow churn during the many small appends below.
    // NOTE: The following things need to be considered:
    // - Long URLs or User-Agent strings may exceed this reservation.
    // - Estimation by sampling logs of single user browsing throughout one day.
    out.reserveSpace(1024);

    // CEF header field order per ArcSight CEF Implementation Standard:
    // https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Header_information
    /* Header: CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity| */
    out.append("CEF:0|", 6);
    appendHeader(out, "Squid");
    out.append('|');
    appendHeader(out, "Squid Cache");
    out.append('|');
    appendHeader(out, VERSION);
    out.append('|');
    appendHeader(out, cacheCode);
    out.append('|');
    appendHeader(out, "Proxy Request");
    out.appendf("|%d|", cefSeverity(*al));

    // CEF extensions are space-separated key=value pairs; key names are drawn
    // from the ArcSight CEF Extensions dictionary:
    // https://docs.microfocus.com/doc/2097/26.1/ab6eeee4916c_arcsight_extensions
    /* Extensions: key1=value1 key2=value2 ... */
    FieldWriter w(out);

    /* Time (rt = receipt time; start/end mark activity boundaries) */
    if (al->cache.start_time.tv_sec > 0) {
        w.integer("rt", startMs);
        w.integer("start", startMs);
        if (endMs >= 0)
            w.integer("end", endMs);
    }

    /* Client side */
    if (clientIp[0] && !(clientIp[0] == '-' && clientIp[1] == '\0'))
        w.str("src", clientIp);
    if (clientPort > 0)
        w.integer("spt", clientPort);

    /* Squid (device) end of the client TCP connection */
    if (dvcAddr[0])
        w.str("dvc", dvcAddr);
    w.str("dvchost", getMyHostname());

    /* Server side */
    if (serverIp[0])
        w.str("dst", serverIp);
    if (serverPort > 0)
        w.integer("dpt", serverPort);
    w.str("dhost", urlHost);

    /* Protocol */
    w.literal("proto", cefTransport(al->cache.code.oldType));
    w.str("app", appProto);

    /* User */
    w.str("suser", user);

    /* Request line */
    w.str("requestMethod", method);
    w.str("request", al->url);
    w.str("requestClientApplication", agent);

    /* Bytes */
    w.integer("in", static_cast<int64_t>(al->http.clientRequestSz.messageTotal()));
    w.integer("out", static_cast<int64_t>(al->http.clientReplySz.messageTotal()));

    /* Action / outcome */
    w.str("act", cacheCode);
    w.literal("outcome", al->http.code >= 400 ? "failure" : "success");

    /* Response time (ms). cn1 is a numeric custom field; cn1Label names it. */
    if (trtMs >= 0) {
        w.integer("cn1", trtMs);
        w.literal("cn1Label", "ResponseTime");
    }

    /* HTTP status code (cn2) */
    if (al->http.code > 0) {
        w.integer("cn2", al->http.code);
        w.literal("cn2Label", "HttpStatus");
    }

    /* Referer (cs1) */
    if (referer && *referer) {
        w.str("cs1", referer);
        w.literal("cs1Label", "Referer");
    }

    /* Hierarchy code (cs2) */
    if (hierCode && *hierCode) {
        w.str("cs2", hierCode);
        w.literal("cs2Label", "Hierarchy");
    }

    /* Response Content-Type */
    w.str("fileType", al->http.content_type);

    /* Reason for failure */
    if (const auto err = al->error()) {
        if (err->category != ERR_NONE)
            w.str("reason", errorTypeName(err->category));
    }

    out.append('\n');
    logfileWrite(logfile, out.rawContent(), out.length());
}


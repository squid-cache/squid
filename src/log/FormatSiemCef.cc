/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - SIEM CEF format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "comm/Connection.h"
#include "error/Error.h"
#include "globals.h"
#include "hier_code.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "sbuf/Stream.h"
#include "time/gadgets.h"
#include "tools.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif

namespace {

/// Transport protocol Squid used for this transaction, derived from the log
/// tag prefix (TCP_*, UDP_*, ICP_*).
static const char *
CefTransport(const LogTags_ot tag)
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
static int
CefSeverity(const AccessLogEntry &al)
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

/// Stream `[data, data+len)` to `os`, escaping the CEF header-reserved bytes
/// '\\' and '|' with a leading backslash.
/// Reference: https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Character_encoding
void
appendHeader(std::ostream &os, const char *data, const size_t len)
{
    if (!data) return;
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (c == '\\' || c == '|')
            os.put('\\');
        os.put(c);
    }
}

inline void
appendHeader(std::ostream &os, const char *cstr)
{
    if (cstr) appendHeader(os, cstr, strlen(cstr));
}

class FieldWriter
{
public:
    explicit FieldWriter(std::ostream &o): out(o) {}

    /// Writes ` key=value` for any value type that std::ostream knows how to
    /// format (integers, const char* literals, etc.). Skips escaping; only
    /// safe for caller-controlled values free of CEF-reserved bytes.
    template <class T>
    void put(const char *key, const T &value) {
        out << ' ' << key << '=' << value;
    }

    /// Writes ` key=value` with the value escaped per CEF extension rules.
    void putStr(const char *key, const char *value) {
        if (!value || !*value) return;
        out << ' ' << key << '=';
        appendExt(out, value, strlen(value));
    }

    void putStr(const char *key, const SBuf &value) {
        if (value.isEmpty()) return;
        out << ' ' << key << '=';
        appendExt(out, value.rawContent(), value.length());
    }

private:
    std::ostream &out;

    /// Stream `[data, data+len)` to `os`, escaping the CEF extension-reserved
    /// bytes '\\', '=', CR, LF.
    /// Reference: https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Character_encoding
    static void
    appendExt(std::ostream &os, const char *data, const size_t len)
    {
        if (!data) return;
        for (size_t i = 0; i < len; ++i) {
            switch (data[i]) {
            case '\\': os << "\\\\"; break;
            case '=':  os << "\\=";  break;
            case '\r': os << "\\r";  break;
            case '\n': os << "\\n";  break;
            default:   os.put(data[i]); break;
            }
        }
    }
};

} // namespace

void
Log::Format::SiemCef(const AccessLogEntry::Pointer &al, Logfile *logfile)
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

    const auto cacheCode = al->cache.code.c_str();
    const auto hierCode = hier_code_str[al->hier.code];

    const auto startMs = static_cast<long long>(al->cache.start_time.tv_sec) * 1000LL +
                         (al->cache.start_time.tv_usec / 1000);
    const auto trtMs = tvToMsec(al->cache.trTime);
    const auto endMs = (trtMs >= 0) ? (startMs + trtMs) : -1;

    SBufStream out;

    // CEF header field order per CEF Implementation Standard:
    // https://docs.microfocus.com/doc/2097/26.1/siemcefimplementationstandard#Header_information
    /* Header: CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity| */
    out << "CEF:0|Squid|Squid Cache|";
    appendHeader(out, VERSION);
    out << '|';
    appendHeader(out, cacheCode);
    out << "|Proxy Request|" << CefSeverity(*al) << '|';

    // CEF extensions are space-separated key=value pairs; FieldWriter::put()
    // emits the leading space for us. Key names are drawn from the CEF
    // Extensions dictionary:
    // https://docs.microfocus.com/doc/2097/26.1/ab6eeee4916c_arcsight_extensions
    /* Extensions: key1=value1 key2=value2 ... */
    FieldWriter w(out);

    /* Time (rt = receipt time; start/end mark activity boundaries) */
    if (al->cache.start_time.tv_sec > 0) {
        w.put("rt", startMs);
        w.put("start", startMs);
        if (endMs >= 0)
            w.put("end", endMs);
    }

    /* Client side */
    if (clientIp[0] && !(clientIp[0] == '-' && clientIp[1] == '\0'))
        w.putStr("src", clientIp);
    if (clientPort > 0)
        w.put("spt", clientPort);

    /* Squid (device) end of the client TCP connection */
    if (dvcAddr[0])
        w.putStr("dvc", dvcAddr);
    w.putStr("dvchost", getMyHostname());

    /* Server side */
    if (serverIp[0])
        w.putStr("dst", serverIp);
    if (serverPort > 0)
        w.put("dpt", serverPort);
    w.putStr("dhost", urlHost);

    /* Protocol */
    w.put("proto", CefTransport(al->cache.code.oldType));
    w.putStr("app", appProto);

    /* User */
    w.putStr("suser", user);

    /* Request line */
    w.putStr("requestMethod", method);
    w.putStr("request", al->url);
    w.putStr("requestClientApplication", agent);

    /* Bytes */
    w.put("in", al->http.clientRequestSz.messageTotal());
    w.put("out", al->http.clientReplySz.messageTotal());

    /* Action / outcome */
    w.putStr("act", cacheCode);
    w.put("outcome", al->http.code >= 400 ? "failure" : "success");

    /* Response time (ms). cn1 is a numeric custom field; cn1Label names it. */
    if (trtMs >= 0) {
        w.put("cn1", trtMs);
        w.put("cn1Label", "ResponseTime");
    }

    /* HTTP status code (cn2) */
    if (al->http.code > 0) {
        w.put("cn2", al->http.code);
        w.put("cn2Label", "HttpStatus");
    }

    /* Referer (cs1) */
    if (referer && *referer) {
        w.putStr("cs1", referer);
        w.put("cs1Label", "Referer");
    }

    /* Hierarchy code (cs2) */
    if (hierCode && *hierCode) {
        w.putStr("cs2", hierCode);
        w.put("cs2Label", "Hierarchy");
    }

    /* Response Content-Type */
    w.putStr("fileType", al->http.content_type);

    /* Reason for failure */
    if (const auto err = al->error()) {
        if (err->category != ERR_NONE)
            w.putStr("reason", errorTypeName(err->category));
    }

    out << '\n';
    const auto buf = out.buf();
    logfileWrite(logfile, buf.rawContent(), buf.length());
}


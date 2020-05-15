/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base64.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "fde.h"
#include "format/Format.h"
#include "format/Quoting.h"
#include "format/Token.h"
#include "fqdncache.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "sbuf/StringConvert.h"
#include "security/CertError.h"
#include "security/NegotiationHistory.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"
#if USE_OPENSSL
#include "ssl/ErrorDetail.h"
#include "ssl/ServerBump.h"
#endif

/// Convert a string to NULL pointer if it is ""
#define strOrNull(s) ((s)==NULL||(s)[0]=='\0'?NULL:(s))

const SBuf Format::Dash("-");

Format::Format::Format(const char *n) :
    format(NULL),
    next(NULL)
{
    name = xstrdup(n);
}

Format::Format::~Format()
{
    // erase the list without consuming stack space
    while (next) {
        // unlink the next entry for deletion
        Format *temp = next;
        next = temp->next;
        temp->next = NULL;
        delete temp;
    }

    // remove locals
    xfree(name);
    delete format;
}

bool
Format::Format::parse(const char *def)
{
    const char *cur, *eos;
    Token *new_lt, *last_lt;
    enum Quoting quote = LOG_QUOTE_NONE;

    debugs(46, 2, HERE << "got definition '" << def << "'");

    if (format) {
        debugs(46, DBG_IMPORTANT, "WARNING: existing format for '" << name << " " << def << "'");
        return false;
    }

    /* very inefficent parser, but who cares, this needs to be simple */
    /* First off, let's tokenize, we'll optimize in a second pass.
     * A token can either be a %-prefixed sequence (usually a dynamic
     * token but it can be an escaped sequence), or a string. */
    cur = def;
    eos = def + strlen(def);
    format = new_lt = last_lt = new Token;
    cur += new_lt->parse(cur, &quote);

    while (cur < eos) {
        new_lt = new Token;
        last_lt->next = new_lt;
        last_lt = new_lt;
        cur += new_lt->parse(cur, &quote);
    }

    return true;
}

void
Format::Format::dump(StoreEntry * entry, const char *directiveName, bool eol) const
{
    debugs(46, 4, HERE);

    // loop rather than recursing to conserve stack space.
    for (const Format *fmt = this; fmt; fmt = fmt->next) {
        debugs(46, 3, HERE << "Dumping format definition for " << fmt->name);
        if (directiveName)
            storeAppendPrintf(entry, "%s %s ", directiveName, fmt->name);

        for (Token *t = fmt->format; t; t = t->next) {
            if (t->type == LFT_STRING)
                storeAppendPrintf(entry, "%s", t->data.string);
            else {
                char argbuf[256];
                char *arg = NULL;
                ByteCode_t type = t->type;

                switch (type) {
                /* special cases */

                case LFT_STRING:
                    break;
#if USE_ADAPTATION
                case LFT_ADAPTATION_LAST_HEADER_ELEM:
#endif
#if ICAP_CLIENT
                case LFT_ICAP_REQ_HEADER_ELEM:
                case LFT_ICAP_REP_HEADER_ELEM:
#endif
                case LFT_REQUEST_HEADER_ELEM:
                case LFT_ADAPTED_REQUEST_HEADER_ELEM:
                case LFT_REPLY_HEADER_ELEM:

                    if (t->data.header.separator != ',')
                        snprintf(argbuf, sizeof(argbuf), "%s:%c%s", t->data.header.header, t->data.header.separator, t->data.header.element);
                    else
                        snprintf(argbuf, sizeof(argbuf), "%s:%s", t->data.header.header, t->data.header.element);

                    arg = argbuf;

                    switch (type) {
                    case LFT_REQUEST_HEADER_ELEM:
                        type = LFT_REQUEST_HEADER_ELEM; // XXX: remove _ELEM?
                        break;
                    case LFT_ADAPTED_REQUEST_HEADER_ELEM:
                        type = LFT_ADAPTED_REQUEST_HEADER_ELEM; // XXX: remove _ELEM?
                        break;
                    case LFT_REPLY_HEADER_ELEM:
                        type = LFT_REPLY_HEADER_ELEM; // XXX: remove _ELEM?
                        break;
#if USE_ADAPTATION
                    case LFT_ADAPTATION_LAST_HEADER_ELEM:
                        type = LFT_ADAPTATION_LAST_HEADER;
                        break;
#endif
#if ICAP_CLIENT
                    case LFT_ICAP_REQ_HEADER_ELEM:
                        type = LFT_ICAP_REQ_HEADER;
                        break;
                    case LFT_ICAP_REP_HEADER_ELEM:
                        type = LFT_ICAP_REP_HEADER;
                        break;
#endif
                    default:
                        break;
                    }

                    break;

                case LFT_REQUEST_ALL_HEADERS:
                case LFT_ADAPTED_REQUEST_ALL_HEADERS:
                case LFT_REPLY_ALL_HEADERS:

#if USE_ADAPTATION
                case LFT_ADAPTATION_LAST_ALL_HEADERS:
#endif
#if ICAP_CLIENT
                case LFT_ICAP_REQ_ALL_HEADERS:
                case LFT_ICAP_REP_ALL_HEADERS:
#endif

                    switch (type) {
                    case LFT_REQUEST_ALL_HEADERS:
                        type = LFT_REQUEST_HEADER;
                        break;
                    case LFT_ADAPTED_REQUEST_ALL_HEADERS:
                        type = LFT_ADAPTED_REQUEST_HEADER;
                        break;
                    case LFT_REPLY_ALL_HEADERS:
                        type = LFT_REPLY_HEADER;
                        break;
#if USE_ADAPTATION
                    case LFT_ADAPTATION_LAST_ALL_HEADERS:
                        type = LFT_ADAPTATION_LAST_HEADER;
                        break;
#endif
#if ICAP_CLIENT
                    case LFT_ICAP_REQ_ALL_HEADERS:
                        type = LFT_ICAP_REQ_HEADER;
                        break;
                    case LFT_ICAP_REP_ALL_HEADERS:
                        type = LFT_ICAP_REP_HEADER;
                        break;
#endif
                    default:
                        break;
                    }

                    break;

                default:
                    if (t->data.string)
                        arg = t->data.string;

                    break;
                }

                entry->append("%", 1);

                switch (t->quote) {

                case LOG_QUOTE_QUOTES:
                    entry->append("\"", 1);
                    break;

                case LOG_QUOTE_MIMEBLOB:
                    entry->append("[", 1);
                    break;

                case LOG_QUOTE_URL:
                    entry->append("#", 1);
                    break;

                case LOG_QUOTE_RAW:
                    entry->append("'", 1);
                    break;

                case LOG_QUOTE_SHELL:
                    entry->append("/", 1);
                    break;

                case LOG_QUOTE_NONE:
                    break;
                }

                if (t->left)
                    entry->append("-", 1);

                if (t->zero)
                    entry->append("0", 1);

                if (t->widthMin >= 0)
                    storeAppendPrintf(entry, "%d", t->widthMin);

                if (t->widthMax >= 0)
                    storeAppendPrintf(entry, ".%d", t->widthMax);

                if (arg)
                    storeAppendPrintf(entry, "{%s}", arg);

                storeAppendPrintf(entry, "%s", t->label);

                if (t->space)
                    entry->append(" ", 1);
            }
        }

        if (eol)
            entry->append("\n", 1);
    }

}

static void
log_quoted_string(const char *str, char *out)
{
    char *p = out;

    while (*str) {
        int l = strcspn(str, "\"\\\r\n\t");
        memcpy(p, str, l);
        str += l;
        p += l;

        switch (*str) {

        case '\0':
            break;

        case '\r':
            *p = '\\';
            ++p;
            *p = 'r';
            ++p;
            ++str;
            break;

        case '\n':
            *p = '\\';
            ++p;
            *p = 'n';
            ++p;
            ++str;
            break;

        case '\t':
            *p = '\\';
            ++p;
            *p = 't';
            ++p;
            ++str;
            break;

        default:
            *p = '\\';
            ++p;
            *p = *str;
            ++p;
            ++str;
            break;
        }
    }

    *p = '\0';
}

/// XXX: Misnamed. TODO: Split <h (and this function) to distinguish received
/// headers from sent headers rather than failing to distinguish requests from responses.
/// \retval HttpReply sent to the HTTP client (access.log and default context).
/// \retval HttpReply received (encapsulated) from the ICAP server (icap.log context).
/// \retval HttpRequest received (encapsulated) from the ICAP server (icap.log context).
static const HttpMsg *
actualReplyHeader(const AccessLogEntry::Pointer &al)
{
    const HttpMsg *msg = al->reply;
#if ICAP_CLIENT
    // al->icap.reqMethod is methodNone in access.log context
    if (!msg && al->icap.reqMethod == Adaptation::methodReqmod)
        msg = al->adapted_request;
#endif
    return msg;
}

/// XXX: Misnamed. See actualReplyHeader().
/// \return HttpRequest or HttpReply for %http::>h.
static const HttpMsg *
actualRequestHeader(const AccessLogEntry::Pointer &al)
{
#if ICAP_CLIENT
    // al->icap.reqMethod is methodNone in access.log context
    if (al->icap.reqMethod == Adaptation::methodRespmod) {
        // XXX: for now AccessLogEntry lacks virgin response headers
        return nullptr;
    }
#endif
    return al->request;
}

void
Format::Format::assemble(MemBuf &mb, const AccessLogEntry::Pointer &al, int logSequenceNumber) const
{
    static char tmp[1024];
    SBuf sb;

    for (Token *fmt = format; fmt; fmt = fmt->next) {   /* for each token */
        const char *out = nullptr;
        int quote = 0;
        long int outint = 0;
        int doint = 0;
        int dofree = 0;
        int64_t outoff = 0;
        int dooff = 0;
        struct timeval outtv = {0, 0};
        int doMsec = 0;
        int doSec = 0;

        switch (fmt->type) {

        case LFT_NONE:
            out = "";
            break;

        case LFT_STRING:
            out = fmt->data.string;
            break;

        case LFT_CLIENT_IP_ADDRESS:
            al->getLogClientIp(tmp, sizeof(tmp));
            out = tmp;
            break;

        case LFT_CLIENT_FQDN:
            if (al->cache.caddr.isAnyAddr()) // e.g., ICAP OPTIONS lack client
                out = "-";
            else
                out = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);

            if (!out) {
                out = al->cache.caddr.toStr(tmp, sizeof(tmp));
            }
            break;

        case LFT_CLIENT_PORT:
            if (al->request) {
                outint = al->request->client_addr.port();
                doint = 1;
            } else if (al->tcpClient) {
                outint = al->tcpClient->remote.port();
                doint = 1;
            }
            break;

        case LFT_CLIENT_EUI:
#if USE_SQUID_EUI
            // TODO make the ACL checklist have a direct link to any TCP details.
            if (al->request && al->request->clientConnectionManager.valid() &&
                    al->request->clientConnectionManager->clientConnection) {
                const auto &conn = al->request->clientConnectionManager->clientConnection;
                if (conn->remote.isIPv4())
                    conn->remoteEui48.encode(tmp, sizeof(tmp));
                else
                    conn->remoteEui64.encode(tmp, sizeof(tmp));
                out = tmp;
            }
#endif
            break;

        case LFT_EXT_ACL_CLIENT_EUI48:
#if USE_SQUID_EUI
            if (al->request && al->request->clientConnectionManager.valid() &&
                    al->request->clientConnectionManager->clientConnection &&
                    al->request->clientConnectionManager->clientConnection->remote.isIPv4()) {
                al->request->clientConnectionManager->clientConnection->remoteEui48.encode(tmp, sizeof(tmp));
                out = tmp;
            }
#endif
            break;

        case LFT_EXT_ACL_CLIENT_EUI64:
#if USE_SQUID_EUI
            if (al->request && al->request->clientConnectionManager.valid() &&
                    al->request->clientConnectionManager->clientConnection &&
                    !al->request->clientConnectionManager->clientConnection->remote.isIPv4()) {
                al->request->clientConnectionManager->clientConnection->remoteEui64.encode(tmp, sizeof(tmp));
                out = tmp;
            }
#endif
            break;

        case LFT_SERVER_IP_ADDRESS:
            if (al->hier.tcpServer)
                out = al->hier.tcpServer->remote.toStr(tmp, sizeof(tmp));
            break;

        case LFT_SERVER_FQDN_OR_PEER_NAME:
            out = al->hier.host;
            break;

        case LFT_SERVER_PORT:
            if (al->hier.tcpServer) {
                outint = al->hier.tcpServer->remote.port();
                doint = 1;
            }
            break;

        case LFT_LOCAL_LISTENING_IP: {
            // avoid logging a dash if we have reliable info
            const bool interceptedAtKnownPort = al->request ?
                                                (al->request->flags.interceptTproxy ||
                                                 al->request->flags.intercepted) && al->cache.port :
                                                false;
            if (interceptedAtKnownPort) {
                const bool portAddressConfigured = !al->cache.port->s.isAnyAddr();
                if (portAddressConfigured)
                    out = al->cache.port->s.toStr(tmp, sizeof(tmp));
            } else if (al->tcpClient)
                out = al->tcpClient->local.toStr(tmp, sizeof(tmp));
        }
        break;

        case LFT_CLIENT_LOCAL_IP:
            if (al->tcpClient)
                out = al->tcpClient->local.toStr(tmp, sizeof(tmp));
            break;

        case LFT_CLIENT_LOCAL_TOS:
            if (al->tcpClient) {
                sb.appendf("0x%x", static_cast<uint32_t>(al->tcpClient->tos));
                out = sb.c_str();
            }
            break;

        case LFT_CLIENT_LOCAL_NFMARK:
            if (al->tcpClient) {
                sb.appendf("0x%x", al->tcpClient->nfmark);
                out = sb.c_str();
            }
            break;

        case LFT_LOCAL_LISTENING_PORT:
            if (al->cache.port) {
                outint = al->cache.port->s.port();
                doint = 1;
            } else if (al->request) {
                outint = al->request->my_addr.port();
                doint = 1;
            }
            break;

        case LFT_CLIENT_LOCAL_PORT:
            if (al->tcpClient) {
                outint = al->tcpClient->local.port();
                doint = 1;
            }
            break;

        case LFT_SERVER_LOCAL_IP_OLD_27:
        case LFT_SERVER_LOCAL_IP:
            if (al->hier.tcpServer)
                out = al->hier.tcpServer->local.toStr(tmp, sizeof(tmp));
            break;

        case LFT_SERVER_LOCAL_PORT:
            if (al->hier.tcpServer) {
                outint = al->hier.tcpServer->local.port();
                doint = 1;
            }
            break;

        case LFT_SERVER_LOCAL_TOS:
            if (al->hier.tcpServer) {
                sb.appendf("0x%x", static_cast<uint32_t>(al->hier.tcpServer->tos));
                out = sb.c_str();
            }
            break;

        case LFT_SERVER_LOCAL_NFMARK:
            if (al->hier.tcpServer) {
                sb.appendf("0x%x", al->hier.tcpServer->nfmark);
                out = sb.c_str();
            }
            break;

        case LFT_CLIENT_HANDSHAKE:
            if (al->request && al->request->clientConnectionManager.valid()) {
                const auto &handshake = al->request->clientConnectionManager->preservedClientData;
                if (const auto rawLength = handshake.length()) {
                    // add 1 byte to optimize the c_str() conversion below
                    char *buf = sb.rawAppendStart(base64_encode_len(rawLength) + 1);

                    struct base64_encode_ctx ctx;
                    base64_encode_init(&ctx);
                    auto encLength = base64_encode_update(&ctx, buf, rawLength, reinterpret_cast<const uint8_t*>(handshake.rawContent()));
                    encLength += base64_encode_final(&ctx, buf + encLength);

                    sb.rawAppendFinish(buf, encLength);
                    out = sb.c_str();
                }
            }
            break;

        case LFT_TIME_SECONDS_SINCE_EPOCH:
            // some platforms store time in 32-bit, some 64-bit...
            outoff = static_cast<int64_t>(current_time.tv_sec);
            dooff = 1;
            break;

        case LFT_TIME_SUBSECOND:
            outint = current_time.tv_usec / fmt->divisor;
            doint = 1;
            break;

        case LFT_TIME_LOCALTIME:
        case LFT_TIME_GMT: {
            const char *spec;
            struct tm *t;
            spec = fmt->data.string;

            if (fmt->type == LFT_TIME_LOCALTIME) {
                if (!spec)
                    spec = "%d/%b/%Y:%H:%M:%S %z";
                t = localtime(&squid_curtime);
            } else {
                if (!spec)
                    spec = "%d/%b/%Y:%H:%M:%S";

                t = gmtime(&squid_curtime);
            }

            strftime(tmp, sizeof(tmp), spec, t);
            out = tmp;
        }
        break;

        case LFT_TIME_START:
            outtv = al->cache.start_time;
            doSec = 1;
            break;

        case LFT_TIME_TO_HANDLE_REQUEST:
            outtv = al->cache.trTime;
            doMsec = 1;
            break;

        case LFT_PEER_RESPONSE_TIME:
            struct timeval peerResponseTime;
            if (al->hier.peerResponseTime(peerResponseTime)) {
                outtv = peerResponseTime;
                doMsec = 1;
            }
            break;

        case LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME: {
            struct timeval totalResponseTime;
            if (al->hier.totalResponseTime(totalResponseTime)) {
                outtv = totalResponseTime;
                doMsec = 1;
            }
        }
        break;

        case LFT_DNS_WAIT_TIME:
            if (al->request && al->request->dnsWait >= 0) {
                // TODO: microsecond precision for dns wait time.
                // Convert miliseconds to timeval struct:
                outtv.tv_sec = al->request->dnsWait / 1000;
                outtv.tv_usec = (al->request->dnsWait % 1000) * 1000;
                doMsec = 1;
            }
            break;

        case LFT_REQUEST_HEADER:
            if (const HttpMsg *msg = actualRequestHeader(al)) {
                sb = StringToSBuf(msg->header.getByName(fmt->data.header.header));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ADAPTED_REQUEST_HEADER:
            if (al->adapted_request) {
                sb = StringToSBuf(al->adapted_request->header.getByName(fmt->data.header.header));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_REPLY_HEADER:
            if (const HttpMsg *msg = actualReplyHeader(al)) {
                sb = StringToSBuf(msg->header.getByName(fmt->data.header.header));
                out = sb.c_str();
                quote = 1;
            }
            break;

#if USE_ADAPTATION
        case LFT_ADAPTATION_SUM_XACT_TIMES:
            if (al->request) {
                Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah) {
                    ah->sumLogString(fmt->data.string, sb);
                    out = sb.c_str();
                }
            }
            break;

        case LFT_ADAPTATION_ALL_XACT_TIMES:
            if (al->request) {
                Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah) {
                    ah->allLogString(fmt->data.string, sb);
                    out = sb.c_str();
                }
            }
            break;

        case LFT_ADAPTATION_LAST_HEADER:
            if (al->request) {
                const Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah) { // XXX: add adapt::<all_h but use lastMeta here
                    sb = StringToSBuf(ah->allMeta.getByName(fmt->data.header.header));
                    out = sb.c_str();
                    quote = 1;
                }
            }
            break;

        case LFT_ADAPTATION_LAST_HEADER_ELEM:
            if (al->request) {
                const Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah) { // XXX: add adapt::<all_h but use lastMeta here
                    sb = StringToSBuf(ah->allMeta.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                    out = sb.c_str();
                    quote = 1;
                }
            }
            break;

        case LFT_ADAPTATION_LAST_ALL_HEADERS:
            out = al->adapt.last_meta;
            quote = 1;
            break;
#endif

#if ICAP_CLIENT
        case LFT_ICAP_ADDR:
            out = al->icap.hostAddr.toStr(tmp, sizeof(tmp));
            break;

        case LFT_ICAP_SERV_NAME:
            out = al->icap.serviceName.termedBuf();
            break;

        case LFT_ICAP_REQUEST_URI:
            out = al->icap.reqUri.termedBuf();
            break;

        case LFT_ICAP_REQUEST_METHOD:
            out = Adaptation::Icap::ICAP::methodStr(al->icap.reqMethod);
            break;

        case LFT_ICAP_BYTES_SENT:
            outoff = al->icap.bytesSent;
            dooff = 1;
            break;

        case LFT_ICAP_BYTES_READ:
            outoff = al->icap.bytesRead;
            dooff = 1;
            break;

        case LFT_ICAP_BODY_BYTES_READ:
            if (al->icap.bodyBytesRead >= 0) {
                outoff = al->icap.bodyBytesRead;
                dooff = 1;
            }
            // else if icap.bodyBytesRead < 0, we do not have any http data,
            // so just print a "-" (204 responses etc)
            break;

        case LFT_ICAP_REQ_HEADER:
            if (al->icap.request) {
                sb = StringToSBuf(al->icap.request->header.getByName(fmt->data.header.header));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_REQ_HEADER_ELEM:
            if (al->icap.request) {
                sb = StringToSBuf(al->icap.request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_REQ_ALL_HEADERS:
            if (al->icap.request) {
                HttpHeaderPos pos = HttpHeaderInitPos;
                while (const HttpHeaderEntry *e = al->icap.request->header.getEntry(&pos)) {
                    sb.append(StringToSBuf(e->name));
                    sb.append(": ");
                    sb.append(StringToSBuf(e->value));
                    sb.append("\r\n");
                }
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_REP_HEADER:
            if (al->icap.reply) {
                sb = StringToSBuf(al->icap.reply->header.getByName(fmt->data.header.header));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_REP_HEADER_ELEM:
            if (al->icap.reply) {
                sb = StringToSBuf(al->icap.reply->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_REP_ALL_HEADERS:
            if (al->icap.reply) {
                HttpHeaderPos pos = HttpHeaderInitPos;
                while (const HttpHeaderEntry *e = al->icap.reply->header.getEntry(&pos)) {
                    sb.append(StringToSBuf(e->name));
                    sb.append(": ");
                    sb.append(StringToSBuf(e->value));
                    sb.append("\r\n");
                }
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ICAP_TR_RESPONSE_TIME:
            outtv = al->icap.trTime;
            doMsec = 1;
            break;

        case LFT_ICAP_IO_TIME:
            outtv = al->icap.ioTime;
            doMsec = 1;
            break;

        case LFT_ICAP_STATUS_CODE:
            outint = al->icap.resStatus;
            doint  = 1;
            break;

        case LFT_ICAP_OUTCOME:
            out = al->icap.outcome;
            break;

        case LFT_ICAP_TOTAL_TIME:
            outtv = al->icap.processingTime;
            doMsec = 1;
            break;
#endif
        case LFT_REQUEST_HEADER_ELEM:
            if (const HttpMsg *msg = actualRequestHeader(al)) {
                sb = StringToSBuf(msg->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_ADAPTED_REQUEST_HEADER_ELEM:
            if (al->adapted_request) {
                sb = StringToSBuf(al->adapted_request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_REPLY_HEADER_ELEM:
            if (const HttpMsg *msg = actualReplyHeader(al)) {
                sb = StringToSBuf(msg->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator));
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_REQUEST_ALL_HEADERS:
#if ICAP_CLIENT
            if (al->icap.reqMethod == Adaptation::methodRespmod) {
                // XXX: since AccessLogEntry::Headers lacks virgin response
                // headers, do nothing for now
                out = nullptr;
            } else
#endif
            {
                out = al->headers.request;
                quote = 1;
            }
            break;

        case LFT_ADAPTED_REQUEST_ALL_HEADERS:
            out = al->headers.adapted_request;
            quote = 1;
            break;

        case LFT_REPLY_ALL_HEADERS:
            out = al->headers.reply;
#if ICAP_CLIENT
            if (!out && al->icap.reqMethod == Adaptation::methodReqmod)
                out = al->headers.adapted_request;
#endif
            quote = 1;
            break;

        case LFT_USER_NAME:
#if USE_AUTH
            if (al->request && al->request->auth_user_request)
                out = strOrNull(al->request->auth_user_request->username());
#endif
            if (!out && al->request && al->request->extacl_user.size()) {
                if (const char *t = al->request->extacl_user.termedBuf())
                    out = t;
            }
            if (!out)
                out = strOrNull(al->getExtUser());
#if USE_OPENSSL
            if (!out)
                out = strOrNull(al->cache.ssluser);
#endif
            if (!out)
                out = strOrNull(al->getClientIdent());
            break;

        case LFT_USER_LOGIN:
#if USE_AUTH
            if (al->request && al->request->auth_user_request)
                out = strOrNull(al->request->auth_user_request->username());
#endif
            break;

        case LFT_USER_IDENT:
            out = strOrNull(al->getClientIdent());
            break;

        case LFT_USER_EXTERNAL:
            out = strOrNull(al->getExtUser());
            break;

        /* case LFT_USER_REALM: */
        /* case LFT_USER_SCHEME: */

        // the fmt->type can not be LFT_HTTP_SENT_STATUS_CODE_OLD_30
        // but compiler complains if ommited
        case LFT_HTTP_SENT_STATUS_CODE_OLD_30:
        case LFT_HTTP_SENT_STATUS_CODE:
            outint = al->http.code;
            doint = 1;
            break;

        case LFT_HTTP_RECEIVED_STATUS_CODE:
            if (al->hier.peer_reply_status != Http::scNone) {
                outint = al->hier.peer_reply_status;
                doint = 1;
            }
            break;
        /* case LFT_HTTP_STATUS:
         *           out = statusline->text;
         *     quote = 1;
         *     break;
         */
        case LFT_HTTP_BODY_BYTES_READ:
            if (al->hier.bodyBytesRead >= 0) {
                outoff = al->hier.bodyBytesRead;
                dooff = 1;
            }
            // else if hier.bodyBytesRead < 0 we did not have any data exchange with
            // a peer server so just print a "-" (eg requests served from cache,
            // or internal error messages).
            break;

        case LFT_SQUID_STATUS:
            out = al->cache.code.c_str();
            break;

        case LFT_SQUID_ERROR:
            if (al->request && al->request->errType != ERR_NONE)
                out = errorPageName(al->request->errType);
            break;

        case LFT_SQUID_ERROR_DETAIL:
#if USE_OPENSSL
            if (al->request && al->request->errType == ERR_SECURE_CONNECT_FAIL) {
                out = Ssl::GetErrorName(al->request->errDetail, true);
            } else
#endif
                if (al->request && al->request->errDetail != ERR_DETAIL_NONE) {
                    if (al->request->errDetail > ERR_DETAIL_START && al->request->errDetail < ERR_DETAIL_MAX)
                        out = errorDetailName(al->request->errDetail);
                    else {
                        if (al->request->errDetail >= ERR_DETAIL_EXCEPTION_START)
                            sb.appendf("%s=0x%X",
                                       errorDetailName(al->request->errDetail), (uint32_t) al->request->errDetail);
                        else
                            sb.appendf("%s=%d",
                                       errorDetailName(al->request->errDetail), al->request->errDetail);
                        out = sb.c_str();
                    }
                }
            break;

        case LFT_SQUID_HIERARCHY:
            if (al->hier.ping.timedout)
                mb.append("TIMEOUT_", 8);
            out = hier_code_str[al->hier.code];
            break;

        case LFT_MIME_TYPE:
            out = al->http.content_type;
            break;

        case LFT_CLIENT_REQ_METHOD:
            if (al->request) {
                sb = al->request->method.image();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_CLIENT_REQ_URI:
            if (const auto uri = al->effectiveVirginUrl()) {
                sb = *uri;
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_CLIENT_REQ_URLSCHEME:
            if (al->request) {
                sb = al->request->url.getScheme().image();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_CLIENT_REQ_URLDOMAIN:
            if (al->request) {
                out = al->request->url.host();
                quote = 1;
            }
            break;

        case LFT_CLIENT_REQ_URLPORT:
            if (al->request) {
                outint = al->request->url.port();
                doint = 1;
            }
            break;

        case LFT_REQUEST_URLPATH_OLD_31:
        case LFT_CLIENT_REQ_URLPATH:
            if (al->request) {
                sb = al->request->url.path();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_CLIENT_REQ_VERSION:
            if (al->request) {
                sb.appendf("%u.%u", al->request->http_ver.major, al->request->http_ver.minor);
                out = sb.c_str();
            }
            break;

        case LFT_REQUEST_METHOD:
            sb = al->getLogMethod();
            out = sb.c_str();
            quote = 1;
            break;

        case LFT_REQUEST_URI:
            if (!al->url.isEmpty()) {
                sb = al->url;
                out = sb.c_str();
            }
            break;

        case LFT_REQUEST_VERSION_OLD_2X:
        case LFT_REQUEST_VERSION:
            sb.appendf("%u.%u", al->http.version.major, al->http.version.minor);
            out = sb.c_str();
            break;

        case LFT_SERVER_REQ_METHOD:
            if (al->adapted_request) {
                sb = al->adapted_request->method.image();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_SERVER_REQ_URI:
            // adapted request URI sent to server/peer
            if (al->adapted_request) {
                sb = al->adapted_request->effectiveRequestUri();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_SERVER_REQ_URLSCHEME:
            if (al->adapted_request) {
                sb = al->adapted_request->url.getScheme().image();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_SERVER_REQ_URLDOMAIN:
            if (al->adapted_request) {
                out = al->adapted_request->url.host();
                quote = 1;
            }
            break;

        case LFT_SERVER_REQ_URLPORT:
            if (al->adapted_request) {
                outint = al->adapted_request->url.port();
                doint = 1;
            }
            break;

        case LFT_SERVER_REQ_URLPATH:
            if (al->adapted_request) {
                sb = al->adapted_request->url.path();
                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_SERVER_REQ_VERSION:
            if (al->adapted_request) {
                sb.appendf("%u.%u",
                           al->adapted_request->http_ver.major,
                           al->adapted_request->http_ver.minor);
                out = tmp;
            }
            break;

        case LFT_CLIENT_REQUEST_SIZE_TOTAL:
            outoff = al->http.clientRequestSz.messageTotal();
            dooff = 1;
            break;

        case LFT_CLIENT_REQUEST_SIZE_HEADERS:
            outoff = al->http.clientRequestSz.header;
            dooff =1;
            break;

        /*case LFT_REQUEST_SIZE_BODY: */
        /*case LFT_REQUEST_SIZE_BODY_NO_TE: */

        case LFT_ADAPTED_REPLY_SIZE_TOTAL:
            outoff = al->http.clientReplySz.messageTotal();
            dooff = 1;
            break;

        case LFT_REPLY_HIGHOFFSET:
            outoff = al->cache.highOffset;
            dooff = 1;
            break;

        case LFT_REPLY_OBJECTSIZE:
            outoff = al->cache.objectSize;
            dooff = 1;
            break;

        case LFT_ADAPTED_REPLY_SIZE_HEADERS:
            outint = al->http.clientReplySz.header;
            doint = 1;
            break;

        /*case LFT_REPLY_SIZE_BODY: */
        /*case LFT_REPLY_SIZE_BODY_NO_TE: */

        case LFT_CLIENT_IO_SIZE_TOTAL:
            outint = al->http.clientRequestSz.messageTotal() + al->http.clientReplySz.messageTotal();
            doint = 1;
            break;
        /*case LFT_SERVER_IO_SIZE_TOTAL: */

        case LFT_TAG:
            if (al->request) {
                out = al->request->tag.termedBuf();
                quote = 1;
            }
            break;

        case LFT_EXT_LOG:
            if (al->request) {
                out = al->request->extacl_log.termedBuf();
                quote = 1;
            }
            break;

        case LFT_SEQUENCE_NUMBER:
            outoff = logSequenceNumber;
            dooff = 1;
            break;

#if USE_OPENSSL
        case LFT_SSL_BUMP_MODE: {
            const Ssl::BumpMode mode = static_cast<Ssl::BumpMode>(al->ssl.bumpMode);
            // for Ssl::bumpEnd, Ssl::bumpMode() returns NULL and we log '-'
            out = Ssl::bumpMode(mode);
        }
        break;

        case LFT_EXT_ACL_USER_CERT_RAW:
            if (al->request) {
                ConnStateData *conn = al->request->clientConnectionManager.get();
                if (conn && Comm::IsConnOpen(conn->clientConnection)) {
                    if (auto ssl = fd_table[conn->clientConnection->fd].ssl.get())
                        out = sslGetUserCertificatePEM(ssl);
                }
            }
            break;

        case LFT_EXT_ACL_USER_CERTCHAIN_RAW:
            if (al->request) {
                ConnStateData *conn = al->request->clientConnectionManager.get();
                if (conn && Comm::IsConnOpen(conn->clientConnection)) {
                    if (auto ssl = fd_table[conn->clientConnection->fd].ssl.get())
                        out = sslGetUserCertificatePEM(ssl);
                }
            }
            break;

        case LFT_EXT_ACL_USER_CERT:
            if (al->request) {
                ConnStateData *conn = al->request->clientConnectionManager.get();
                if (conn && Comm::IsConnOpen(conn->clientConnection)) {
                    if (auto ssl = fd_table[conn->clientConnection->fd].ssl.get())
                        out = sslGetUserAttribute(ssl, fmt->data.header.header);
                }
            }
            break;

        case LFT_EXT_ACL_USER_CA_CERT:
            if (al->request) {
                ConnStateData *conn = al->request->clientConnectionManager.get();
                if (conn && Comm::IsConnOpen(conn->clientConnection)) {
                    if (auto ssl = fd_table[conn->clientConnection->fd].ssl.get())
                        out = sslGetCAAttribute(ssl, fmt->data.header.header);
                }
            }
            break;

        case LFT_SSL_USER_CERT_SUBJECT:
            if (X509 *cert = al->cache.sslClientCert.get()) {
                if (X509_NAME *subject = X509_get_subject_name(cert)) {
                    X509_NAME_oneline(subject, tmp, sizeof(tmp));
                    out = tmp;
                }
            }
            break;

        case LFT_SSL_USER_CERT_ISSUER:
            if (X509 *cert = al->cache.sslClientCert.get()) {
                if (X509_NAME *issuer = X509_get_issuer_name(cert)) {
                    X509_NAME_oneline(issuer, tmp, sizeof(tmp));
                    out = tmp;
                }
            }
            break;

        case LFT_SSL_CLIENT_SNI:
            if (al->request && al->request->clientConnectionManager.valid()) {
                if (const ConnStateData *conn = al->request->clientConnectionManager.get()) {
                    if (!conn->tlsClientSni().isEmpty()) {
                        sb = conn->tlsClientSni();
                        out = sb.c_str();
                    }
                }
            }
            break;

        case LFT_SSL_SERVER_CERT_ERRORS:
            if (al->request && al->request->clientConnectionManager.valid()) {
                if (Ssl::ServerBump * srvBump = al->request->clientConnectionManager->serverBump()) {
                    const char *separator = fmt->data.string ? fmt->data.string : ":";
                    for (const Security::CertErrors *sslError = srvBump->sslErrors(); sslError; sslError = sslError->next) {
                        if (!sb.isEmpty())
                            sb.append(separator);
                        sb.append(Ssl::GetErrorName(sslError->element.code, true));
                        if (sslError->element.depth >= 0)
                            sb.appendf("@depth=%d", sslError->element.depth);
                    }
                    if (!sb.isEmpty())
                        out = sb.c_str();
                }
            }
            break;

        case LFT_SSL_SERVER_CERT_ISSUER:
        case LFT_SSL_SERVER_CERT_SUBJECT:
            if (al->request && al->request->clientConnectionManager.valid()) {
                if (Ssl::ServerBump * srvBump = al->request->clientConnectionManager->serverBump()) {
                    if (X509 *serverCert = srvBump->serverCert.get()) {
                        if (fmt->type == LFT_SSL_SERVER_CERT_SUBJECT)
                            out = Ssl::GetX509UserAttribute(serverCert, "DN");
                        else
                            out = Ssl::GetX509CAAttribute(serverCert, "DN");
                    }
                }
            }
            break;

        case LFT_TLS_CLIENT_NEGOTIATED_VERSION:
            if (al->tcpClient && al->tcpClient->hasTlsNegotiations())
                out = al->tcpClient->hasTlsNegotiations()->negotiatedVersion();
            break;

        case LFT_TLS_SERVER_NEGOTIATED_VERSION:
            if (al->hier.tcpServer && al->hier.tcpServer->hasTlsNegotiations())
                out = al->hier.tcpServer->hasTlsNegotiations()->negotiatedVersion();
            break;

        case LFT_TLS_CLIENT_RECEIVED_HELLO_VERSION:
            if (al->tcpClient && al->tcpClient->hasTlsNegotiations())
                out = al->tcpClient->hasTlsNegotiations()->helloVersion();
            break;

        case LFT_TLS_SERVER_RECEIVED_HELLO_VERSION:
            if (al->hier.tcpServer && al->hier.tcpServer->hasTlsNegotiations())
                out = al->hier.tcpServer->hasTlsNegotiations()->helloVersion();
            break;

        case LFT_TLS_CLIENT_SUPPORTED_VERSION:
            if (al->tcpClient && al->tcpClient->hasTlsNegotiations())
                out = al->tcpClient->hasTlsNegotiations()->supportedVersion();
            break;

        case LFT_TLS_SERVER_SUPPORTED_VERSION:
            if (al->hier.tcpServer && al->hier.tcpServer->hasTlsNegotiations())
                out = al->hier.tcpServer->hasTlsNegotiations()->supportedVersion();
            break;

        case LFT_TLS_CLIENT_NEGOTIATED_CIPHER:
            if (al->tcpClient && al->tcpClient->hasTlsNegotiations())
                out = al->tcpClient->hasTlsNegotiations()->cipherName();
            break;

        case LFT_TLS_SERVER_NEGOTIATED_CIPHER:
            if (al->hier.tcpServer && al->hier.tcpServer->hasTlsNegotiations())
                out = al->hier.tcpServer->hasTlsNegotiations()->cipherName();
            break;
#endif

        case LFT_REQUEST_URLGROUP_OLD_2X:
            assert(LFT_REQUEST_URLGROUP_OLD_2X == 0); // should never happen.

        case LFT_NOTE:
            tmp[0] = fmt->data.header.separator;
            tmp[1] = '\0';
            if (fmt->data.header.header && *fmt->data.header.header) {
                const char *separator = tmp;
#if USE_ADAPTATION
                Adaptation::History::Pointer ah = al->request ? al->request->adaptHistory() : Adaptation::History::Pointer();
                if (ah && ah->metaHeaders) {
                    if (const char *meta = ah->metaHeaders->find(fmt->data.header.header, separator))
                        sb.append(meta);
                }
#endif
                if (al->notes) {
                    if (const char *note = al->notes->find(fmt->data.header.header, separator)) {
                        if (!sb.isEmpty())
                            sb.append(separator);
                        sb.append(note);
                    }
                }
                out = sb.c_str();
                quote = 1;
            } else {
                // if no argument given use default "\r\n" as notes separator
                const char *separator = fmt->data.string ? tmp : "\r\n";
#if USE_ADAPTATION
                Adaptation::History::Pointer ah = al->request ? al->request->adaptHistory() : Adaptation::History::Pointer();
                if (ah && ah->metaHeaders && !ah->metaHeaders->empty())
                    sb.append(ah->metaHeaders->toString(separator));
#endif
                if (al->notes && !al->notes->empty())
                    sb.append(al->notes->toString(separator));

                out = sb.c_str();
                quote = 1;
            }
            break;

        case LFT_CREDENTIALS:
#if USE_AUTH
            if (al->request && al->request->auth_user_request)
                out = strOrNull(al->request->auth_user_request->credentialsStr());
#endif
            break;

        case LFT_PERCENT:
            out = "%";
            break;

        case LFT_EXT_ACL_NAME:
            out = al->lastAclName;
            break;

        case LFT_EXT_ACL_DATA:
            if (!al->lastAclData.isEmpty())
                out = al->lastAclData.c_str();
            break;
        }

        if (dooff) {
            sb.appendf("%0*" PRId64, fmt->zero && fmt->widthMin >= 0 ? fmt->widthMin : 0, outoff);
            out = sb.c_str();

        } else if (doint) {
            sb.appendf("%0*ld", fmt->zero && fmt->widthMin >= 0 ? fmt->widthMin : 0, outint);
            out = sb.c_str();
        } else if (doMsec) {
            if (fmt->widthMax < 0) {
                sb.appendf("%0*ld", fmt->zero && fmt->widthMin >= 0 ? fmt->widthMin : 0, tvToMsec(outtv));
            } else {
                int precision = fmt->widthMax;
                sb.appendf("%0*" PRId64 ".%0*" PRId64 "", fmt->zero && (fmt->widthMin - precision - 1 >= 0) ? fmt->widthMin - precision - 1 : 0, static_cast<int64_t>(outtv.tv_sec * 1000 + outtv.tv_usec / 1000), precision, static_cast<int64_t>((outtv.tv_usec % 1000 )* (1000 / fmt->divisor)));
            }
            out = sb.c_str();
        } else if (doSec) {
            int precision = fmt->widthMax >=0 ? fmt->widthMax :3;
            sb.appendf("%0*" PRId64 ".%0*d", fmt->zero && (fmt->widthMin - precision - 1 >= 0) ? fmt->widthMin - precision - 1 : 0, static_cast<int64_t>(outtv.tv_sec), precision, (int)(outtv.tv_usec / fmt->divisor));
            out = sb.c_str();
        }

        if (out && *out) {
            if (quote || fmt->quote != LOG_QUOTE_NONE) {
                // Do not write to the tmp buffer because it may contain the to-be-quoted value.
                static char quotedOut[2 * sizeof(tmp)];
                static_assert(sizeof(quotedOut) > 0, "quotedOut has zero length");
                quotedOut[0] = '\0';

                char *newout = NULL;
                int newfree = 0;

                switch (fmt->quote) {

                case LOG_QUOTE_NONE:
                    newout = rfc1738_escape_unescaped(out);
                    break;

                case LOG_QUOTE_QUOTES: {
                    size_t out_len = static_cast<size_t>(strlen(out)) * 2 + 1;
                    if (out_len >= sizeof(tmp)) {
                        newout = (char *)xmalloc(out_len);
                        newfree = 1;
                    } else
                        newout = quotedOut;
                    log_quoted_string(out, newout);
                }
                break;

                case LOG_QUOTE_MIMEBLOB:
                    newout = QuoteMimeBlob(out);
                    newfree = 1;
                    break;

                case LOG_QUOTE_URL:
                    newout = rfc1738_escape(out);
                    break;

                case LOG_QUOTE_SHELL: {
                    MemBuf mbq;
                    mbq.init();
                    strwordquote(&mbq, out);
                    newout = mbq.content();
                    mbq.stolen = 1;
                    newfree = 1;
                }
                break;

                case LOG_QUOTE_RAW:
                    break;
                }

                if (newout) {
                    if (dofree)
                        safe_free(out);

                    out = newout;

                    dofree = newfree;
                }
            }

            // enforce width limits if configured
            const bool haveMaxWidth = fmt->widthMax >=0 && !doint && !dooff && !doMsec && !doSec;
            if (haveMaxWidth || fmt->widthMin) {
                const int minWidth = fmt->widthMin >= 0 ?
                                     fmt->widthMin :0;
                const int maxWidth = haveMaxWidth ?
                                     fmt->widthMax : strlen(out);

                if (fmt->left)
                    mb.appendf("%-*.*s", minWidth, maxWidth, out);
                else
                    mb.appendf("%*.*s", minWidth, maxWidth, out);
            } else
                mb.append(out, strlen(out));
        } else {
            mb.append("-", 1);
        }

        if (fmt->space)
            mb.append(" ", 1);

        sb.clear();

        if (dofree)
            safe_free(out);
    }
}


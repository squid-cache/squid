/*
 * $Id$
 *
 * DEBUG: section 46    Access Log - Squid Custom format
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "config.h"
#include "AccessLogEntry.h"
#include "log/File.h"
#include "log/Formats.h"
#include "log/Gadgets.h"
#include "log/Tokens.h"
#include "SquidTime.h"

#include "MemBuf.h"
#include "HttpRequest.h"
#include "rfc1738.h"
#include "err_detail_type.h"
#include "errorpage.h"

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
            *p++ = '\\';
            *p++ = 'r';
            str++;
            break;

        case '\n':
            *p++ = '\\';
            *p++ = 'n';
            str++;
            break;

        case '\t':
            *p++ = '\\';
            *p++ = 't';
            str++;
            break;

        default:
            *p++ = '\\';
            *p++ = *str;
            str++;
            break;
        }
    }

    *p++ = '\0';
}

void
Log::Format::SquidCustom(AccessLogEntry * al, customlog * log)
{
    logformat *lf;
    Logfile *logfile;
    logformat_token *fmt;
    static MemBuf mb;
    char tmp[1024];
    String sb;

    mb.reset();

    lf = log->logFormat;
    logfile = log->logfile;

    for (fmt = lf->format; fmt != NULL; fmt = fmt->next) {	/* for each token */
        const char *out = NULL;
        int quote = 0;
        long int outint = 0;
        int doint = 0;
        int dofree = 0;
        int64_t outoff = 0;
        int dooff = 0;

        switch (fmt->type) {

        case LFT_NONE:
            out = "";
            break;

        case LFT_STRING:
            out = fmt->data.string;
            break;

        case LFT_CLIENT_IP_ADDRESS:
            if (al->cache.caddr.IsNoAddr()) // e.g., ICAP OPTIONS lack client
                out = "-";
            else
                out = al->cache.caddr.NtoA(tmp,1024);
            break;

        case LFT_CLIENT_FQDN:
            if (al->cache.caddr.IsAnyAddr()) // e.g., ICAP OPTIONS lack client
                out = "-";
            else
                out = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);
            if (!out) {
                out = al->cache.caddr.NtoA(tmp,1024);
            }

            break;

        case LFT_CLIENT_PORT:
            if (al->request) {
                outint = al->request->client_addr.GetPort();
                doint = 1;
            }
            break;

#if USE_SQUID_EUI
        case LFT_CLIENT_EUI:
            if (al->request) {
                if (al->cache.caddr.IsIPv4())
                    al->request->client_eui48.encode(tmp, 1024);
                else
                    al->request->client_eui64.encode(tmp, 1024);
                out = tmp;
            }
            break;
#endif

            /* case LFT_SERVER_IP_ADDRESS: */

        case LFT_SERVER_IP_OR_PEER_NAME:
            out = al->hier.host;

            break;

            /* case LFT_SERVER_PORT: */

        case LFT_LOCAL_IP:
            if (al->request) {
                out = al->request->my_addr.NtoA(tmp,1024);
            }

            break;

        case LFT_LOCAL_PORT:
            if (al->request) {
                outint = al->request->my_addr.GetPort();
                doint = 1;
            }

            break;

        case LFT_PEER_LOCAL_PORT:
            if (al->hier.peer_local_port) {
                outint = al->hier.peer_local_port;
                doint = 1;
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
            spec = fmt->data.timespec;

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

        case LFT_TIME_TO_HANDLE_REQUEST:
            outint = al->cache.msec;
            doint = 1;
            break;

        case LFT_PEER_RESPONSE_TIME:
            if (al->hier.peer_response_time < 0) {
                out = "-";
            } else {
                outoff = al->hier.peer_response_time;
                dooff = 1;
            }
            break;

        case LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME:
            if (al->hier.total_response_time < 0) {
                out = "-";
            } else {
                outoff = al->hier.total_response_time;
                dooff = 1;
            }
            break;

        case LFT_DNS_WAIT_TIME:
            if (al->request && al->request->dnsWait >= 0) {
                outint = al->request->dnsWait;
                doint = 1;
            }
            break;

        case LFT_REQUEST_HEADER:

            if (al->request)
                sb = al->request->header.getByName(fmt->data.header.header);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ADAPTED_REQUEST_HEADER:

            if (al->request)
                sb = al->adapted_request->header.getByName(fmt->data.header.header);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_REPLY_HEADER:
            if (al->reply)
                sb = al->reply->header.getByName(fmt->data.header.header);

            out = sb.termedBuf();

            quote = 1;

            break;

#if USE_ADAPTATION
        case LTF_ADAPTATION_SUM_XACT_TIMES:
            if (al->request) {
                Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah != NULL)
                    ah->sumLogString(fmt->data.string, sb);
                out = sb.termedBuf();
            }
            break;

        case LTF_ADAPTATION_ALL_XACT_TIMES:
            if (al->request) {
                Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah != NULL)
                    ah->allLogString(fmt->data.string, sb);
                out = sb.termedBuf();
            }
            break;

        case LFT_ADAPTATION_LAST_HEADER:
            if (al->request) {
                const Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah != NULL) // XXX: add adapt::<all_h but use lastMeta here
                    sb = ah->allMeta.getByName(fmt->data.header.header);
            }

            // XXX: here and elsewhere: move such code inside the if guard
            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ADAPTATION_LAST_HEADER_ELEM:
            if (al->request) {
                const Adaptation::History::Pointer ah = al->request->adaptHistory();
                if (ah != NULL) // XXX: add adapt::<all_h but use lastMeta here
                    sb = ah->allMeta.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);
            }

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ADAPTATION_LAST_ALL_HEADERS:
            out = al->headers.adapt_last;

            quote = 1;

            break;
#endif

#if ICAP_CLIENT
        case LFT_ICAP_ADDR:
            if (!out)
                out = al->icap.hostAddr.NtoA(tmp,1024);
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
            if (NULL != al->icap.request) {
                sb = al->icap.request->header.getByName(fmt->data.header.header);
                out = sb.termedBuf();
                quote = 1;
            }
            break;

        case LFT_ICAP_REQ_HEADER_ELEM:
            if (al->request)
                sb = al->icap.request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ICAP_REQ_ALL_HEADERS:
            if (al->icap.request) {
                HttpHeaderPos pos = HttpHeaderInitPos;
                while (const HttpHeaderEntry *e = al->icap.request->header.getEntry(&pos)) {
                    sb.append(e->name);
                    sb.append(": ");
                    sb.append(e->value);
                    sb.append("\r\n");
                }
                out = sb.termedBuf();
                quote = 1;
            }
            break;

        case LFT_ICAP_REP_HEADER:
            if (NULL != al->icap.reply) {
                sb = al->icap.reply->header.getByName(fmt->data.header.header);
                out = sb.termedBuf();
                quote = 1;
            }
            break;

        case LFT_ICAP_REP_HEADER_ELEM:
            if (NULL != al->icap.reply)
                sb = al->icap.reply->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ICAP_REP_ALL_HEADERS:
            if (al->icap.reply) {
                HttpHeaderPos pos = HttpHeaderInitPos;
                while (const HttpHeaderEntry *e = al->icap.reply->header.getEntry(&pos)) {
                    sb.append(e->name);
                    sb.append(": ");
                    sb.append(e->value);
                    sb.append("\r\n");
                }
                out = sb.termedBuf();
                quote = 1;
            }
            break;

        case LFT_ICAP_TR_RESPONSE_TIME:
            outint = al->icap.trTime;
            doint = 1;
            break;

        case LFT_ICAP_IO_TIME:
            outint = al->icap.ioTime;
            doint = 1;
            break;

        case LFT_ICAP_STATUS_CODE:
            outint = al->icap.resStatus;
            doint  = 1;
            break;

        case LFT_ICAP_OUTCOME:
            out = al->icap.outcome;
            break;

        case LFT_ICAP_TOTAL_TIME:
            outint = al->icap.processingTime;
            doint = 1;
            break;
#endif
        case LFT_REQUEST_HEADER_ELEM:
            if (al->request)
                sb = al->request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_ADAPTED_REQUEST_HEADER_ELEM:
            if (al->adapted_request)
                sb = al->adapted_request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_REPLY_HEADER_ELEM:
            if (al->reply)
                sb = al->reply->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.termedBuf();

            quote = 1;

            break;

        case LFT_REQUEST_ALL_HEADERS:
            out = al->headers.request;

            quote = 1;

            break;

        case LFT_ADAPTED_REQUEST_ALL_HEADERS:
            out = al->headers.adapted_request;

            quote = 1;

            break;

        case LFT_REPLY_ALL_HEADERS:
            out = al->headers.reply;

            quote = 1;

            break;

        case LFT_USER_NAME:
            out = Log::FormatName(al->cache.authuser);

            if (!out)
                out = Log::FormatName(al->cache.extuser);

#if USE_SSL

            if (!out)
                out = Log::FormatName(al->cache.ssluser);

#endif

            if (!out)
                out = Log::FormatName(al->cache.rfc931);

            dofree = 1;

            break;

        case LFT_USER_LOGIN:
            out = Log::FormatName(al->cache.authuser);

            dofree = 1;

            break;

        case LFT_USER_IDENT:
            out = Log::FormatName(al->cache.rfc931);

            dofree = 1;

            break;

        case LFT_USER_EXTERNAL:
            out = Log::FormatName(al->cache.extuser);

            dofree = 1;

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
            if (al->hier.peer_reply_status == HTTP_STATUS_NONE) {
                out = "-";
            } else {
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
            if (al->http.timedout || al->http.aborted) {
                snprintf(tmp, sizeof(tmp), "%s%s", log_tags[al->cache.code],
                         al->http.statusSfx());
                out = tmp;
            } else {
                out = log_tags[al->cache.code];
            }

            break;

        case LFT_SQUID_ERROR:
            if (al->request && al->request->errType != ERR_NONE)
                out = errorPageName(al->request->errType);
            break;

        case LFT_SQUID_ERROR_DETAIL:
            if (al->request && al->request->errDetail != ERR_DETAIL_NONE) {
                if (al->request->errDetail > ERR_DETAIL_START  &&
                        al->request->errDetail < ERR_DETAIL_MAX)
                    out = errorDetailName(al->request->errDetail);
                else {
                    if (al->request->errDetail >= ERR_DETAIL_EXCEPTION_START)
                        snprintf(tmp, sizeof(tmp), "%s=0x%X",
                                 errorDetailName(al->request->errDetail), (uint32_t) al->request->errDetail);
                    else
                        snprintf(tmp, sizeof(tmp), "%s=%d",
                                 errorDetailName(al->request->errDetail), al->request->errDetail);
                    out = tmp;
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

        case LFT_REQUEST_METHOD:
            out = al->_private.method_str;

            break;

        case LFT_REQUEST_URI:
            out = al->url;

            break;

        case LFT_REQUEST_URLPATH:
            if (al->request) {
                out = al->request->urlpath.termedBuf();
                quote = 1;
            }
            break;

        case LFT_REQUEST_VERSION:
            snprintf(tmp, sizeof(tmp), "%d.%d", (int) al->http.version.major, (int) al->http.version.minor);
            out = tmp;
            break;

        case LFT_REQUEST_SIZE_TOTAL:
            outoff = al->cache.requestSize;
            dooff = 1;
            break;

            /*case LFT_REQUEST_SIZE_LINE: */
        case LFT_REQUEST_SIZE_HEADERS:
            outoff = al->cache.requestHeadersSize;
            dooff =1;
            break;
            /*case LFT_REQUEST_SIZE_BODY: */
            /*case LFT_REQUEST_SIZE_BODY_NO_TE: */

        case LFT_REPLY_SIZE_TOTAL:
            outoff = al->cache.replySize;
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

            /*case LFT_REPLY_SIZE_LINE: */
        case LFT_REPLY_SIZE_HEADERS:
            outint = al->cache.replyHeadersSize;
            doint = 1;
            break;
            /*case LFT_REPLY_SIZE_BODY: */
            /*case LFT_REPLY_SIZE_BODY_NO_TE: */

        case LFT_TAG:
            if (al->request)
                out = al->request->tag.termedBuf();

            quote = 1;

            break;

        case LFT_IO_SIZE_TOTAL:
            outint = al->cache.requestSize + al->cache.replySize;
            doint = 1;
            break;

        case LFT_EXT_LOG:
            if (al->request)
                out = al->request->extacl_log.termedBuf();

            quote = 1;

            break;

        case LFT_SEQUENCE_NUMBER:
            outoff = logfile->sequence_number;
            dooff = 1;
            break;

        case LFT_PERCENT:
            out = "%";

            break;
        }

        if (dooff) {
            snprintf(tmp, sizeof(tmp), "%0*" PRId64, fmt->zero ? (int) fmt->width : 0, outoff);
            out = tmp;

        } else if (doint) {
            snprintf(tmp, sizeof(tmp), "%0*ld", fmt->zero ? (int) fmt->width : 0, outint);
            out = tmp;
        }

        if (out && *out) {
            if (quote || fmt->quote != LOG_QUOTE_NONE) {
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
                        newout = tmp;
                    log_quoted_string(out, newout);
                }
                break;

                case LOG_QUOTE_MIMEBLOB:
                    newout = Log::QuoteMimeBlob(out);
                    newfree = 1;
                    break;

                case LOG_QUOTE_URL:
                    newout = rfc1738_escape(out);
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

            if (fmt->width) {
                if (fmt->left)
                    mb.Printf("%-*s", (int) fmt->width, out);
                else
                    mb.Printf("%*s", (int) fmt->width, out);
            } else
                mb.append(out, strlen(out));
        } else {
            mb.append("-", 1);
        }

        if (fmt->space)
            mb.append(" ", 1);

        sb.clean();

        if (dofree)
            safe_free(out);
    }

    logfilePrintf(logfile, "%s\n", mb.buf);
}

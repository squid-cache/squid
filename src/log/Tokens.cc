/*
 * $Id$
 *
 * DEBUG: section 46    Access Log Format Tokens
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
#include "log/Tokens.h"
#include "Store.h"

const char *log_tags[] = {
    "NONE",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_REFRESH_UNMODIFIED",
    "TCP_REFRESH_FAIL", // same tag logged for LOG_TCP_REFRESH_FAIL_OLD and
    "TCP_REFRESH_FAIL", // LOG_TCP_REFRESH_FAIL_ERR for backward-compatibility
    "TCP_REFRESH_MODIFIED",
    "TCP_CLIENT_REFRESH_MISS",
    "TCP_IMS_HIT",
    "TCP_SWAPFAIL_MISS",
    "TCP_NEGATIVE_HIT",
    "TCP_MEM_HIT",
    "TCP_DENIED",
    "TCP_DENIED_REPLY",
    "TCP_OFFLINE_HIT",
#if LOG_TCP_REDIRECTS
    "TCP_REDIRECT",
#endif
    "UDP_HIT",
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "UDP_MISS_NOFETCH",
    "ICP_QUERY",
    "LOG_TYPE_MAX"
};

#if USE_ADAPTATION
bool alLogformatHasAdaptToken = false;
#endif

#if ICAP_CLIENT
bool alLogformatHasIcapToken = false;
#endif

struct logformat_token_table_entry logformat_token_table[] = {

    {">a", LFT_CLIENT_IP_ADDRESS},
    {">p", LFT_CLIENT_PORT},
    {">A", LFT_CLIENT_FQDN},
#if USE_SQUID_EUI
    {">eui", LFT_CLIENT_EUI},
#endif

    /*{ "<a", LFT_SERVER_IP_ADDRESS }, */
    /*{ "<p", LFT_SERVER_PORT }, */
    {"<A", LFT_SERVER_IP_OR_PEER_NAME},

    /* {"oa", LFT_OUTGOING_IP}, */
    /* {"ot", LFT_OUTGOING_TOS}, */

    {"la", LFT_LOCAL_IP},
    {"lp", LFT_LOCAL_PORT},
    /*{ "lA", LFT_LOCAL_NAME }, */
    {"<lp", LFT_PEER_LOCAL_PORT},

    {"ts", LFT_TIME_SECONDS_SINCE_EPOCH},
    {"tu", LFT_TIME_SUBSECOND},
    {"tl", LFT_TIME_LOCALTIME},
    {"tg", LFT_TIME_GMT},
    {"tr", LFT_TIME_TO_HANDLE_REQUEST},

    {"<pt", LFT_PEER_RESPONSE_TIME},
    {"<tt", LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME},
    {"dt", LFT_DNS_WAIT_TIME},

    {">ha", LFT_ADAPTED_REQUEST_HEADER},
    {">ha", LFT_ADAPTED_REQUEST_ALL_HEADERS},
    {">h", LFT_REQUEST_HEADER},
    {">h", LFT_REQUEST_ALL_HEADERS},
    {"<h", LFT_REPLY_HEADER},
    {"<h", LFT_REPLY_ALL_HEADERS},

    {"un", LFT_USER_NAME},
    {"ul", LFT_USER_LOGIN},
    /*{ "ur", LFT_USER_REALM }, */
    /*{ "us", LFT_USER_SCHEME }, */
    {"ui", LFT_USER_IDENT},
    {"ue", LFT_USER_EXTERNAL},

    {"Hs", LFT_HTTP_SENT_STATUS_CODE_OLD_30},
    {">Hs", LFT_HTTP_SENT_STATUS_CODE},
    {"<Hs", LFT_HTTP_RECEIVED_STATUS_CODE},
    /*{ "Ht", LFT_HTTP_STATUS }, */
    {"<bs", LFT_HTTP_BODY_BYTES_READ},

    {"Ss", LFT_SQUID_STATUS},
    { "err_code", LFT_SQUID_ERROR },
    { "err_detail", LFT_SQUID_ERROR_DETAIL },
    {"Sh", LFT_SQUID_HIERARCHY},

    {"mt", LFT_MIME_TYPE},

    {"rm", LFT_REQUEST_METHOD},
    {"ru", LFT_REQUEST_URI},	/* doesn't include the query-string */
    {"rp", LFT_REQUEST_URLPATH},	/* doesn't include the host */
    /* { "rq", LFT_REQUEST_QUERY }, * /     / * the query-string, INCLUDING the leading ? */
    {">v", LFT_REQUEST_VERSION},
    {"rv", LFT_REQUEST_VERSION},

    { ">st", LFT_REQUEST_SIZE_TOTAL },
    /*{ ">sl", LFT_REQUEST_SIZE_LINE }, * / / * the request line "GET ... " */
    { ">sh", LFT_REQUEST_SIZE_HEADERS },
    /*{ ">sb", LFT_REQUEST_SIZE_BODY }, */
    /*{ ">sB", LFT_REQUEST_SIZE_BODY_NO_TE }, */

    {"<st", LFT_REPLY_SIZE_TOTAL},
    {"<sH", LFT_REPLY_HIGHOFFSET},
    {"<sS", LFT_REPLY_OBJECTSIZE},
    /*{ "<sl", LFT_REPLY_SIZE_LINE }, * /   / * the reply line (protocol, code, text) */
    { "<sh", LFT_REPLY_SIZE_HEADERS },
    /*{ "<sb", LFT_REPLY_SIZE_BODY }, */
    /*{ "<sB", LFT_REPLY_SIZE_BODY_NO_TE }, */

    {"et", LFT_TAG},
    {"st", LFT_IO_SIZE_TOTAL},
    {"ea", LFT_EXT_LOG},
    {"sn", LFT_SEQUENCE_NUMBER},

    {"%", LFT_PERCENT},

#if USE_ADAPTATION
    {"adapt::all_trs", LTF_ADAPTATION_ALL_XACT_TIMES},
    {"adapt::sum_trs", LTF_ADAPTATION_SUM_XACT_TIMES},
#endif

#if ICAP_CLIENT
    {"icap::tt", LFT_ICAP_TOTAL_TIME},
    {"icap::<last_h", LFT_ICAP_LAST_MATCHED_HEADER},

    {"icap::<A",  LFT_ICAP_ADDR},
    {"icap::<service_name",  LFT_ICAP_SERV_NAME},
    {"icap::ru",  LFT_ICAP_REQUEST_URI},
    {"icap::rm",  LFT_ICAP_REQUEST_METHOD},
    {"icap::>st",  LFT_ICAP_BYTES_SENT},
    {"icap::<st",  LFT_ICAP_BYTES_READ},
    {"icap::<bs", LFT_ICAP_BODY_BYTES_READ},

    {"icap::>h",  LFT_ICAP_REQ_HEADER},
    {"icap::<h",  LFT_ICAP_REP_HEADER},

    {"icap::tr",  LFT_ICAP_TR_RESPONSE_TIME},
    {"icap::tio",  LFT_ICAP_IO_TIME},
    {"icap::to",  LFT_ICAP_OUTCOME},
    {"icap::Hs",  LFT_ICAP_STATUS_CODE},
#endif

    {NULL, LFT_NONE}		/* this must be last */
};

/* parses a single token. Returns the token length in characters,
 * and fills in the lt item with the token information.
 * def is for sure null-terminated
 */
int
accessLogGetNewLogFormatToken(logformat_token * lt, char *def, enum log_quote *quote)
{
    char *cur = def;

    struct logformat_token_table_entry *lte;
    int l;

    memset(lt, 0, sizeof(*lt));
    l = strcspn(cur, "%");

    if (l > 0) {
        char *cp;
        /* it's a string for sure, until \0 or the next % */
        cp = (char *)xmalloc(l + 1);
        xstrncpy(cp, cur, l + 1);
        lt->type = LFT_STRING;
        lt->data.string = cp;

        while (l > 0) {
            switch (*cur) {

            case '"':

                if (*quote == LOG_QUOTE_NONE)
                    *quote = LOG_QUOTE_QUOTES;
                else if (*quote == LOG_QUOTE_QUOTES)
                    *quote = LOG_QUOTE_NONE;

                break;

            case '[':
                if (*quote == LOG_QUOTE_NONE)
                    *quote = LOG_QUOTE_MIMEBLOB;

                break;

            case ']':
                if (*quote == LOG_QUOTE_MIMEBLOB)
                    *quote = LOG_QUOTE_NONE;

                break;
            }

            cur++;
            l--;
        }

        goto done;
    }

    if (!*cur)
        goto done;

    cur++;

    switch (*cur) {

    case '"':
        lt->quote = LOG_QUOTE_QUOTES;
        cur++;
        break;

    case '\'':
        lt->quote = LOG_QUOTE_RAW;
        cur++;
        break;

    case '[':
        lt->quote = LOG_QUOTE_MIMEBLOB;
        cur++;
        break;

    case '#':
        lt->quote = LOG_QUOTE_URL;
        cur++;
        break;

    default:
        lt->quote = *quote;
        break;
    }

    if (*cur == '-') {
        lt->left = 1;
        cur++;
    }

    if (*cur == '0') {
        lt->zero = 1;
        cur++;
    }

    if (xisdigit(*cur))
        lt->width = strtol(cur, &cur, 10);

    if (*cur == '.')
        lt->precision = strtol(cur + 1, &cur, 10);

    if (*cur == '{') {
        char *cp;
        cur++;
        l = strcspn(cur, "}");
        cp = (char *)xmalloc(l + 1);
        xstrncpy(cp, cur, l + 1);
        lt->data.string = cp;
        cur += l;

        if (*cur == '}')
            cur++;
    }

    // For upward compatibility, assume "http::" prefix as default prefix
    // for all log access formating codes, except those starting
    // from "icap::", "adapt::" and "%"
    if (strncmp(cur,"http::", 6) == 0 &&
            strncmp(cur+6, "icap::", 6) != 0  &&
            strncmp(cur+6, "adapt::", 12) != 0 && *(cur+6) != '%' ) {
        cur += 6;
    }

    lt->type = LFT_NONE;

    for (lte = logformat_token_table; lte->config != NULL; lte++) {
        if (strncmp(lte->config, cur, strlen(lte->config)) == 0) {
            lt->type = lte->token_type;
            cur += strlen(lte->config);
            break;
        }
    }

    if (lt->type == LFT_NONE) {
        fatalf("Can't parse configuration token: '%s'\n",
               def);
    }

    if (*cur == ' ') {
        lt->space = 1;
        cur++;
    }

done:

    switch (lt->type) {

#if ICAP_CLIENT
    case LFT_ICAP_LAST_MATCHED_HEADER:

    case LFT_ICAP_REQ_HEADER:

    case LFT_ICAP_REP_HEADER:
#endif

    case LFT_ADAPTED_REQUEST_HEADER:

    case LFT_REQUEST_HEADER:

    case LFT_REPLY_HEADER:

        if (lt->data.string) {
            char *header = lt->data.string;
            char *cp = strchr(header, ':');

            if (cp) {
                *cp++ = '\0';

                if (*cp == ',' || *cp == ';' || *cp == ':')
                    lt->data.header.separator = *cp++;
                else
                    lt->data.header.separator = ',';

                lt->data.header.element = cp;

                switch (lt->type) {
                case LFT_REQUEST_HEADER:
                    lt->type = LFT_REQUEST_HEADER_ELEM;
                    break;

                case LFT_ADAPTED_REQUEST_HEADER:
                    lt->type = LFT_ADAPTED_REQUEST_HEADER_ELEM;
                    break;

                case LFT_REPLY_HEADER:
                    lt->type = LFT_REPLY_HEADER_ELEM;
                    break;
#if ICAP_CLIENT
                case LFT_ICAP_LAST_MATCHED_HEADER:
                    lt->type = LFT_ICAP_LAST_MATCHED_HEADER_ELEM;
                    break;
                case LFT_ICAP_REQ_HEADER:
                    lt->type = LFT_ICAP_REQ_HEADER_ELEM;
                    break;
                case LFT_ICAP_REP_HEADER:
                    lt->type = LFT_ICAP_REP_HEADER_ELEM;
                    break;
#endif
                default:
                    break;
                }
            }

            lt->data.header.header = header;
        } else {
            switch (lt->type) {
            case LFT_REQUEST_HEADER:
                lt->type = LFT_REQUEST_ALL_HEADERS;
                break;

            case LFT_ADAPTED_REQUEST_HEADER:
                lt->type = LFT_ADAPTED_REQUEST_ALL_HEADERS;
                break;

            case LFT_REPLY_HEADER:
                lt->type = LFT_REPLY_ALL_HEADERS;
                break;
#if ICAP_CLIENT
            case LFT_ICAP_LAST_MATCHED_HEADER:
                lt->type = LFT_ICAP_LAST_MATCHED_ALL_HEADERS;
                break;
            case LFT_ICAP_REQ_HEADER:
                lt->type = LFT_ICAP_REQ_ALL_HEADERS;
                break;
            case LFT_ICAP_REP_HEADER:
                lt->type = LFT_ICAP_REP_ALL_HEADERS;
                break;
#endif
            default:
                break;
            }
            Config.onoff.log_mime_hdrs = 1;
        }

        break;

    case LFT_CLIENT_FQDN:
        Config.onoff.log_fqdn = 1;
        break;

    case LFT_TIME_SUBSECOND:
        lt->divisor = 1000;

        if (lt->precision) {
            int i;
            lt->divisor = 1000000;

            for (i = lt->precision; i > 1; i--)
                lt->divisor /= 10;

            if (!lt->divisor)
                lt->divisor = 0;
        }

        break;

    case LFT_HTTP_SENT_STATUS_CODE_OLD_30:
        debugs(46, 0, "WARNING: the \"Hs\" formating code is deprecated use the \">Hs\" instead");
        lt->type = LFT_HTTP_SENT_STATUS_CODE;
        break;
    default:
        break;
    }

    return (cur - def);
}

int
accessLogParseLogFormat(logformat_token ** fmt, char *def)
{
    char *cur, *eos;
    logformat_token *new_lt, *last_lt;
    enum log_quote quote = LOG_QUOTE_NONE;

    debugs(46, 2, "accessLogParseLogFormat: got definition '" << def << "'");

    /* very inefficent parser, but who cares, this needs to be simple */
    /* First off, let's tokenize, we'll optimize in a second pass.
     * A token can either be a %-prefixed sequence (usually a dynamic
     * token but it can be an escaped sequence), or a string. */
    cur = def;
    eos = def + strlen(def);
    *fmt = new_lt = last_lt = (logformat_token *)xmalloc(sizeof(logformat_token));
    cur += accessLogGetNewLogFormatToken(new_lt, cur, &quote);

    while (cur < eos) {
        new_lt = (logformat_token *)xmalloc(sizeof(logformat_token));
        last_lt->next = new_lt;
        last_lt = new_lt;
        cur += accessLogGetNewLogFormatToken(new_lt, cur, &quote);
    }

    return 1;
}

void
accessLogDumpLogFormat(StoreEntry * entry, const char *name, logformat * definitions)
{
    logformat_token *t;
    logformat *format;

    struct logformat_token_table_entry *te;
    debugs(46, 4, "accessLogDumpLogFormat called");

    for (format = definitions; format; format = format->next) {
        debugs(46, 3, "Dumping logformat definition for " << format->name);
        storeAppendPrintf(entry, "logformat %s ", format->name);

        for (t = format->format; t; t = t->next) {
            if (t->type == LFT_STRING)
                storeAppendPrintf(entry, "%s", t->data.string);
            else {
                char argbuf[256];
                char *arg = NULL;
                logformat_bcode_t type = t->type;

                switch (type) {
                    /* special cases */

                case LFT_STRING:
                    break;
#if ICAP_CLIENT
                case LFT_ICAP_LAST_MATCHED_HEADER_ELEM:
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
                        type = LFT_REQUEST_HEADER_ELEM;
                        break;
                    case LFT_ADAPTED_REQUEST_HEADER_ELEM:
                        type = LFT_ADAPTED_REQUEST_HEADER_ELEM;
                        break;
                    case LFT_REPLY_HEADER_ELEM:
                        type = LFT_REPLY_HEADER_ELEM;
                        break;
#if ICAP_CLIENT
                    case LFT_ICAP_LAST_MATCHED_HEADER_ELEM:
                        type = LFT_ICAP_LAST_MATCHED_HEADER;
                        break;
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

#if ICAP_CLIENT
                case LFT_ICAP_LAST_MATCHED_ALL_HEADERS:
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
#if ICAP_CLIENT
                    case LFT_ICAP_LAST_MATCHED_ALL_HEADERS:
                        type = LFT_ICAP_LAST_MATCHED_HEADER;
                        break;
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

                case LOG_QUOTE_NONE:
                    break;
                }

                if (t->left)
                    entry->append("-", 1);

                if (t->zero)
                    entry->append("0", 1);

                if (t->width)
                    storeAppendPrintf(entry, "%d", (int) t->width);

                if (t->precision)
                    storeAppendPrintf(entry, ".%d", (int) t->precision);

                if (arg)
                    storeAppendPrintf(entry, "{%s}", arg);

                for (te = logformat_token_table; te->config != NULL; te++) {
                    if (te->token_type == type) {
                        storeAppendPrintf(entry, "%s", te->config);
                        break;
                    }
                }

                if (t->space)
                    entry->append(" ", 1);

                assert(te->config != NULL);
            }
        }

        entry->append("\n", 1);
    }

}

void
accessLogFreeLogFormat(logformat_token ** tokens)
{
    while (*tokens) {
        logformat_token *token = *tokens;
        *tokens = token->next;
        safe_free(token->data.string);
        xfree(token);
    }
}

logformat::logformat(const char *n) :
        format(NULL),
        next(NULL)
{
    name = xstrdup(n);
}

logformat::~logformat()
{
    // erase the list without consuming stack space
    while (next) {
        // unlink the next entry for deletion
        logformat *temp = next;
        next = temp->next;
        temp->next = NULL;
        delete temp;
    }

    // remove locals
    xfree(name);
    accessLogFreeLogFormat(&format);
}

/*
 * $Id$
 *
 * DEBUG: section 46    Access Log
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
#ifndef _SQUID_LOG_TOKENS_H
#define _SQUID_LOG_TOKENS_H

class StoreEntry;

#define LOG_BUF_SZ (MAX_URL<<2)

/*
 * Bytecodes for the configureable logformat stuff
 */
typedef enum {
    LFT_NONE,			/* dummy */
    LFT_STRING,

    LFT_CLIENT_IP_ADDRESS,
    LFT_CLIENT_FQDN,
    LFT_CLIENT_PORT,
#if USE_SQUID_EUI
    LFT_CLIENT_EUI,
#endif

    /*LFT_SERVER_IP_ADDRESS, */
    LFT_SERVER_IP_OR_PEER_NAME,
    /*LFT_SERVER_PORT, */

    LFT_LOCAL_IP,
    LFT_LOCAL_PORT,
    /*LFT_LOCAL_NAME, */
    LFT_PEER_LOCAL_IP,
    LFT_PEER_LOCAL_IP_OLD_27,
    LFT_PEER_LOCAL_PORT,

    LFT_TIME_SECONDS_SINCE_EPOCH,
    LFT_TIME_SUBSECOND,
    LFT_TIME_LOCALTIME,
    LFT_TIME_GMT,
    LFT_TIME_TO_HANDLE_REQUEST,

    LFT_PEER_RESPONSE_TIME,
    LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME,
    LFT_DNS_WAIT_TIME,

    LFT_REQUEST_HEADER,
    LFT_REQUEST_HEADER_ELEM,
    LFT_REQUEST_ALL_HEADERS,

    LFT_ADAPTED_REQUEST_HEADER,
    LFT_ADAPTED_REQUEST_HEADER_ELEM,
    LFT_ADAPTED_REQUEST_ALL_HEADERS,

    LFT_REPLY_HEADER,
    LFT_REPLY_HEADER_ELEM,
    LFT_REPLY_ALL_HEADERS,

    LFT_USER_NAME,
    LFT_USER_LOGIN,
    LFT_USER_IDENT,
    /*LFT_USER_REALM, */
    /*LFT_USER_SCHEME, */
    LFT_USER_EXTERNAL,

    LFT_HTTP_SENT_STATUS_CODE_OLD_30,
    LFT_HTTP_SENT_STATUS_CODE,
    LFT_HTTP_RECEIVED_STATUS_CODE,
    /*LFT_HTTP_STATUS, */
    LFT_HTTP_BODY_BYTES_READ,

    LFT_SQUID_STATUS,
    LFT_SQUID_ERROR,
    LFT_SQUID_ERROR_DETAIL,
    LFT_SQUID_HIERARCHY,

    LFT_MIME_TYPE,

    LFT_REQUEST_METHOD,
    LFT_REQUEST_URI,
    LFT_REQUEST_URLPATH,
    /*LFT_REQUEST_QUERY, * // * this is not needed. see strip_query_terms */
    LFT_REQUEST_VERSION,

    LFT_REQUEST_SIZE_TOTAL,
    /*LFT_REQUEST_SIZE_LINE, */
    LFT_REQUEST_SIZE_HEADERS,
    /*LFT_REQUEST_SIZE_BODY, */
    /*LFT_REQUEST_SIZE_BODY_NO_TE, */

    LFT_REPLY_SIZE_TOTAL,
    LFT_REPLY_HIGHOFFSET,
    LFT_REPLY_OBJECTSIZE,
    /*LFT_REPLY_SIZE_LINE, */
    LFT_REPLY_SIZE_HEADERS,
    /*LFT_REPLY_SIZE_BODY, */
    /*LFT_REPLY_SIZE_BODY_NO_TE, */

    LFT_TAG,
    LFT_IO_SIZE_TOTAL,
    LFT_EXT_LOG,

    LFT_SEQUENCE_NUMBER,

#if USE_ADAPTATION
    LTF_ADAPTATION_SUM_XACT_TIMES,
    LTF_ADAPTATION_ALL_XACT_TIMES,
    LFT_ADAPTATION_LAST_HEADER,
    LFT_ADAPTATION_LAST_HEADER_ELEM,
    LFT_ADAPTATION_LAST_ALL_HEADERS,
#endif

#if ICAP_CLIENT

    LFT_ICAP_TOTAL_TIME,

    LFT_ICAP_ADDR,
    LFT_ICAP_SERV_NAME,
    LFT_ICAP_REQUEST_URI,
    LFT_ICAP_REQUEST_METHOD,
    LFT_ICAP_BYTES_SENT,
    LFT_ICAP_BYTES_READ,
    LFT_ICAP_BODY_BYTES_READ,

    LFT_ICAP_REQ_HEADER,
    LFT_ICAP_REQ_HEADER_ELEM,
    LFT_ICAP_REQ_ALL_HEADERS,

    LFT_ICAP_REP_HEADER,
    LFT_ICAP_REP_HEADER_ELEM,
    LFT_ICAP_REP_ALL_HEADERS,

    LFT_ICAP_TR_RESPONSE_TIME,
    LFT_ICAP_IO_TIME,
    LFT_ICAP_OUTCOME,
    LFT_ICAP_STATUS_CODE,
#endif

    LFT_PERCENT			/* special string cases for escaped chars */
} logformat_bcode_t;

enum log_quote {
    LOG_QUOTE_NONE = 0,
    LOG_QUOTE_QUOTES,
    LOG_QUOTE_MIMEBLOB,
    LOG_QUOTE_URL,
    LOG_QUOTE_RAW
};

/* FIXME: public class so we can pre-define its type. */
class logformat_token
{
public:
    logformat_bcode_t type;
    union {
        char *string;

        struct {
            char *header;
            char *element;
            char separator;
        } header;
        char *timespec;
    } data;
    unsigned char width;
    unsigned char precision;
    enum log_quote quote;
    unsigned int left:1;
    unsigned int space:1;
    unsigned int zero:1;
    int divisor;
    logformat_token *next;	/* todo: move from linked list to array */
};

struct logformat_token_table_entry {
    const char *config;
    logformat_bcode_t token_type;
    int options;
};

class logformat
{
public:
    logformat(const char *name);
    ~logformat();

    char *name;
    logformat_token *format;
    logformat *next;
};

extern const char *log_tags[];
extern struct logformat_token_table_entry logformat_token_table[];

#if USE_ADAPTATION
extern bool alLogformatHasAdaptToken;
#endif

#if ICAP_CLIENT
extern bool alLogformatHasIcapToken;
#endif

/* parses a single token. Returns the token length in characters,
 * and fills in the lt item with the token information.
 * def is for sure null-terminated
 */
int accessLogGetNewLogFormatToken(logformat_token * lt, char *def, enum log_quote *quote);

/* very inefficent parser, but who cares, this needs to be simple */
/* First off, let's tokenize, we'll optimize in a second pass.
 * A token can either be a %-prefixed sequence (usually a dynamic
 * token but it can be an escaped sequence), or a string. */
int accessLogParseLogFormat(logformat_token ** fmt, char *def);

void accessLogDumpLogFormat(StoreEntry * entry, const char *name, logformat * definitions);

void accessLogFreeLogFormat(logformat_token ** tokens);

#endif /* _SQUID_LOG_TOKENS_H */

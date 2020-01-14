/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "format/Config.h"
#include "format/Token.h"
#include "format/TokenTableEntry.h"
#include "globals.h"
#include "proxyp/Elements.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "Store.h"

// Due to token overlaps between 1 and 2 letter tokens (Bug 3310)
// We split the token table into sets determined by the token length
namespace Format
{

/// 1-char tokens.
static TokenTableEntry TokenTable1C[] = {

    TokenTableEntry(">a", LFT_CLIENT_IP_ADDRESS),
    TokenTableEntry(">p", LFT_CLIENT_PORT),
    TokenTableEntry(">A", LFT_CLIENT_FQDN),

    TokenTableEntry("<a", LFT_SERVER_IP_ADDRESS),
    TokenTableEntry("<p", LFT_SERVER_PORT),
    TokenTableEntry("<A", LFT_SERVER_FQDN_OR_PEER_NAME),

    TokenTableEntry(">h", LFT_REQUEST_HEADER),
    TokenTableEntry(">h", LFT_REQUEST_ALL_HEADERS),
    TokenTableEntry("<h", LFT_REPLY_HEADER),
    TokenTableEntry("<h", LFT_REPLY_ALL_HEADERS),

    TokenTableEntry(">v", LFT_REQUEST_VERSION_OLD_2X),

    TokenTableEntry("%", LFT_PERCENT),

    TokenTableEntry(NULL, LFT_NONE)        /* this must be last */
};

/// 2-char tokens
static TokenTableEntry TokenTable2C[] = {

    TokenTableEntry(">la", LFT_CLIENT_LOCAL_IP),
    TokenTableEntry("la", LFT_LOCAL_LISTENING_IP),
    TokenTableEntry(">lp", LFT_CLIENT_LOCAL_PORT),
    TokenTableEntry("lp", LFT_LOCAL_LISTENING_PORT),
    /*TokenTableEntry( "lA", LFT_LOCAL_NAME ), */

    TokenTableEntry("<la", LFT_SERVER_LOCAL_IP),
    TokenTableEntry("oa", LFT_SERVER_LOCAL_IP_OLD_27),
    TokenTableEntry("<lp", LFT_SERVER_LOCAL_PORT),

    TokenTableEntry("ts", LFT_TIME_SECONDS_SINCE_EPOCH),
    TokenTableEntry("tu", LFT_TIME_SUBSECOND),
    TokenTableEntry("tl", LFT_TIME_LOCALTIME),
    TokenTableEntry("tg", LFT_TIME_GMT),
    TokenTableEntry("tS", LFT_TIME_START),
    TokenTableEntry("tr", LFT_TIME_TO_HANDLE_REQUEST),

    TokenTableEntry("<pt", LFT_PEER_RESPONSE_TIME),
    TokenTableEntry("<tt", LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME),
    TokenTableEntry("dt", LFT_DNS_WAIT_TIME),

    TokenTableEntry(">ha", LFT_ADAPTED_REQUEST_HEADER),
    TokenTableEntry(">ha", LFT_ADAPTED_REQUEST_ALL_HEADERS),

    TokenTableEntry("un", LFT_USER_NAME),
    TokenTableEntry("ul", LFT_USER_LOGIN),
    /*TokenTableEntry( "ur", LFT_USER_REALM ), */
    /*TokenTableEntry( "us", LFT_USER_SCHEME ), */
    TokenTableEntry("ui", LFT_USER_IDENT),
    TokenTableEntry("ue", LFT_USER_EXTERNAL),

    TokenTableEntry("Hs", LFT_HTTP_SENT_STATUS_CODE_OLD_30),
    TokenTableEntry(">Hs", LFT_HTTP_SENT_STATUS_CODE),
    TokenTableEntry("<Hs", LFT_HTTP_RECEIVED_STATUS_CODE),
    /*TokenTableEntry( "Ht", LFT_HTTP_STATUS ), */
    TokenTableEntry("<bs", LFT_HTTP_BODY_BYTES_READ),

    TokenTableEntry("Ss", LFT_SQUID_STATUS),
    TokenTableEntry("Sh", LFT_SQUID_HIERARCHY),

    TokenTableEntry("mt", LFT_MIME_TYPE),

    TokenTableEntry(">rm", LFT_CLIENT_REQ_METHOD),
    TokenTableEntry(">ru", LFT_CLIENT_REQ_URI),
    TokenTableEntry(">rs", LFT_CLIENT_REQ_URLSCHEME),
    TokenTableEntry(">rd", LFT_CLIENT_REQ_URLDOMAIN),
    TokenTableEntry(">rP", LFT_CLIENT_REQ_URLPORT),
    TokenTableEntry(">rp", LFT_CLIENT_REQ_URLPATH),
    /*TokenTableEntry(">rq", LFT_CLIENT_REQ_QUERY),*/
    TokenTableEntry(">rv", LFT_CLIENT_REQ_VERSION),

    TokenTableEntry("rm", LFT_REQUEST_METHOD),
    TokenTableEntry("ru", LFT_REQUEST_URI),    /* doesn't include the query-string */
    TokenTableEntry("rp", LFT_REQUEST_URLPATH_OLD_31),
    /* TokenTableEntry( "rq", LFT_REQUEST_QUERY ), * /     / * the query-string, INCLUDING the leading ? */
    TokenTableEntry("rv", LFT_REQUEST_VERSION),
    TokenTableEntry("rG", LFT_REQUEST_URLGROUP_OLD_2X),

    TokenTableEntry("<rm", LFT_SERVER_REQ_METHOD),
    TokenTableEntry("<ru", LFT_SERVER_REQ_URI),
    TokenTableEntry("<rs", LFT_SERVER_REQ_URLSCHEME),
    TokenTableEntry("<rd", LFT_SERVER_REQ_URLDOMAIN),
    TokenTableEntry("<rP", LFT_SERVER_REQ_URLPORT),
    TokenTableEntry("<rp", LFT_SERVER_REQ_URLPATH),
    /*TokenTableEntry("<rq", LFT_SERVER_REQ_QUERY),*/
    TokenTableEntry("<rv", LFT_SERVER_REQ_VERSION),

    TokenTableEntry(">st", LFT_CLIENT_REQUEST_SIZE_TOTAL ),
    TokenTableEntry(">sh", LFT_CLIENT_REQUEST_SIZE_HEADERS ),
    /*TokenTableEntry( ">sb", LFT_REQUEST_SIZE_BODY ), */
    /*TokenTableEntry( ">sB", LFT_REQUEST_SIZE_BODY_NO_TE ), */

    TokenTableEntry("<st", LFT_ADAPTED_REPLY_SIZE_TOTAL), // XXX: adapted should be code: <sta
    TokenTableEntry("<sH", LFT_REPLY_HIGHOFFSET),
    TokenTableEntry("<sS", LFT_REPLY_OBJECTSIZE),
    TokenTableEntry("<sh", LFT_ADAPTED_REPLY_SIZE_HEADERS ), // XXX: adapted should be code: <sha
    /*TokenTableEntry( "<sb", LFT_REPLY_SIZE_BODY ), */
    /*TokenTableEntry( "<sB", LFT_REPLY_SIZE_BODY_NO_TE ), */

    TokenTableEntry("st", LFT_CLIENT_IO_SIZE_TOTAL), // XXX: total from client should be stC ??
    /*TokenTableEntry("stP", LFT_SERVER_IO_SIZE_TOTAL),*/

    TokenTableEntry("et", LFT_TAG),
    TokenTableEntry("ea", LFT_EXT_LOG),
    TokenTableEntry("sn", LFT_SEQUENCE_NUMBER),

    TokenTableEntry(NULL, LFT_NONE)        /* this must be last */
};

/// Miscellaneous >2 byte tokens
static TokenTableEntry TokenTableMisc[] = {
    TokenTableEntry(">eui", LFT_CLIENT_EUI),
    TokenTableEntry(">qos", LFT_CLIENT_LOCAL_TOS),
    TokenTableEntry("<qos", LFT_SERVER_LOCAL_TOS),
    TokenTableEntry(">nfmark", LFT_CLIENT_LOCAL_NFMARK),
    TokenTableEntry("<nfmark", LFT_SERVER_LOCAL_NFMARK),
    TokenTableEntry(">handshake", LFT_CLIENT_HANDSHAKE),
    TokenTableEntry("err_code", LFT_SQUID_ERROR ),
    TokenTableEntry("err_detail", LFT_SQUID_ERROR_DETAIL ),
    TokenTableEntry("note", LFT_NOTE ),
    TokenTableEntry("credentials", LFT_CREDENTIALS),
    TokenTableEntry("request_attempts", LFT_SQUID_REQUEST_ATTEMPTS),
    TokenTableEntry("master_xaction", LFT_MASTER_XACTION),
    /*
     * Legacy external_acl_type format tokens
     */
    TokenTableEntry("ACL", LFT_EXT_ACL_NAME),
    TokenTableEntry("DATA", LFT_EXT_ACL_DATA),
    TokenTableEntry("DST", LFT_CLIENT_REQ_URLDOMAIN),
    TokenTableEntry("EXT_LOG", LFT_EXT_LOG),
    TokenTableEntry("EXT_TAG", LFT_TAG),
    TokenTableEntry("EXT_USER", LFT_USER_EXTERNAL),
    TokenTableEntry("IDENT", LFT_USER_IDENT),
    TokenTableEntry("LOGIN", LFT_USER_LOGIN),
    TokenTableEntry("METHOD", LFT_CLIENT_REQ_METHOD),
    TokenTableEntry("MYADDR", LFT_LOCAL_LISTENING_IP),
    TokenTableEntry("MYPORT", LFT_LOCAL_LISTENING_PORT),
    TokenTableEntry("PATH", LFT_CLIENT_REQ_URLPATH),
    TokenTableEntry("PORT", LFT_CLIENT_REQ_URLPORT),
    TokenTableEntry("PROTO", LFT_CLIENT_REQ_URLSCHEME),
    TokenTableEntry("SRCEUI48", LFT_EXT_ACL_CLIENT_EUI48),
    TokenTableEntry("SRCEUI64", LFT_EXT_ACL_CLIENT_EUI64),
    TokenTableEntry("SRCPORT", LFT_CLIENT_PORT),
    TokenTableEntry("SRC", LFT_CLIENT_IP_ADDRESS), // keep after longer SRC* tokens
    TokenTableEntry("TAG", LFT_TAG),
    TokenTableEntry("URI", LFT_CLIENT_REQ_URI),
#if USE_OPENSSL
    TokenTableEntry("USER_CERTCHAIN", LFT_EXT_ACL_USER_CERTCHAIN_RAW),
    TokenTableEntry("USER_CERT", LFT_EXT_ACL_USER_CERT_RAW),
#endif
    TokenTableEntry(NULL, LFT_NONE)        /* this must be last */
};

static TokenTableEntry TokenTableProxyProtocol[] = {
    TokenTableEntry(">h", LFT_PROXY_PROTOCOL_RECEIVED_HEADER),
};

#if USE_ADAPTATION
static TokenTableEntry TokenTableAdapt[] = {
    TokenTableEntry("all_trs", LFT_ADAPTATION_ALL_XACT_TIMES),
    TokenTableEntry("sum_trs", LFT_ADAPTATION_SUM_XACT_TIMES),
    TokenTableEntry("<last_h", LFT_ADAPTATION_LAST_HEADER),
    TokenTableEntry(NULL, LFT_NONE)           /* this must be last */
};
#endif

#if ICAP_CLIENT
/// ICAP (icap::) tokens
static TokenTableEntry TokenTableIcap[] = {
    TokenTableEntry("tt", LFT_ICAP_TOTAL_TIME),
    TokenTableEntry("<last_h", LFT_ADAPTATION_LAST_HEADER), // deprecated

    TokenTableEntry("<A",  LFT_ICAP_ADDR),
    TokenTableEntry("<service_name",  LFT_ICAP_SERV_NAME),
    TokenTableEntry("ru",  LFT_ICAP_REQUEST_URI),
    TokenTableEntry("rm",  LFT_ICAP_REQUEST_METHOD),
    TokenTableEntry(">st", LFT_ICAP_BYTES_SENT),
    TokenTableEntry("<st", LFT_ICAP_BYTES_READ),
    TokenTableEntry("<bs", LFT_ICAP_BODY_BYTES_READ),

    TokenTableEntry(">h",  LFT_ICAP_REQ_HEADER),
    TokenTableEntry("<h",  LFT_ICAP_REP_HEADER),

    TokenTableEntry("tr",  LFT_ICAP_TR_RESPONSE_TIME),
    TokenTableEntry("tio", LFT_ICAP_IO_TIME),
    TokenTableEntry("to",  LFT_ICAP_OUTCOME),
    TokenTableEntry("Hs",  LFT_ICAP_STATUS_CODE),
    TokenTableEntry("request_attempts",  LFT_ICAP_REQUEST_ATTEMPTS),

    TokenTableEntry(NULL, LFT_NONE)           /* this must be last */
};
#endif

#if USE_OPENSSL
// TLS/SSL (tls:: or ssl::) tokens
static TokenTableEntry TokenTableSsl[] = {
    TokenTableEntry("bump_mode", LFT_SSL_BUMP_MODE),
    TokenTableEntry(">cert_subject", LFT_SSL_USER_CERT_SUBJECT),
    TokenTableEntry(">cert_issuer", LFT_SSL_USER_CERT_ISSUER),
    TokenTableEntry(">sni", LFT_SSL_CLIENT_SNI),
    TokenTableEntry("<cert_subject", LFT_SSL_SERVER_CERT_SUBJECT),
    TokenTableEntry("<cert_issuer", LFT_SSL_SERVER_CERT_ISSUER),
    TokenTableEntry("<cert_errors", LFT_SSL_SERVER_CERT_ERRORS),
    TokenTableEntry("<cert", LFT_SSL_SERVER_CERT_WHOLE),
    TokenTableEntry(">negotiated_version", LFT_TLS_CLIENT_NEGOTIATED_VERSION),
    TokenTableEntry("<negotiated_version", LFT_TLS_SERVER_NEGOTIATED_VERSION),
    TokenTableEntry(">negotiated_cipher", LFT_TLS_CLIENT_NEGOTIATED_CIPHER),
    TokenTableEntry("<negotiated_cipher", LFT_TLS_SERVER_NEGOTIATED_CIPHER),
    TokenTableEntry(">received_hello_version", LFT_TLS_CLIENT_RECEIVED_HELLO_VERSION),
    TokenTableEntry("<received_hello_version", LFT_TLS_SERVER_RECEIVED_HELLO_VERSION),
    TokenTableEntry(">received_supported_version", LFT_TLS_CLIENT_SUPPORTED_VERSION),
    TokenTableEntry("<received_supported_version", LFT_TLS_SERVER_SUPPORTED_VERSION),
    TokenTableEntry(NULL, LFT_NONE)
};
#endif
} // namespace Format

/// Register all components custom format tokens
void
Format::Token::Init()
{
    // TODO standard log tokens

#if USE_ADAPTATION
    TheConfig.registerTokens(SBuf("adapt"),::Format::TokenTableAdapt);
#endif
#if ICAP_CLIENT
    TheConfig.registerTokens(SBuf("icap"),::Format::TokenTableIcap);
#endif
#if USE_OPENSSL
    TheConfig.registerTokens(SBuf("tls"),::Format::TokenTableSsl);
    TheConfig.registerTokens(SBuf("ssl"),::Format::TokenTableSsl);
#endif
    TheConfig.registerTokens(SBuf("proxy_protocol"), ::Format::TokenTableProxyProtocol);
}

/// Scans a token table to see if the next token exists there
/// returns a pointer to next unparsed byte and updates type member if found
const char *
Format::Token::scanForToken(TokenTableEntry const table[], const char *cur)
{
    for (TokenTableEntry const *lte = table; lte->configTag != NULL; ++lte) {
        debugs(46, 8, HERE << "compare tokens '" << lte->configTag << "' with '" << cur << "'");
        if (strncmp(lte->configTag, cur, strlen(lte->configTag)) == 0) {
            type = lte->tokenType;
            label = lte->configTag;
            debugs(46, 7, HERE << "Found token '" << label << "'");
            return cur + strlen(lte->configTag);
        }
    }
    return cur;
}

/* parses a single token. Returns the token length in characters,
 * and fills in the lt item with the token information.
 * def is for sure null-terminated
 */
int
Format::Token::parse(const char *def, Quoting *quoting)
{
    const char *cur = def;

    int l;

    l = strcspn(cur, "%");

    if (l > 0) {
        char *cp;
        /* it's a string for sure, until \0 or the next % */
        cp = (char *)xmalloc(l + 1);
        xstrncpy(cp, cur, l + 1);
        type = LFT_STRING;
        data.string = cp;

        while (l > 0) {
            switch (*cur) {

            case '"':

                if (*quoting == LOG_QUOTE_NONE)
                    *quoting = LOG_QUOTE_QUOTES;
                else if (*quoting == LOG_QUOTE_QUOTES)
                    *quoting = LOG_QUOTE_NONE;

                break;

            case '[':
                if (*quoting == LOG_QUOTE_NONE)
                    *quoting = LOG_QUOTE_MIMEBLOB;

                break;

            case ']':
                if (*quoting == LOG_QUOTE_MIMEBLOB)
                    *quoting = LOG_QUOTE_NONE;

                break;
            }

            ++cur;
            --l;
        }

    } else if (*cur) {

        ++cur;

        // select quoting style for his particular token
        switch (*cur) {

        case '"':
            quote = LOG_QUOTE_QUOTES;
            ++cur;
            break;

        case '\'':
            quote = LOG_QUOTE_RAW;
            ++cur;
            break;

        case '[':
            quote = LOG_QUOTE_MIMEBLOB;
            ++cur;
            break;

        case '#':
            quote = LOG_QUOTE_URL;
            ++cur;
            break;

        case '/':
            quote = LOG_QUOTE_SHELL;
            ++cur;
            break;

        default:
            quote = *quoting;
            break;
        }

        if (*cur == '-') {
            left = true;
            ++cur;
        }

        if (*cur == '0') {
            zero = true;
            ++cur;
        }

        char *endp;
        if (xisdigit(*cur)) {
            widthMin = strtol(cur, &endp, 10);
            cur = endp;
        }

        if (*cur == '.' && xisdigit(*(++cur))) {
            widthMax = strtol(cur, &endp, 10);
            cur = endp;
        }

        // when {arg} field is before the token (old logformat syntax)
        if (*cur == '{') {
            char *cp;
            ++cur;
            l = strcspn(cur, "}");
            cp = (char *)xmalloc(l + 1);
            xstrncpy(cp, cur, l + 1);
            data.string = cp;
            cur += l;

            if (*cur == '}')
                ++cur;
        }

        type = LFT_NONE;

        // Scan each registered token namespace
        debugs(46, 9, "check for token in " << TheConfig.tokens.size() << " namespaces.");
        for (const auto &itr : TheConfig.tokens) {
            debugs(46, 7, "check for possible " << itr.prefix << ":: token");
            const size_t len = itr.prefix.length();
            if (itr.prefix.cmp(cur, len) == 0 && cur[len] == ':' && cur[len+1] == ':') {
                debugs(46, 5, "check for " << itr.prefix << ":: token in '" << cur << "'");
                const char *old = cur;
                cur = scanForToken(itr.tokenSet, cur+len+2);
                if (old != cur) // found
                    break;
                else // reset to start of namespace
                    cur = cur - len - 2;
            }
        }

        if (type == LFT_NONE) {
            // For upward compatibility, assume "http::" prefix as default prefix
            // for all log access formatting codes, except those starting with a
            // "%" or a known namespace. (ie "icap::", "adapt::")
            if (strncmp(cur,"http::", 6) == 0 && *(cur+6) != '%' )
                cur += 6;

            // NP: scan the sets of tokens in decreasing size to guarantee no
            //     mistakes made with overlapping names. (Bug 3310)

            // Scan for various long tokens
            debugs(46, 5, HERE << "scan for possible Misc token");
            cur = scanForToken(TokenTableMisc, cur);
            // scan for 2-char tokens
            if (type == LFT_NONE) {
                debugs(46, 5, HERE << "scan for possible 2C token");
                cur = scanForToken(TokenTable2C, cur);
            }
            // finally scan for 1-char tokens.
            if (type == LFT_NONE) {
                debugs(46, 5, HERE << "scan for possible 1C token");
                cur = scanForToken(TokenTable1C, cur);
            }
        }

        if (type == LFT_NONE)
            throw TexcHere(ToSBuf("Unsupported %code: '", def, "'"));

        // when {arg} field is after the token (old external_acl_type token syntax)
        // but accept only if there was none before the token
        if (*cur == '{' && !data.string) {
            char *cp;
            ++cur;
            l = strcspn(cur, "}");
            cp = (char *)xmalloc(l + 1);
            xstrncpy(cp, cur, l + 1);
            data.string = cp;
            cur += l;

            if (*cur == '}')
                ++cur;
        }

        if (*cur == ' ') {
            space = true;
            ++cur;
        }
    }

    switch (type) {

#if USE_ADAPTATION
    case LFT_ADAPTATION_LAST_HEADER:
#endif

#if ICAP_CLIENT
    case LFT_ICAP_REQ_HEADER:

    case LFT_ICAP_REP_HEADER:
#endif

    case LFT_ADAPTED_REQUEST_HEADER:

    case LFT_REQUEST_HEADER:

    case LFT_REPLY_HEADER:

    case LFT_NOTE:

    case LFT_PROXY_PROTOCOL_RECEIVED_HEADER:

        if (data.string) {
            char *header = data.string;
            const auto initialType = type;

            const auto pseudoHeader = header[0] == ':';
            char *cp = strchr(pseudoHeader ? header+1 : header, ':');

            if (cp) {
                *cp = '\0';
                ++cp;

                if (*cp == ',' || *cp == ';' || *cp == ':') {
                    data.header.separator = *cp;
                    ++cp;
                } else {
                    data.header.separator = ',';
                }

                data.header.element = cp;

                switch (type) {
                case LFT_REQUEST_HEADER:
                    type = LFT_REQUEST_HEADER_ELEM;
                    break;

                case LFT_ADAPTED_REQUEST_HEADER:
                    type = LFT_ADAPTED_REQUEST_HEADER_ELEM;
                    break;

                case LFT_REPLY_HEADER:
                    type = LFT_REPLY_HEADER_ELEM;
                    break;
#if USE_ADAPTATION
                case LFT_ADAPTATION_LAST_HEADER:
                    type = LFT_ADAPTATION_LAST_HEADER_ELEM;
                    break;
#endif
#if ICAP_CLIENT
                case LFT_ICAP_REQ_HEADER:
                    type = LFT_ICAP_REQ_HEADER_ELEM;
                    break;
                case LFT_ICAP_REP_HEADER:
                    type = LFT_ICAP_REP_HEADER_ELEM;
                    break;
#endif
                case LFT_PROXY_PROTOCOL_RECEIVED_HEADER:
                    type = LFT_PROXY_PROTOCOL_RECEIVED_HEADER_ELEM;
                    break;
                default:
                    break;
                }
            }

            if (!*header)
                throw TexcHere(ToSBuf("Can't parse configuration token: '", def, "': missing header name"));

            if (initialType == LFT_PROXY_PROTOCOL_RECEIVED_HEADER)
                data.headerId = ProxyProtocol::FieldNameToFieldType(SBuf(header));
            else if (pseudoHeader)
                throw TexcHere(ToSBuf("Pseudo headers are not supported in this context; got: '", def, "'"));

            data.header.header = header;
        } else {
            switch (type) {
            case LFT_REQUEST_HEADER:
                type = LFT_REQUEST_ALL_HEADERS;
                break;

            case LFT_ADAPTED_REQUEST_HEADER:
                type = LFT_ADAPTED_REQUEST_ALL_HEADERS;
                break;

            case LFT_REPLY_HEADER:
                type = LFT_REPLY_ALL_HEADERS;
                break;
#if USE_ADAPTATION
            case LFT_ADAPTATION_LAST_HEADER:
                type = LFT_ADAPTATION_LAST_ALL_HEADERS;
                break;
#endif
#if ICAP_CLIENT
            case LFT_ICAP_REQ_HEADER:
                type = LFT_ICAP_REQ_ALL_HEADERS;
                break;
            case LFT_ICAP_REP_HEADER:
                type = LFT_ICAP_REP_ALL_HEADERS;
                break;
#endif
            case LFT_PROXY_PROTOCOL_RECEIVED_HEADER:
                type = LFT_PROXY_PROTOCOL_RECEIVED_ALL_HEADERS;
                break;
            default:
                break;
            }
            Config.onoff.log_mime_hdrs = 1;
        }

        break;

    case LFT_CLIENT_FQDN:
        Config.onoff.log_fqdn = 1;
        break;

    case LFT_TIME_TO_HANDLE_REQUEST:
    case LFT_PEER_RESPONSE_TIME:
    case LFT_TOTAL_SERVER_SIDE_RESPONSE_TIME:
    case LFT_DNS_WAIT_TIME:
#if ICAP_CLIENT
    case LFT_ICAP_TR_RESPONSE_TIME:
    case LFT_ICAP_IO_TIME:
    case LFT_ICAP_TOTAL_TIME:
#endif
    case LFT_TIME_START:
    case LFT_TIME_SUBSECOND:
        divisor = 1000;

        if (widthMax > 0) {
            divisor = 1000000;

            for (int i = widthMax; i > 0; --i)
                divisor /= 10;

            if (!divisor)
                divisor = 1;
        }
        break;

    case LFT_HTTP_SENT_STATUS_CODE_OLD_30:
        debugs(46, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: The \"Hs\" formatting code is deprecated. Use the \">Hs\" instead.");
        type = LFT_HTTP_SENT_STATUS_CODE;
        break;

    case LFT_SERVER_LOCAL_IP_OLD_27:
        debugs(46, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: The \"oa\" formatting code is deprecated. Use the \"<la\" instead.");
        type = LFT_SERVER_LOCAL_IP;
        break;

    case LFT_REQUEST_URLPATH_OLD_31:
        debugs(46, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: The \"rp\" formatting code is deprecated. Use the \">rp\" instead.");
        type = LFT_CLIENT_REQ_URLPATH;
        break;

    case LFT_REQUEST_VERSION_OLD_2X:
        debugs(46, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: The \">v\" formatting code is deprecated. Use the \">rv\" instead.");
        type = LFT_REQUEST_VERSION;
        break;

#if !USE_SQUID_EUI
    case LFT_CLIENT_EUI:
        debugs(46, DBG_CRITICAL, "WARNING: The \">eui\" formatting code requires EUI features which are disabled in this Squid.");
        break;
#endif

#if USE_OPENSSL
    case LFT_TLS_SERVER_NEGOTIATED_VERSION:
    case LFT_TLS_SERVER_RECEIVED_HELLO_VERSION:
    case LFT_TLS_SERVER_SUPPORTED_VERSION:
        Config.onoff.logTlsServerHelloDetails = true;
        break;
#endif

    case LFT_REQUEST_URLGROUP_OLD_2X:
        debugs(46, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: The \"rG\" formatting code is deprecated. Use \"note{urlgroup}\" instead.");
        type = LFT_NOTE;
        data.header.header = xstrdup("urlgroup");
        break;

    default:
        break;
    }

    return (cur - def);
}

Format::Token::Token() : type(LFT_NONE),
    label(NULL),
    widthMin(-1),
    widthMax(-1),
    quote(LOG_QUOTE_NONE),
    left(false),
    space(false),
    zero(false),
    divisor(1),
    next(NULL)
{
    data.string = NULL;
    data.header.header = NULL;
    data.header.element = NULL;
    data.header.separator = ',';
    data.headerId = ProxyProtocol::Two::htUnknown;
}

Format::Token::~Token()
{
    label = NULL; // drop reference to global static.
    safe_free(data.string);
    while (next) {
        Token *tokens = next;
        next = next->next;
        tokens->next = NULL;
        delete tokens;
    }
}


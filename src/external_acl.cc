/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 82    External ACL */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "ConfigParser.h"
#include "ExternalACL.h"
#include "ExternalACLEntry.h"
#include "fde.h"
#include "format/ByteCode.h"
#include "helper.h"
#include "helper/Reply.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"
#include "URL.h"
#include "wordlist.h"
#if USE_OPENSSL
#include "ssl/ServerBump.h"
#include "ssl/support.h"
#endif
#if USE_AUTH
#include "auth/Acl.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#endif
#if USE_IDENT
#include "ident/AclIdent.h"
#endif

#ifndef DEFAULT_EXTERNAL_ACL_TTL
#define DEFAULT_EXTERNAL_ACL_TTL 1 * 60 * 60
#endif
#ifndef DEFAULT_EXTERNAL_ACL_CHILDREN
#define DEFAULT_EXTERNAL_ACL_CHILDREN 5
#endif

static char *makeExternalAclKey(ACLFilledChecklist * ch, external_acl_data * acl_data);
static void external_acl_cache_delete(external_acl * def, const ExternalACLEntryPointer &entry);
static int external_acl_entry_expired(external_acl * def, const ExternalACLEntryPointer &entry);
static int external_acl_grace_expired(external_acl * def, const ExternalACLEntryPointer &entry);
static void external_acl_cache_touch(external_acl * def, const ExternalACLEntryPointer &entry);
static ExternalACLEntryPointer external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const &data);

/******************************************************************
 * external_acl directive
 */

class external_acl_format : public RefCountable
{
public:
    typedef RefCount<external_acl_format> Pointer;
    MEMPROXY_CLASS(external_acl_format);

    external_acl_format() : type(Format::LFT_NONE), header(NULL), member(NULL), separator(' '), header_id(HDR_BAD_HDR) {}
    ~external_acl_format() {
        xfree(header);
        xfree(member);
    }

    Format::ByteCode_t type;
    external_acl_format::Pointer next;
    char *header;
    char *member;
    char separator;
    http_hdr_type header_id;
};

MEMPROXY_CLASS_INLINE(external_acl_format);

class external_acl
{

public:
    external_acl *next;

    void add(const ExternalACLEntryPointer &);

    void trimCache();

    int ttl;

    int negative_ttl;

    int grace;

    char *name;

    external_acl_format::Pointer format;

    wordlist *cmdline;

    Helper::ChildConfig children;

    helper *theHelper;

    hash_table *cache;

    dlink_list lru_list;

    int cache_size;

    int cache_entries;

    dlink_list queue;

#if USE_AUTH
    /**
     * Configuration flag. May only be altered by the configuration parser.
     *
     * Indicates that all uses of this external_acl_type helper require authentication
     * details to be processed. If none are available its a fail match.
     */
    bool require_auth;
#endif

    enum {
        QUOTE_METHOD_SHELL = 1,
        QUOTE_METHOD_URL
    } quote;

    Ip::Address local_addr;
};

/* FIXME: These are not really cbdata, but it is an easy way
 * to get them pooled, refcounted, accounted and freed properly...
 */
CBDATA_TYPE(external_acl);

static void
free_external_acl(void *data)
{
    external_acl *p = static_cast<external_acl *>(data);
    safe_free(p->name);

    p->format = NULL;

    wordlistDestroy(&p->cmdline);

    if (p->theHelper) {
        helperShutdown(p->theHelper);
        delete p->theHelper;
        p->theHelper = NULL;
    }

    while (p->lru_list.tail) {
        ExternalACLEntryPointer e(static_cast<ExternalACLEntry *>(p->lru_list.tail->data));
        external_acl_cache_delete(p, e);
    }
    if (p->cache)
        hashFreeMemory(p->cache);
}

/**
 * Parse the External ACL format %<{.*} and %>{.*} token(s) to pass a specific
 * request or reply header to external helper.
 *
 \param header   - the token being parsed (without the identifying prefix)
 \param type     - format enum identifier for this element, pulled from identifying prefix
 \param format   - structure to contain all the info about this format element.
 */
void
parse_header_token(external_acl_format::Pointer format, char *header, const Format::ByteCode_t type)
{
    /* header format */
    char *member, *end;

    /** Cut away the closing brace */
    end = strchr(header, '}');
    if (end && strlen(end) == 1)
        *end = '\0';
    else
        self_destruct();

    member = strchr(header, ':');

    if (member) {
        /* Split in header and member */
        *member = '\0';
        ++member;

        if (!xisalnum(*member)) {
            format->separator = *member;
            ++member;
        } else {
            format->separator = ',';
        }

        format->member = xstrdup(member);

        if (type == Format::LFT_ADAPTED_REQUEST_HEADER)
            format->type = Format::LFT_ADAPTED_REQUEST_HEADER_ELEM;
        else
            format->type = Format::LFT_REPLY_HEADER_ELEM;

    } else {
        format->type = type;
    }

    format->header = xstrdup(header);
    format->header_id = httpHeaderIdByNameDef(header, strlen(header));
}

void
parse_externalAclHelper(external_acl ** list)
{
    external_acl *a;
    char *token;

    CBDATA_INIT_TYPE_FREECB(external_acl, free_external_acl);

    a = cbdataAlloc(external_acl);

    /* set defaults */
    a->ttl = DEFAULT_EXTERNAL_ACL_TTL;
    a->negative_ttl = -1;
    a->cache_size = 256*1024;
    a->children.n_max = DEFAULT_EXTERNAL_ACL_CHILDREN;
    a->children.n_startup = a->children.n_max;
    a->children.n_idle = 1;
    a->local_addr.setLocalhost();
    a->quote = external_acl::QUOTE_METHOD_URL;

    token = ConfigParser::NextToken();

    if (!token)
        self_destruct();

    a->name = xstrdup(token);

    // Allow supported %macros inside quoted tokens
    ConfigParser::EnableMacros();
    token = ConfigParser::NextToken();

    /* Parse options */
    while (token) {
        if (strncmp(token, "ttl=", 4) == 0) {
            a->ttl = atoi(token + 4);
        } else if (strncmp(token, "negative_ttl=", 13) == 0) {
            a->negative_ttl = atoi(token + 13);
        } else if (strncmp(token, "children=", 9) == 0) {
            a->children.n_max = atoi(token + 9);
            debugs(0, DBG_CRITICAL, "WARNING: external_acl_type option children=N has been deprecated in favor of children-max=N and children-startup=N");
        } else if (strncmp(token, "children-max=", 13) == 0) {
            a->children.n_max = atoi(token + 13);
        } else if (strncmp(token, "children-startup=", 17) == 0) {
            a->children.n_startup = atoi(token + 17);
        } else if (strncmp(token, "children-idle=", 14) == 0) {
            a->children.n_idle = atoi(token + 14);
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            a->children.concurrency = atoi(token + 12);
        } else if (strncmp(token, "cache=", 6) == 0) {
            a->cache_size = atoi(token + 6);
        } else if (strncmp(token, "grace=", 6) == 0) {
            a->grace = atoi(token + 6);
        } else if (strcmp(token, "protocol=2.5") == 0) {
            a->quote = external_acl::QUOTE_METHOD_SHELL;
        } else if (strcmp(token, "protocol=3.0") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option protocol=3.0 is deprecated. Remove this from your config.");
            a->quote = external_acl::QUOTE_METHOD_URL;
        } else if (strcmp(token, "quote=url") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option quote=url is deprecated. Remove this from your config.");
            a->quote = external_acl::QUOTE_METHOD_URL;
        } else if (strcmp(token, "quote=shell") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option quote=shell is deprecated. Use protocol=2.5 if still needed.");
            a->quote = external_acl::QUOTE_METHOD_SHELL;

            /* INET6: allow admin to configure some helpers explicitly to
                      bind to IPv4/v6 localhost port. */
        } else if (strcmp(token, "ipv4") == 0) {
            if ( !a->local_addr.setIPv4() ) {
                debugs(3, DBG_CRITICAL, "WARNING: Error converting " << a->local_addr << " to IPv4 in " << a->name );
            }
        } else if (strcmp(token, "ipv6") == 0) {
            if (!Ip::EnableIpv6)
                debugs(3, DBG_CRITICAL, "WARNING: --enable-ipv6 required for external ACL helpers to use IPv6: " << a->name );
            // else nothing to do.
        } else {
            break;
        }

        token = ConfigParser::NextToken();
    }
    ConfigParser::DisableMacros();

    /* check that child startup value is sane. */
    if (a->children.n_startup > a->children.n_max)
        a->children.n_startup = a->children.n_max;

    /* check that child idle value is sane. */
    if (a->children.n_idle > a->children.n_max)
        a->children.n_idle = a->children.n_max;
    if (a->children.n_idle < 1)
        a->children.n_idle = 1;

    if (a->negative_ttl == -1)
        a->negative_ttl = a->ttl;

    /* Parse format */
    external_acl_format::Pointer *p = &a->format;

    while (token) {
        /* stop on first non-format token found */

        if (*token != '%')
            break;

        external_acl_format::Pointer format = new external_acl_format;

        if (strncmp(token, "%{", 2) == 0) {
            // deprecated. but assume the old configs all referred to request headers.
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %{...} is being replaced by %>ha{...} for : " << token);
            parse_header_token(format, (token+2), Format::LFT_ADAPTED_REQUEST_HEADER);
        } else if (strncmp(token, "%>{", 3) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %>{...} is being replaced by %>ha{...} for : " << token);
            parse_header_token(format, (token+3), Format::LFT_ADAPTED_REQUEST_HEADER);
        } else if (strncmp(token, "%>ha{", 5) == 0) {
            parse_header_token(format, (token+5), Format::LFT_ADAPTED_REQUEST_HEADER);
        } else if (strncmp(token, "%<{", 3) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %<{...} is being replaced by %<h{...} for : " << token);
            parse_header_token(format, (token+3), Format::LFT_REPLY_HEADER);
        } else if (strncmp(token, "%<h{", 4) == 0) {
            parse_header_token(format, (token+4), Format::LFT_REPLY_HEADER);
#if USE_AUTH
        } else if (strcmp(token, "%LOGIN") == 0 || strcmp(token, "%ul") == 0) {
            format->type = Format::LFT_USER_LOGIN;
            a->require_auth = true;
#endif
        }
#if USE_IDENT
        else if (strcmp(token, "%IDENT") == 0 || strcmp(token, "%ui") == 0)
            format->type = Format::LFT_USER_IDENT;
#endif
        else if (strcmp(token, "%SRC") == 0 || strcmp(token, "%>a") == 0)
            format->type = Format::LFT_CLIENT_IP_ADDRESS;
        else if (strcmp(token, "%SRCPORT") == 0 || strcmp(token, "%>p") == 0)
            format->type = Format::LFT_CLIENT_PORT;
#if USE_SQUID_EUI
        else if (strcmp(token, "%SRCEUI48") == 0)
            format->type = Format::LFT_EXT_ACL_CLIENT_EUI48;
        else if (strcmp(token, "%SRCEUI64") == 0)
            format->type = Format::LFT_EXT_ACL_CLIENT_EUI64;
#endif
        else if (strcmp(token, "%MYADDR") == 0 || strcmp(token, "%la") == 0)
            format->type = Format::LFT_LOCAL_LISTENING_IP;
        else if (strcmp(token, "%MYPORT") == 0 || strcmp(token, "%lp") == 0)
            format->type = Format::LFT_LOCAL_LISTENING_PORT;
        else if (strcmp(token, "%URI") == 0 || strcmp(token, "%>ru") == 0)
            format->type = Format::LFT_CLIENT_REQ_URI;
        else if (strcmp(token, "%DST") == 0 || strcmp(token, "%>rd") == 0)
            format->type = Format::LFT_CLIENT_REQ_URLDOMAIN;
        else if (strcmp(token, "%PROTO") == 0 || strcmp(token, "%>rs") == 0)
            format->type = Format::LFT_CLIENT_REQ_URLSCHEME;
        else if (strcmp(token, "%PORT") == 0) // XXX: add a logformat token
            format->type = Format::LFT_CLIENT_REQ_URLPORT;
        else if (strcmp(token, "%PATH") == 0 || strcmp(token, "%>rp") == 0)
            format->type = Format::LFT_CLIENT_REQ_URLPATH;
        else if (strcmp(token, "%METHOD") == 0 || strcmp(token, "%>rm") == 0)
            format->type = Format::LFT_CLIENT_REQ_METHOD;
#if USE_OPENSSL
        else if (strcmp(token, "%USER_CERT") == 0)
            format->type = Format::LFT_EXT_ACL_USER_CERT_RAW;
        else if (strcmp(token, "%USER_CERTCHAIN") == 0)
            format->type = Format::LFT_EXT_ACL_USER_CERTCHAIN_RAW;
        else if (strncmp(token, "%USER_CERT_", 11) == 0) {
            format->type = Format::LFT_EXT_ACL_USER_CERT;
            format->header = xstrdup(token + 11);
        } else if (strncmp(token, "%USER_CA_CERT_", 14) == 0) {
            format->type = Format::LFT_EXT_ACL_USER_CA_CERT;
            format->header = xstrdup(token + 14);
        } else if (strncmp(token, "%CA_CERT_", 9) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type %CA_CERT_* code is obsolete. Use %USER_CA_CERT_* instead");
            format->type = Format::LFT_EXT_ACL_USER_CA_CERT;
            format->header = xstrdup(token + 9);
        } else if (strcmp(token, "%ssl::>sni") == 0)
            format->type = Format::LFT_SSL_CLIENT_SNI;
        else if (strcmp(token, "%ssl::<cert_subject") == 0)
            format->type = Format::LFT_SSL_SERVER_CERT_SUBJECT;
        else if (strcmp(token, "%ssl::<cert_issuer") == 0)
            format->type = Format::LFT_SSL_SERVER_CERT_ISSUER;
#endif
#if USE_AUTH
        else if (strcmp(token, "%EXT_USER") == 0 || strcmp(token, "%ue") == 0)
            format->type = Format::LFT_USER_EXTERNAL;
#endif
#if USE_AUTH || defined(USE_OPENSSL) || defined(USE_IDENT)
        else if (strcmp(token, "%un") == 0)
            format->type = Format::LFT_USER_NAME;
#endif
        else if (strcmp(token, "%EXT_LOG") == 0 || strcmp(token, "%ea") == 0)
            format->type = Format::LFT_EXT_LOG;
        else if (strcmp(token, "%TAG") == 0  || strcmp(token, "%et") == 0)
            format->type = Format::LFT_TAG;
        else if (strcmp(token, "%ACL") == 0)
            format->type = Format::LFT_EXT_ACL_NAME;
        else if (strcmp(token, "%DATA") == 0)
            format->type = Format::LFT_EXT_ACL_DATA;
        else if (strcmp(token, "%%") == 0)
            format->type = Format::LFT_PERCENT;
        else {
            debugs(0, DBG_CRITICAL, "ERROR: Unknown Format token " << token);
            self_destruct();
        }

        *p = format;
        p = &format->next;
        token = ConfigParser::NextToken();
    }

    /* There must be at least one format token */
    if (!a->format)
        self_destruct();

    /* helper */
    if (!token)
        self_destruct();

    wordlistAdd(&a->cmdline, token);

    /* arguments */
    parse_wordlist(&a->cmdline);

    while (*list)
        list = &(*list)->next;

    *list = a;
}

void
dump_externalAclHelper(StoreEntry * sentry, const char *name, const external_acl * list)
{
    const external_acl *node;
    const wordlist *word;

    for (node = list; node; node = node->next) {
        storeAppendPrintf(sentry, "%s %s", name, node->name);

        if (!node->local_addr.isIPv6())
            storeAppendPrintf(sentry, " ipv4");
        else
            storeAppendPrintf(sentry, " ipv6");

        if (node->ttl != DEFAULT_EXTERNAL_ACL_TTL)
            storeAppendPrintf(sentry, " ttl=%d", node->ttl);

        if (node->negative_ttl != node->ttl)
            storeAppendPrintf(sentry, " negative_ttl=%d", node->negative_ttl);

        if (node->grace)
            storeAppendPrintf(sentry, " grace=%d", node->grace);

        if (node->children.n_max != DEFAULT_EXTERNAL_ACL_CHILDREN)
            storeAppendPrintf(sentry, " children-max=%d", node->children.n_max);

        if (node->children.n_startup != 1)
            storeAppendPrintf(sentry, " children-startup=%d", node->children.n_startup);

        if (node->children.n_idle != (node->children.n_max + node->children.n_startup) )
            storeAppendPrintf(sentry, " children-idle=%d", node->children.n_idle);

        if (node->children.concurrency)
            storeAppendPrintf(sentry, " concurrency=%d", node->children.concurrency);

        if (node->cache)
            storeAppendPrintf(sentry, " cache=%d", node->cache_size);

        if (node->quote == external_acl::QUOTE_METHOD_SHELL)
            storeAppendPrintf(sentry, " protocol=2.5");

        for (external_acl_format::Pointer format = node->format; format!= NULL; format = format->next) {
            switch (format->type) {

            case Format::LFT_ADAPTED_REQUEST_HEADER:
                storeAppendPrintf(sentry, " %%>ha{%s}", format->header);
                break;

            case Format::LFT_ADAPTED_REQUEST_HEADER_ELEM:
                storeAppendPrintf(sentry, " %%>ha{%s:%s}", format->header, format->member);
                break;

            case Format::LFT_REPLY_HEADER:
                storeAppendPrintf(sentry, " %%<h{%s}", format->header);
                break;

            case Format::LFT_REPLY_HEADER_ELEM:
                storeAppendPrintf(sentry, " %%<h{%s:%s}", format->header, format->member);
                break;

#define DUMP_EXT_ACL_TYPE_FMT(a, fmt, ...) \
            case Format::LFT_##a: \
                storeAppendPrintf(sentry, fmt, ##__VA_ARGS__); \
                break
#if USE_AUTH
                DUMP_EXT_ACL_TYPE_FMT(USER_LOGIN," %%ul");
                DUMP_EXT_ACL_TYPE_FMT(USER_NAME," %%un");
#endif
#if USE_IDENT

                DUMP_EXT_ACL_TYPE_FMT(USER_IDENT," %%ui");
#endif
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_IP_ADDRESS," %%>a");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_PORT," %%>p");
#if USE_SQUID_EUI
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_CLIENT_EUI48," %%SRCEUI48");
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_CLIENT_EUI64," %%SRCEUI64");
#endif
                DUMP_EXT_ACL_TYPE_FMT(LOCAL_LISTENING_IP," %%>la");
                DUMP_EXT_ACL_TYPE_FMT(LOCAL_LISTENING_PORT," %%>lp");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_URI," %%>ru");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_URLDOMAIN," %%>rd");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_URLSCHEME," %%>rs");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_URLPORT," %%>rP");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_URLPATH," %%>rp");
                DUMP_EXT_ACL_TYPE_FMT(CLIENT_REQ_METHOD," %%>rm");
#if USE_OPENSSL
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_USER_CERT_RAW, " %%USER_CERT_RAW");
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_USER_CERTCHAIN_RAW, " %%USER_CERTCHAIN_RAW");
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_USER_CERT, " %%USER_CERT_%s", format->header);
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_USER_CA_CERT, " %%USER_CA_CERT_%s", format->header);
                DUMP_EXT_ACL_TYPE_FMT(SSL_CLIENT_SNI, "%%ssl::>sni");
                DUMP_EXT_ACL_TYPE_FMT(SSL_SERVER_CERT_SUBJECT, "%%ssl::<cert_subject");
                DUMP_EXT_ACL_TYPE_FMT(SSL_SERVER_CERT_ISSUER, "%%ssl::<cert_issuer");
#endif
#if USE_AUTH
                DUMP_EXT_ACL_TYPE_FMT(USER_EXTERNAL," %%ue");
#endif
                DUMP_EXT_ACL_TYPE_FMT(EXT_LOG," %%ea");
                DUMP_EXT_ACL_TYPE_FMT(TAG," %%et");
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_NAME," %%ACL");
                DUMP_EXT_ACL_TYPE_FMT(EXT_ACL_DATA," %%DATA");
                DUMP_EXT_ACL_TYPE_FMT(PERCENT, " %%%%");
            default:
                fatal("unknown external_acl format error");
                break;
            }
        }

        for (word = node->cmdline; word; word = word->next)
            storeAppendPrintf(sentry, " %s", word->key);

        storeAppendPrintf(sentry, "\n");
    }
}

void
free_externalAclHelper(external_acl ** list)
{
    while (*list) {
        external_acl *node = *list;
        *list = node->next;
        node->next = NULL;
        cbdataFree(node);
    }
}

static external_acl *
find_externalAclHelper(const char *name)
{
    external_acl *node;

    for (node = Config.externalAclHelperList; node; node = node->next) {
        if (strcmp(node->name, name) == 0)
            return node;
    }

    return NULL;
}

void
external_acl::add(const ExternalACLEntryPointer &anEntry)
{
    trimCache();
    assert(anEntry != NULL);
    assert (anEntry->def == NULL);
    anEntry->def = this;
    ExternalACLEntry *e = const_cast<ExternalACLEntry *>(anEntry.getRaw()); // XXX: make hash a std::map of Pointer.
    hash_join(cache, e);
    dlinkAdd(e, &e->lru, &lru_list);
    e->lock(); //cbdataReference(e); // lock it on behalf of the hash
    ++cache_entries;
}

void
external_acl::trimCache()
{
    if (cache_size && cache_entries >= cache_size) {
        ExternalACLEntryPointer e(static_cast<ExternalACLEntry *>(lru_list.tail->data));
        external_acl_cache_delete(this, e);
    }
}

/******************************************************************
 * external acl type
 */

struct _external_acl_data {
    external_acl *def;
    const char *name;
    wordlist *arguments;
};

CBDATA_TYPE(external_acl_data);
static void
free_external_acl_data(void *data)
{
    external_acl_data *p = static_cast<external_acl_data *>(data);
    safe_free(p->name);
    wordlistDestroy(&p->arguments);
    cbdataReferenceDone(p->def);
}

void
ACLExternal::parse()
{
    char *token;

    if (data)
        self_destruct();

    CBDATA_INIT_TYPE_FREECB(external_acl_data, free_external_acl_data);

    data = cbdataAlloc(external_acl_data);

    token = strtokFile();

    if (!token)
        self_destruct();

    data->def = cbdataReference(find_externalAclHelper(token));

    if (!data->def)
        self_destruct();

    // def->name is the name of the external_acl_type.
    // this is the name of the 'acl' directive being tested
    data->name = xstrdup(AclMatchedName);

    while ((token = strtokFile())) {
        wordlistAdd(&data->arguments, token);
    }
}

bool
ACLExternal::valid () const
{
#if USE_AUTH
    if (data->def->require_auth) {
        if (authenticateSchemeCount() == 0) {
            debugs(28, DBG_CRITICAL, "Can't use proxy auth because no authentication schemes were compiled.");
            return false;
        }

        if (authenticateActiveSchemeCount() == 0) {
            debugs(28, DBG_CRITICAL, "Can't use proxy auth because no authentication schemes are fully configured.");
            return false;
        }
    }
#endif

    return true;
}

bool
ACLExternal::empty () const
{
    return false;
}

ACLExternal::~ACLExternal()
{
    cbdataFree(data);
    safe_free (class_);
}

static void
copyResultsFromEntry(HttpRequest *req, const ExternalACLEntryPointer &entry)
{
    if (req) {
#if USE_AUTH
        if (entry->user.size())
            req->extacl_user = entry->user;

        if (entry->password.size())
            req->extacl_passwd = entry->password;
#endif
        if (!req->tag.size())
            req->tag = entry->tag;

        if (entry->log.size())
            req->extacl_log = entry->log;

        if (entry->message.size())
            req->extacl_message = entry->message;

        // attach the helper kv-pair to the transaction
        UpdateRequestNotes(req->clientConnectionManager.get(), *req, entry->notes);
    }
}

static allow_t
aclMatchExternal(external_acl_data *acl, ACLFilledChecklist *ch)
{
    debugs(82, 9, HERE << "acl=\"" << acl->def->name << "\"");
    ExternalACLEntryPointer entry = ch->extacl_entry;

    external_acl_message = "MISSING REQUIRED INFORMATION";

    if (entry != NULL) {
        if (entry->def == acl->def) {
            /* Ours, use it.. if the key matches */
            const char *key = makeExternalAclKey(ch, acl);
            if (!key)
                return ACCESS_DUNNO; // insufficent data to continue
            if (strcmp(key, (char*)entry->key) != 0) {
                debugs(82, 9, "entry key='" << (char *)entry->key << "', our key='" << key << "' dont match. Discarded.");
                // too bad. need a new lookup.
                entry = ch->extacl_entry = NULL;
            }
        } else {
            /* Not ours.. get rid of it */
            debugs(82, 9, "entry " << entry << " not valid or not ours. Discarded.");
            if (entry != NULL) {
                debugs(82, 9, "entry def=" << entry->def << ", our def=" << acl->def);
                const char *key = makeExternalAclKey(ch, acl); // may be nil
                debugs(82, 9, "entry key='" << (char *)entry->key << "', our key='" << key << "'");
            }
            entry = ch->extacl_entry = NULL;
        }
    }

    if (!entry) {
        debugs(82, 9, HERE << "No helper entry available");
#if USE_AUTH
        if (acl->def->require_auth) {
            /* Make sure the user is authenticated */
            debugs(82, 3, HERE << acl->def->name << " check user authenticated.");
            const allow_t ti = AuthenticateAcl(ch);
            if (ti != ACCESS_ALLOWED) {
                debugs(82, 2, HERE << acl->def->name << " user not authenticated (" << ti << ")");
                return ti;
            }
            debugs(82, 3, HERE << acl->def->name << " user is authenticated.");
        }
#endif
        const char *key = makeExternalAclKey(ch, acl);

        if (!key) {
            /* Not sufficient data to process */
            return ACCESS_DUNNO;
        }

        entry = static_cast<ExternalACLEntry *>(hash_lookup(acl->def->cache, key));

        const ExternalACLEntryPointer staleEntry = entry;
        if (entry != NULL && external_acl_entry_expired(acl->def, entry))
            entry = NULL;

        if (entry != NULL && external_acl_grace_expired(acl->def, entry)) {
            // refresh in the background
            ExternalACLLookup::Start(ch, acl, true);
            debugs(82, 4, HERE << "no need to wait for the refresh of '" <<
                   key << "' in '" << acl->def->name << "' (ch=" << ch << ").");
        }

        if (!entry) {
            debugs(82, 2, HERE << acl->def->name << "(\"" << key << "\") = lookup needed");

            if (acl->def->theHelper->stats.queue_size < (int)acl->def->theHelper->childs.n_active) {
                debugs(82, 2, HERE << "\"" << key << "\": queueing a call.");
                if (!ch->goAsync(ExternalACLLookup::Instance()))
                    debugs(82, 2, "\"" << key << "\": no async support!");
                debugs(82, 2, HERE << "\"" << key << "\": return -1.");
                return ACCESS_DUNNO; // expired cached or simply absent entry
            } else {
                if (!staleEntry) {
                    debugs(82, DBG_IMPORTANT, "WARNING: external ACL '" << acl->def->name <<
                           "' queue overload. Request rejected '" << key << "'.");
                    external_acl_message = "SYSTEM TOO BUSY, TRY AGAIN LATER";
                    return ACCESS_DUNNO;
                } else {
                    debugs(82, DBG_IMPORTANT, "WARNING: external ACL '" << acl->def->name <<
                           "' queue overload. Using stale result. '" << key << "'.");
                    entry = staleEntry;
                    /* Fall thru to processing below */
                }
            }
        }
    }

    debugs(82, 4, HERE << "entry = { date=" <<
           (long unsigned int) entry->date <<
           ", result=" << entry->result <<
           " tag=" << entry->tag <<
           " log=" << entry->log << " }");
#if USE_AUTH
    debugs(82, 4, HERE << "entry user=" << entry->user);
#endif

    external_acl_cache_touch(acl->def, entry);
    external_acl_message = entry->message.termedBuf();

    debugs(82, 2, HERE << acl->def->name << " = " << entry->result);
    copyResultsFromEntry(ch->request, entry);
    return entry->result;
}

int
ACLExternal::match(ACLChecklist *checklist)
{
    allow_t answer = aclMatchExternal(data, Filled(checklist));

    // convert to tri-state ACL match 1,0,-1
    switch (answer) {
    case ACCESS_ALLOWED:
        return 1; // match

    case ACCESS_DENIED:
        return 0; // non-match

    case ACCESS_DUNNO:
    case ACCESS_AUTH_REQUIRED:
    default:
        // If the answer is not allowed or denied (matches/not matches) and
        // async authentication is not in progress, then we are done.
        if (checklist->keepMatching())
            checklist->markFinished(answer, "aclMatchExternal exception");
        return -1; // other
    }
}

SBufList
ACLExternal::dump() const
{
    external_acl_data const *acl = data;
    SBufList rv;
    rv.push_back(SBuf(acl->def->name));

    for (wordlist *arg = acl->arguments; arg; arg = arg->next) {
        SBuf s;
        s.Printf(" %s", arg->key);
        rv.push_back(s);
    }

    return rv;
}

/******************************************************************
 * external_acl cache
 */

static void
external_acl_cache_touch(external_acl * def, const ExternalACLEntryPointer &entry)
{
    // this must not be done when nothing is being cached.
    if (def->cache_size <= 0 || (def->ttl <= 0 && entry->result == 1) || (def->negative_ttl <= 0 && entry->result != 1))
        return;

    dlinkDelete(&entry->lru, &def->lru_list);
    ExternalACLEntry *e = const_cast<ExternalACLEntry *>(entry.getRaw()); // XXX: make hash a std::map of Pointer.
    dlinkAdd(e, &entry->lru, &def->lru_list);
}

#if USE_OPENSSL
static const char *
external_acl_ssl_get_user_attribute(const ACLFilledChecklist &ch, const char *attr)
{
    if (ch.conn() != NULL && Comm::IsConnOpen(ch.conn()->clientConnection)) {
        if (SSL *ssl = fd_table[ch.conn()->clientConnection->fd].ssl)
            return sslGetUserAttribute(ssl, attr);
    }
    return NULL;
}
#endif

static char *
makeExternalAclKey(ACLFilledChecklist * ch, external_acl_data * acl_data)
{
    static MemBuf mb;
    char buf[256];
    int first = 1;
    wordlist *arg;
    HttpRequest *request = ch->request;
    HttpReply *reply = ch->reply;
    mb.reset();
    bool data_used = false;

    for (external_acl_format::Pointer format = acl_data->def->format; format != NULL; format = format->next) {
        const char *str = NULL;
        String sb;

        switch (format->type) {
#if USE_AUTH
        case Format::LFT_USER_LOGIN:
            // if this ACL line was the cause of credentials fetch
            // they may not already be in the checklist
            if (ch->auth_user_request == NULL && ch->request)
                ch->auth_user_request = ch->request->auth_user_request;

            if (ch->auth_user_request != NULL)
                str = ch->auth_user_request->username();
            break;
#endif
#if USE_IDENT
        case Format::LFT_USER_IDENT:
            str = ch->rfc931;

            if (!str || !*str) {
                // if we fail to go async, we still return NULL and the caller
                // will detect the failure in ACLExternal::match().
                (void)ch->goAsync(IdentLookup::Instance());
                return NULL;
            }

            break;
#endif

        case Format::LFT_CLIENT_IP_ADDRESS:
            str = ch->src_addr.toStr(buf,sizeof(buf));
            break;

        case Format::LFT_CLIENT_PORT:
            snprintf(buf, sizeof(buf), "%d", request->client_addr.port());
            str = buf;
            break;

#if USE_SQUID_EUI
        case Format::LFT_EXT_ACL_CLIENT_EUI48:
            if (request->clientConnectionManager.valid() && request->clientConnectionManager->clientConnection != NULL &&
                    request->clientConnectionManager->clientConnection->remoteEui48.encode(buf, sizeof(buf)))
                str = buf;
            break;

        case Format::LFT_EXT_ACL_CLIENT_EUI64:
            if (request->clientConnectionManager.valid() && request->clientConnectionManager->clientConnection != NULL &&
                    request->clientConnectionManager->clientConnection->remoteEui64.encode(buf, sizeof(buf)))
                str = buf;
            break;
#endif

        case Format::LFT_LOCAL_LISTENING_IP:
            str = request->my_addr.toStr(buf, sizeof(buf));
            break;

        case Format::LFT_LOCAL_LISTENING_PORT:
            snprintf(buf, sizeof(buf), "%d", request->my_addr.port());
            str = buf;
            break;

        case Format::LFT_CLIENT_REQ_URI:
            str = urlCanonical(request);
            break;

        case Format::LFT_CLIENT_REQ_URLDOMAIN:
            str = request->GetHost();
            break;

        case Format::LFT_CLIENT_REQ_URLSCHEME:
            str = request->url.getScheme().c_str();
            break;

        case Format::LFT_CLIENT_REQ_URLPORT:
            snprintf(buf, sizeof(buf), "%d", request->port);
            str = buf;
            break;

        case Format::LFT_CLIENT_REQ_URLPATH:
            str = request->urlpath.termedBuf();
            break;

        case Format::LFT_CLIENT_REQ_METHOD: {
            const SBuf &s = request->method.image();
            sb.append(s.rawContent(), s.length());
        }
        str = sb.termedBuf();
        break;

        case Format::LFT_ADAPTED_REQUEST_HEADER:
            if (format->header_id == -1)
                sb = request->header.getByName(format->header);
            else
                sb = request->header.getStrOrList(format->header_id);
            str = sb.termedBuf();
            break;

        case Format::LFT_ADAPTED_REQUEST_HEADER_ELEM:
            if (format->header_id == -1)
                sb = request->header.getByNameListMember(format->header, format->member, format->separator);
            else
                sb = request->header.getListMember(format->header_id, format->member, format->separator);
            str = sb.termedBuf();
            break;

        case Format::LFT_REPLY_HEADER:
            if (reply) {
                if (format->header_id == -1)
                    sb = reply->header.getByName(format->header);
                else
                    sb = reply->header.getStrOrList(format->header_id);
                str = sb.termedBuf();
            }
            break;

        case Format::LFT_REPLY_HEADER_ELEM:
            if (reply) {
                if (format->header_id == -1)
                    sb = reply->header.getByNameListMember(format->header, format->member, format->separator);
                else
                    sb = reply->header.getListMember(format->header_id, format->member, format->separator);
                str = sb.termedBuf();
            }
            break;

#if USE_OPENSSL

        case Format::LFT_EXT_ACL_USER_CERT_RAW:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificatePEM(ssl);
            }

            break;

        case Format::LFT_EXT_ACL_USER_CERTCHAIN_RAW:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificateChainPEM(ssl);
            }

            break;

        case Format::LFT_EXT_ACL_USER_CERT:
            str = external_acl_ssl_get_user_attribute(*ch, format->header);
            break;

        case Format::LFT_EXT_ACL_USER_CA_CERT:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetCAAttribute(ssl, format->header);
            }

            break;

        case Format::LFT_SSL_CLIENT_SNI:
            if (ch->conn() != NULL) {
                if (Ssl::ServerBump * srvBump = ch->conn()->serverBump()) {
                    if (!srvBump->clientSni.isEmpty())
                        str = srvBump->clientSni.c_str();
                }
            }
            break;

        case Format::LFT_SSL_SERVER_CERT_SUBJECT:
        case Format::LFT_SSL_SERVER_CERT_ISSUER: {
            X509 *serverCert = NULL;
            if (ch->serverCert.get())
                serverCert = ch->serverCert.get();
            else if (ch->conn() && ch->conn()->serverBump())
                serverCert = ch->conn()->serverBump()->serverCert.get();

            if (serverCert) {
                if (format->type == Format::LFT_SSL_SERVER_CERT_SUBJECT)
                    str = Ssl::GetX509UserAttribute(serverCert, "DN");
                else
                    str = Ssl::GetX509CAAttribute(serverCert, "DN");
            }
            break;
        }

#endif
#if USE_AUTH
        case Format::LFT_USER_EXTERNAL:
            str = request->extacl_user.termedBuf();
            break;
#endif
        case Format::LFT_USER_NAME:
            /* find the first available name from various sources */
#if USE_AUTH
            if (ch->auth_user_request != NULL)
                str = ch->auth_user_request->username();
            if ((!str || !*str) &&
                    (request->extacl_user.size() > 0 && request->extacl_user[0] != '-'))
                str = request->extacl_user.termedBuf();
#endif
#if USE_OPENSSL
            if (!str || !*str)
                str = external_acl_ssl_get_user_attribute(*ch, "CN");
#endif
#if USE_IDENT
            if (!str || !*str)
                str = ch->rfc931;
#endif
            break;
        case Format::LFT_EXT_LOG:
            str = request->extacl_log.termedBuf();
            break;
        case Format::LFT_TAG:
            str = request->tag.termedBuf();
            break;
        case Format::LFT_EXT_ACL_NAME:
            str = acl_data->name;
            break;
        case Format::LFT_EXT_ACL_DATA:
            data_used = true;
            for (arg = acl_data->arguments; arg; arg = arg->next) {
                if (!first)
                    sb.append(" ", 1);

                if (acl_data->def->quote == external_acl::QUOTE_METHOD_URL) {
                    const char *quoted = rfc1738_escape(arg->key);
                    sb.append(quoted, strlen(quoted));
                } else {
                    static MemBuf mb2;
                    mb2.init();
                    strwordquote(&mb2, arg->key);
                    sb.append(mb2.buf, mb2.size);
                    mb2.clean();
                }

                first = 0;
            }
            break;
        case Format::LFT_PERCENT:
            str = "%";
            break;

        default:
            // TODO: replace this function with Format::assemble()
            // For now die on unsupported logformat codes.
            fatalf("ERROR: unknown external_acl_type format %u", (uint8_t)format->type);
            break;
        }

        if (str)
            if (!*str)
                str = NULL;

        if (!str)
            str = "-";

        if (!first)
            mb.append(" ", 1);

        if (acl_data->def->quote == external_acl::QUOTE_METHOD_URL) {
            const char *quoted = rfc1738_escape(str);
            mb.append(quoted, strlen(quoted));
        } else {
            strwordquote(&mb, str);
        }

        sb.clean();

        first = 0;
    }

    if (!data_used) {
        for (arg = acl_data->arguments; arg; arg = arg->next) {
            if (!first)
                mb.append(" ", 1);

            if (acl_data->def->quote == external_acl::QUOTE_METHOD_URL) {
                const char *quoted = rfc1738_escape(arg->key);
                mb.append(quoted, strlen(quoted));
            } else {
                strwordquote(&mb, arg->key);
            }

            first = 0;
        }
    }

    return mb.buf;
}

static int
external_acl_entry_expired(external_acl * def, const ExternalACLEntryPointer &entry)
{
    if (def->cache_size <= 0)
        return 1;

    if (entry->date + (entry->result == 1 ? def->ttl : def->negative_ttl) < squid_curtime)
        return 1;
    else
        return 0;
}

static int
external_acl_grace_expired(external_acl * def, const ExternalACLEntryPointer &entry)
{
    if (def->cache_size <= 0)
        return 1;

    int ttl;
    ttl = entry->result == 1 ? def->ttl : def->negative_ttl;
    ttl = (ttl * (100 - def->grace)) / 100;

    if (entry->date + ttl <= squid_curtime)
        return 1;
    else
        return 0;
}

static ExternalACLEntryPointer
external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const & data)
{
    ExternalACLEntryPointer entry;

    // do not bother caching this result if TTL is going to expire it immediately
    if (def->cache_size <= 0 || (def->ttl <= 0 && data.result == 1) || (def->negative_ttl <= 0 && data.result != 1)) {
        debugs(82,6, HERE);
        entry = new ExternalACLEntry;
        entry->key = xstrdup(key);
        entry->update(data);
        entry->def = def;
        return entry;
    }

    entry = static_cast<ExternalACLEntry *>(hash_lookup(def->cache, key));
    debugs(82, 2, "external_acl_cache_add: Adding '" << key << "' = " << data.result);

    if (entry != NULL) {
        debugs(82, 3, "updating existing entry");
        entry->update(data);
        external_acl_cache_touch(def, entry);
        return entry;
    }

    entry = new ExternalACLEntry;
    entry->key = xstrdup(key);
    entry->update(data);

    def->add(entry);

    return entry;
}

static void
external_acl_cache_delete(external_acl * def, const ExternalACLEntryPointer &entry)
{
    assert(entry != NULL);
    assert(def->cache_size > 0 && entry->def == def);
    ExternalACLEntry *e = const_cast<ExternalACLEntry *>(entry.getRaw()); // XXX: make hash a std::map of Pointer.
    hash_remove_link(def->cache, e);
    dlinkDelete(&e->lru, &def->lru_list);
    e->unlock(); // unlock on behalf of the hash
    def->cache_entries -= 1;
}

/******************************************************************
 * external_acl helpers
 */

typedef struct _externalAclState externalAclState;

struct _externalAclState {
    EAH *callback;
    void *callback_data;
    char *key;
    external_acl *def;
    dlink_node list;
    externalAclState *queue;
};

CBDATA_TYPE(externalAclState);
static void
free_externalAclState(void *data)
{
    externalAclState *state = static_cast<externalAclState *>(data);
    safe_free(state->key);
    cbdataReferenceDone(state->callback_data);
    cbdataReferenceDone(state->def);
}

/*
 * The helper program receives queries on stdin, one
 * per line, and must return the result on on stdout
 *
 * General result syntax:
 *
 *   OK/ERR keyword=value ...
 *
 * Keywords:
 *
 *   user=      The users name (login)
 *   message=   Message describing the reason
 *   tag=   A string tag to be applied to the request that triggered the acl match.
 *          applies to both OK and ERR responses.
 *          Won't override existing request tags.
 *   log=   A string to be used in access logging
 *
 * Other keywords may be added to the protocol later
 *
 * value needs to be URL-encoded or enclosed in double quotes (")
 * with \-escaping on any whitespace, quotes, or slashes (\).
 */
static void
externalAclHandleReply(void *data, const Helper::Reply &reply)
{
    externalAclState *state = static_cast<externalAclState *>(data);
    externalAclState *next;
    ExternalACLEntryData entryData;
    entryData.result = ACCESS_DENIED;

    debugs(82, 2, HERE << "reply=" << reply);

    if (reply.result == Helper::Okay)
        entryData.result = ACCESS_ALLOWED;
    // XXX: handle other non-DENIED results better

    // XXX: make entryData store a proper Helper::Reply object instead of copying.

    entryData.notes.append(&reply.notes);

    const char *label = reply.notes.findFirst("tag");
    if (label != NULL && *label != '\0')
        entryData.tag = label;

    label = reply.notes.findFirst("message");
    if (label != NULL && *label != '\0')
        entryData.message = label;

    label = reply.notes.findFirst("log");
    if (label != NULL && *label != '\0')
        entryData.log = label;

#if USE_AUTH
    label = reply.notes.findFirst("user");
    if (label != NULL && *label != '\0')
        entryData.user = label;

    label = reply.notes.findFirst("password");
    if (label != NULL && *label != '\0')
        entryData.password = label;
#endif

    dlinkDelete(&state->list, &state->def->queue);

    ExternalACLEntryPointer entry;
    if (cbdataReferenceValid(state->def)) {
        // only cache OK and ERR results.
        if (reply.result == Helper::Okay || reply.result == Helper::Error)
            entry = external_acl_cache_add(state->def, state->key, entryData);
        else {
            const ExternalACLEntryPointer oldentry = static_cast<ExternalACLEntry *>(hash_lookup(state->def->cache, state->key));

            if (oldentry != NULL)
                external_acl_cache_delete(state->def, oldentry);
        }
    }

    do {
        void *cbdata;
        cbdataReferenceDone(state->def);

        if (state->callback && cbdataReferenceValidDone(state->callback_data, &cbdata))
            state->callback(cbdata, entry);

        next = state->queue;

        cbdataFree(state);

        state = next;
    } while (state);
}

void
ACLExternal::ExternalAclLookup(ACLChecklist *checklist, ACLExternal * me)
{
    ExternalACLLookup::Start(checklist, me->data, false);
}

void
ExternalACLLookup::Start(ACLChecklist *checklist, external_acl_data *acl, bool inBackground)
{
    external_acl *def = acl->def;

    ACLFilledChecklist *ch = Filled(checklist);
    const char *key = makeExternalAclKey(ch, acl);
    assert(key); // XXX: will fail if EXT_ACL_IDENT case needs an async lookup

    debugs(82, 2, HERE << (inBackground ? "bg" : "fg") << " lookup in '" <<
           def->name << "' for '" << key << "'");

    /* Check for a pending lookup to hook into */
    // only possible if we are caching results.
    externalAclState *oldstate = NULL;
    if (def->cache_size > 0) {
        for (dlink_node *node = def->queue.head; node; node = node->next) {
            externalAclState *oldstatetmp = static_cast<externalAclState *>(node->data);

            if (strcmp(key, oldstatetmp->key) == 0) {
                oldstate = oldstatetmp;
                break;
            }
        }
    }

    // A background refresh has no need to piggiback on a pending request:
    // When the pending request completes, the cache will be refreshed anyway.
    if (oldstate && inBackground) {
        debugs(82, 7, HERE << "'" << def->name << "' queue is already being refreshed (ch=" << ch << ")");
        return;
    }

    externalAclState *state = cbdataAlloc(externalAclState);
    state->def = cbdataReference(def);

    state->key = xstrdup(key);

    if (!inBackground) {
        state->callback = &ExternalACLLookup::LookupDone;
        state->callback_data = cbdataReference(checklist);
    }

    if (oldstate) {
        /* Hook into pending lookup */
        state->queue = oldstate->queue;
        oldstate->queue = state;
    } else {
        /* No pending lookup found. Sumbit to helper */

        /* Check for queue overload */

        if (def->theHelper->stats.queue_size >= (int)def->theHelper->childs.n_running) {
            debugs(82, 7, HERE << "'" << def->name << "' queue is too long");
            assert(inBackground); // or the caller should have checked
            cbdataFree(state);
            return;
        }

        /* Send it off to the helper */
        MemBuf buf;
        buf.init();

        buf.Printf("%s\n", key);

        debugs(82, 4, "externalAclLookup: looking up for '" << key << "' in '" << def->name << "'.");

        helperSubmit(def->theHelper, buf.buf, externalAclHandleReply, state);

        dlinkAdd(state, &state->list, &def->queue);

        buf.clean();
    }

    debugs(82, 4, "externalAclLookup: will wait for the result of '" << key <<
           "' in '" << def->name << "' (ch=" << ch << ").");
}

static void
externalAclStats(StoreEntry * sentry)
{
    external_acl *p;

    for (p = Config.externalAclHelperList; p; p = p->next) {
        storeAppendPrintf(sentry, "External ACL Statistics: %s\n", p->name);
        storeAppendPrintf(sentry, "Cache size: %d\n", p->cache->count);
        helperStats(sentry, p->theHelper);
        storeAppendPrintf(sentry, "\n");
    }
}

static void
externalAclRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("external_acl",
                        "External ACL stats",
                        externalAclStats, 0, 1);
}

void
externalAclInit(void)
{
    static int firstTimeInit = 1;
    external_acl *p;

    for (p = Config.externalAclHelperList; p; p = p->next) {
        if (!p->cache)
            p->cache = hash_create((HASHCMP *) strcmp, hashPrime(1024), hash4);

        if (!p->theHelper)
            p->theHelper = new helper(p->name);

        p->theHelper->cmdline = p->cmdline;

        p->theHelper->childs.updateLimits(p->children);

        p->theHelper->ipc_type = IPC_TCP_SOCKET;

        p->theHelper->addr = p->local_addr;

        helperOpenServers(p->theHelper);
    }

    if (firstTimeInit) {
        firstTimeInit = 0;
        CBDATA_INIT_TYPE_FREECB(externalAclState, free_externalAclState);
    }

    externalAclRegisterWithCacheManager();
}

void
externalAclShutdown(void)
{
    external_acl *p;

    for (p = Config.externalAclHelperList; p; p = p->next) {
        helperShutdown(p->theHelper);
    }
}

ExternalACLLookup ExternalACLLookup::instance_;
ExternalACLLookup *
ExternalACLLookup::Instance()
{
    return &instance_;
}

void
ExternalACLLookup::checkForAsync(ACLChecklist *checklist)const
{
    /* TODO: optimise this - we probably have a pointer to this
     * around somewhere */
    ACL *acl = ACL::FindByName(AclMatchedName);
    assert(acl);
    ACLExternal *me = dynamic_cast<ACLExternal *> (acl);
    assert (me);
    ACLExternal::ExternalAclLookup(checklist, me);
}

/// Called when an async lookup returns
void
ExternalACLLookup::LookupDone(void *data, const ExternalACLEntryPointer &result)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    checklist->extacl_entry = result;
    checklist->resumeNonBlockingCheck(ExternalACLLookup::Instance());
}

/* This registers "external" in the registry. To do dynamic definitions
 * of external ACL's, rather than a static prototype, have a Prototype instance
 * prototype in the class that defines each external acl 'class'.
 * Then, then the external acl instance is created, it self registers under
 * it's name.
 * Be sure that clone is fully functional for that acl class though!
 */
ACL::Prototype ACLExternal::RegistryProtoype(&ACLExternal::RegistryEntry_, "external");

ACLExternal ACLExternal::RegistryEntry_("external");

ACL *
ACLExternal::clone() const
{
    return new ACLExternal(*this);
}

ACLExternal::ACLExternal(char const *theClass) : data(NULL), class_(xstrdup(theClass))
{}

ACLExternal::ACLExternal(ACLExternal const & old) : data(NULL), class_(old.class_ ? xstrdup(old.class_) : NULL)
{
    /* we don't have copy constructors for the data yet */
    assert(!old.data);
}

char const *
ACLExternal::typeString() const
{
    return class_;
}

bool
ACLExternal::isProxyAuth() const
{
#if USE_AUTH
    return data->def->require_auth;
#else
    return false;
#endif
}


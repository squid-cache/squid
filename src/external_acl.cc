
/*
 * DEBUG: section 82    External ACL
 * AUTHOR: Henrik Nordstrom, MARA Systems AB
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  The contents of this file is Copyright (C) 2002 by MARA Systems AB,
 *  Sweden, unless otherwise is indicated in the specific function. The
 *  author gives his full permission to include this file into the Squid
 *  software product under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
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

#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "ExternalACL.h"
#include "ExternalACLEntry.h"
#include "fde.h"
#include "helper.h"
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
#include "URLScheme.h"
#include "wordlist.h"
#if USE_SSL
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

typedef struct _external_acl_format external_acl_format;

static char *makeExternalAclKey(ACLFilledChecklist * ch, external_acl_data * acl_data);
static void external_acl_cache_delete(external_acl * def, external_acl_entry * entry);
static int external_acl_entry_expired(external_acl * def, external_acl_entry * entry);
static int external_acl_grace_expired(external_acl * def, external_acl_entry * entry);
static void external_acl_cache_touch(external_acl * def, external_acl_entry * entry);
static external_acl_entry *external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const &data);

/******************************************************************
 * external_acl directive
 */

class external_acl
{

public:
    external_acl *next;

    void add(ExternalACLEntry *);

    void trimCache();

    int ttl;

    int negative_ttl;

    int grace;

    char *name;

    external_acl_format *format;

    wordlist *cmdline;

    HelperChildConfig children;

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

struct _external_acl_format {
    enum format_type {
        EXT_ACL_UNKNOWN,
#if USE_AUTH
        EXT_ACL_LOGIN,
#endif
#if USE_IDENT
        EXT_ACL_IDENT,
#endif
        EXT_ACL_SRC,
        EXT_ACL_SRCPORT,
#if USE_SQUID_EUI
        EXT_ACL_SRCEUI48,
        EXT_ACL_SRCEUI64,
#endif
        EXT_ACL_MYADDR,
        EXT_ACL_MYPORT,
        EXT_ACL_URI,
        EXT_ACL_DST,
        EXT_ACL_PROTO,
        EXT_ACL_PORT,
        EXT_ACL_PATH,
        EXT_ACL_METHOD,

        EXT_ACL_HEADER_REQUEST,
        EXT_ACL_HEADER_REQUEST_MEMBER,
        EXT_ACL_HEADER_REQUEST_ID,
        EXT_ACL_HEADER_REQUEST_ID_MEMBER,

        EXT_ACL_HEADER_REPLY,
        EXT_ACL_HEADER_REPLY_MEMBER,
        EXT_ACL_HEADER_REPLY_ID,
        EXT_ACL_HEADER_REPLY_ID_MEMBER,

#if USE_SSL
        EXT_ACL_USER_CERT,
        EXT_ACL_USER_CA_CERT,
        EXT_ACL_USER_CERT_RAW,
        EXT_ACL_USER_CERTCHAIN_RAW,
#endif
#if USE_AUTH
        EXT_ACL_EXT_USER,
#endif
        EXT_ACL_EXT_LOG,
        EXT_ACL_TAG,
        EXT_ACL_ACLNAME,
        EXT_ACL_ACLDATA,
        EXT_ACL_PERCENT,
        EXT_ACL_END
    } type;
    external_acl_format *next;
    char *header;
    char *member;
    char separator;
    http_hdr_type header_id;
};

/* FIXME: These are not really cbdata, but it is an easy way
 * to get them pooled, refcounted, accounted and freed properly...
 */
CBDATA_TYPE(external_acl);
CBDATA_TYPE(external_acl_format);

static void
free_external_acl_format(void *data)
{
    external_acl_format *p = static_cast<external_acl_format *>(data);
    safe_free(p->header);
}

static void
free_external_acl(void *data)
{
    external_acl *p = static_cast<external_acl *>(data);
    safe_free(p->name);

    while (p->format) {
        external_acl_format *f = p->format;
        p->format = f->next;
        cbdataFree(f);
    }

    wordlistDestroy(&p->cmdline);

    if (p->theHelper) {
        helperShutdown(p->theHelper);
        delete p->theHelper;
        p->theHelper = NULL;
    }

    while (p->lru_list.tail)
        external_acl_cache_delete(p, static_cast<external_acl_entry *>(p->lru_list.tail->data));
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
parse_header_token(external_acl_format *format, char *header, const _external_acl_format::format_type type)
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

        if (type == _external_acl_format::EXT_ACL_HEADER_REQUEST)
            format->type = _external_acl_format::EXT_ACL_HEADER_REQUEST_MEMBER;
        else
            format->type = _external_acl_format::EXT_ACL_HEADER_REQUEST_MEMBER;
    } else {
        format->type = type;
    }

    format->header = xstrdup(header);
    format->header_id = httpHeaderIdByNameDef(header, strlen(header));

    if (format->header_id != -1) {
        if (member) {
            if (type == _external_acl_format::EXT_ACL_HEADER_REQUEST)
                format->type = _external_acl_format::EXT_ACL_HEADER_REQUEST_ID_MEMBER;
            else
                format->type = _external_acl_format::EXT_ACL_HEADER_REPLY_ID_MEMBER;
        } else {
            if (type == _external_acl_format::EXT_ACL_HEADER_REQUEST)
                format->type = _external_acl_format::EXT_ACL_HEADER_REQUEST_ID;
            else
                format->type = _external_acl_format::EXT_ACL_HEADER_REPLY_ID;
        }
    }
}

void
parse_externalAclHelper(external_acl ** list)
{
    external_acl *a;
    char *token;
    external_acl_format **p;

    CBDATA_INIT_TYPE_FREECB(external_acl, free_external_acl);
    CBDATA_INIT_TYPE_FREECB(external_acl_format, free_external_acl_format);

    a = cbdataAlloc(external_acl);

    /* set defaults */
    a->ttl = DEFAULT_EXTERNAL_ACL_TTL;
    a->negative_ttl = -1;
    a->cache_size = 256*1024;
    a->children.n_max = DEFAULT_EXTERNAL_ACL_CHILDREN;
    a->children.n_startup = a->children.n_max;
    a->children.n_idle = 1;
    a->local_addr.SetLocalhost();
    a->quote = external_acl::QUOTE_METHOD_URL;

    token = strtok(NULL, w_space);

    if (!token)
        self_destruct();

    a->name = xstrdup(token);

    token = strtok(NULL, w_space);

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
            a->quote = external_acl::QUOTE_METHOD_URL;
        } else if (strcmp(token, "quote=url") == 0) {
            a->quote = external_acl::QUOTE_METHOD_URL;
        } else if (strcmp(token, "quote=shell") == 0) {
            a->quote = external_acl::QUOTE_METHOD_SHELL;

            /* INET6: allow admin to configure some helpers explicitly to
                      bind to IPv4/v6 localhost port. */
        } else if (strcmp(token, "ipv4") == 0) {
            if ( !a->local_addr.SetIPv4() ) {
                debugs(3, DBG_CRITICAL, "WARNING: Error converting " << a->local_addr << " to IPv4 in " << a->name );
            }
        } else if (strcmp(token, "ipv6") == 0) {
            if (!Ip::EnableIpv6)
                debugs(3, DBG_CRITICAL, "WARNING: --enable-ipv6 required for external ACL helpers to use IPv6: " << a->name );
            // else nothing to do.
        } else {
            break;
        }

        token = strtok(NULL, w_space);
    }

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
    p = &a->format;

    while (token) {
        external_acl_format *format;

        /* stop on first non-format token found */

        if (*token != '%')
            break;

        format = cbdataAlloc(external_acl_format);

        if (strncmp(token, "%{", 2) == 0) {
            // deprecated. but assume the old configs all referred to request headers.
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %{...} is being replaced by %>ha{...} for : " << token);
            parse_header_token(format, (token+2), _external_acl_format::EXT_ACL_HEADER_REQUEST);
        } else if (strncmp(token, "%>{", 3) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %>{...} is being replaced by %>ha{...} for : " << token);
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REQUEST);
        } else if (strncmp(token, "%>ha{", 5) == 0) {
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REQUEST);
        } else if (strncmp(token, "%<{", 3) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %<{...} is being replaced by %<h{...} for : " << token);
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REPLY);
        } else if (strncmp(token, "%<h{", 4) == 0) {
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REPLY);
#if USE_AUTH
        } else if (strcmp(token, "%LOGIN") == 0 || strcmp(token, "%ul") == 0) {
            format->type = _external_acl_format::EXT_ACL_LOGIN;
            a->require_auth = true;
#endif
        }
#if USE_IDENT
        else if (strcmp(token, "%IDENT") == 0 || strcmp(token, "%ui") == 0)
            format->type = _external_acl_format::EXT_ACL_IDENT;
#endif
        else if (strcmp(token, "%SRC") == 0 || strcmp(token, "%>a") == 0)
            format->type = _external_acl_format::EXT_ACL_SRC;
        else if (strcmp(token, "%SRCPORT") == 0 || strcmp(token, "%>p") == 0)
            format->type = _external_acl_format::EXT_ACL_SRCPORT;
#if USE_SQUID_EUI
        else if (strcmp(token, "%SRCEUI48") == 0)
            format->type = _external_acl_format::EXT_ACL_SRCEUI48;
        else if (strcmp(token, "%SRCEUI64") == 0)
            format->type = _external_acl_format::EXT_ACL_SRCEUI64;
#endif
        else if (strcmp(token, "%MYADDR") == 0 || strcmp(token, "%la") == 0)
            format->type = _external_acl_format::EXT_ACL_MYADDR;
        else if (strcmp(token, "%MYPORT") == 0 || strcmp(token, "%lp") == 0)
            format->type = _external_acl_format::EXT_ACL_MYPORT;
        else if (strcmp(token, "%URI") == 0 || strcmp(token, "%>ru") == 0)
            format->type = _external_acl_format::EXT_ACL_URI;
        else if (strcmp(token, "%DST") == 0)
            format->type = _external_acl_format::EXT_ACL_DST;
        else if (strcmp(token, "%PROTO") == 0)
            format->type = _external_acl_format::EXT_ACL_PROTO;
        else if (strcmp(token, "%PORT") == 0)
            format->type = _external_acl_format::EXT_ACL_PORT;
        else if (strcmp(token, "%PATH") == 0 || strcmp(token, "%>rp") == 0)
            format->type = _external_acl_format::EXT_ACL_PATH;
        else if (strcmp(token, "%METHOD") == 0 || strcmp(token, "%>rm") == 0)
            format->type = _external_acl_format::EXT_ACL_METHOD;
#if USE_SSL
        else if (strcmp(token, "%USER_CERT") == 0)
            format->type = _external_acl_format::EXT_ACL_USER_CERT_RAW;
        else if (strcmp(token, "%USER_CERTCHAIN") == 0)
            format->type = _external_acl_format::EXT_ACL_USER_CERTCHAIN_RAW;
        else if (strncmp(token, "%USER_CERT_", 11) == 0) {
            format->type = _external_acl_format::EXT_ACL_USER_CERT;
            format->header = xstrdup(token + 11);
        } else if (strncmp(token, "%USER_CA_CERT_", 11) == 0) {
            format->type = _external_acl_format::EXT_ACL_USER_CA_CERT;
            format->header = xstrdup(token + 11);
        } else if (strncmp(token, "%CA_CERT_", 11) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type %CA_CERT_* code is obsolete. Use %USER_CA_CERT_* instead");
            format->type = _external_acl_format::EXT_ACL_USER_CA_CERT;
            format->header = xstrdup(token + 11);
        }
#endif
#if USE_AUTH
        else if (strcmp(token, "%EXT_USER") == 0)
            format->type = _external_acl_format::EXT_ACL_EXT_USER;
#endif
        else if (strcmp(token, "%EXT_LOG") == 0)
            format->type = _external_acl_format::EXT_ACL_EXT_LOG;
        else if (strcmp(token, "%TAG") == 0)
            format->type = _external_acl_format::EXT_ACL_TAG;
        else if (strcmp(token, "%ACL") == 0)
            format->type = _external_acl_format::EXT_ACL_ACLNAME;
        else if (strcmp(token, "%DATA") == 0)
            format->type = _external_acl_format::EXT_ACL_ACLDATA;
        else if (strcmp(token, "%%") == 0)
            format->type = _external_acl_format::EXT_ACL_PERCENT;
        else {
            debugs(0, DBG_CRITICAL, "ERROR: Unknown Format token " << token);
            self_destruct();
        }

        *p = format;
        p = &format->next;
        token = strtok(NULL, w_space);
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
    const external_acl_format *format;
    const wordlist *word;

    for (node = list; node; node = node->next) {
        storeAppendPrintf(sentry, "%s %s", name, node->name);

        if (!node->local_addr.IsIPv6())
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

        for (format = node->format; format; format = format->next) {
            switch (format->type) {

            case _external_acl_format::EXT_ACL_HEADER_REQUEST:
            case _external_acl_format::EXT_ACL_HEADER_REQUEST_ID:
                storeAppendPrintf(sentry, " %%>{%s}", format->header);
                break;

            case _external_acl_format::EXT_ACL_HEADER_REQUEST_MEMBER:
            case _external_acl_format::EXT_ACL_HEADER_REQUEST_ID_MEMBER:
                storeAppendPrintf(sentry, " %%>{%s:%s}", format->header, format->member);
                break;

            case _external_acl_format::EXT_ACL_HEADER_REPLY:
            case _external_acl_format::EXT_ACL_HEADER_REPLY_ID:
                storeAppendPrintf(sentry, " %%<{%s}", format->header);
                break;

            case _external_acl_format::EXT_ACL_HEADER_REPLY_MEMBER:
            case _external_acl_format::EXT_ACL_HEADER_REPLY_ID_MEMBER:
                storeAppendPrintf(sentry, " %%<{%s:%s}", format->header, format->member);
                break;
#define DUMP_EXT_ACL_TYPE(a) \
            case _external_acl_format::EXT_ACL_##a: \
                storeAppendPrintf(sentry, " %%%s", #a); \
                break
#define DUMP_EXT_ACL_TYPE_FMT(a, fmt, ...) \
            case _external_acl_format::EXT_ACL_##a: \
                storeAppendPrintf(sentry, fmt, ##__VA_ARGS__); \
                break
#if USE_AUTH
                DUMP_EXT_ACL_TYPE(LOGIN);
#endif
#if USE_IDENT

                DUMP_EXT_ACL_TYPE(IDENT);
#endif

                DUMP_EXT_ACL_TYPE(SRC);
                DUMP_EXT_ACL_TYPE(SRCPORT);
#if USE_SQUID_EUI
                DUMP_EXT_ACL_TYPE(SRCEUI48);
                DUMP_EXT_ACL_TYPE(SRCEUI64);
#endif

                DUMP_EXT_ACL_TYPE(MYADDR);
                DUMP_EXT_ACL_TYPE(MYPORT);
                DUMP_EXT_ACL_TYPE(URI);
                DUMP_EXT_ACL_TYPE(DST);
                DUMP_EXT_ACL_TYPE(PROTO);
                DUMP_EXT_ACL_TYPE(PORT);
                DUMP_EXT_ACL_TYPE(PATH);
                DUMP_EXT_ACL_TYPE(METHOD);
#if USE_SSL
                DUMP_EXT_ACL_TYPE_FMT(USER_CERT_RAW, " %%USER_CERT_RAW");
                DUMP_EXT_ACL_TYPE_FMT(USER_CERTCHAIN_RAW, " %%USER_CERTCHAIN_RAW");
                DUMP_EXT_ACL_TYPE_FMT(USER_CERT, " %%USER_CERT_%s", format->header);
                DUMP_EXT_ACL_TYPE_FMT(USER_CA_CERT, " %%USER_CA_CERT_%s", format->header);
#endif
#if USE_AUTH
                DUMP_EXT_ACL_TYPE(EXT_USER);
#endif
                DUMP_EXT_ACL_TYPE(EXT_LOG);
                DUMP_EXT_ACL_TYPE(TAG);
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
external_acl::add(ExternalACLEntry *anEntry)
{
    trimCache();
    assert (anEntry->def == NULL);
    anEntry->def = this;
    hash_join(cache, anEntry);
    dlinkAdd(anEntry, &anEntry->lru, &lru_list);
    ++cache_entries;
}

void
external_acl::trimCache()
{
    if (cache_size && cache_entries >= cache_size)
        external_acl_cache_delete(this, static_cast<external_acl_entry *>(lru_list.tail->data));
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

    token = strtok(NULL, w_space);

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
copyResultsFromEntry(HttpRequest *req, external_acl_entry *entry)
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
    }
}

static allow_t
aclMatchExternal(external_acl_data *acl, ACLFilledChecklist *ch)
{
    const char *key = "";
    debugs(82, 9, HERE << "acl=\"" << acl->def->name << "\"");
    external_acl_entry *entry = ch->extacl_entry;

    if (entry) {
        if (cbdataReferenceValid(entry) && entry->def == acl->def) {
            /* Ours, use it.. if the key matches */
            key = makeExternalAclKey(ch, acl);
            if (strcmp(key, (char*)entry->key) != 0) {
                debugs(82, 9, HERE << "entry key='" << (char *)entry->key << "', our key='" << key << "' dont match. Discarded.");
                // too bad. need a new lookup.
                cbdataReferenceDone(ch->extacl_entry);
                entry = NULL;
            }
        } else {
            /* Not valid, or not ours.. get rid of it */
            debugs(82, 9, HERE << "entry " << entry << " not valid or not ours. Discarded.");
            if (entry) {
                debugs(82, 9, HERE << "entry def=" << entry->def << ", our def=" << acl->def);
                key = makeExternalAclKey(ch, acl);
                debugs(82, 9, HERE << "entry key='" << (char *)entry->key << "', our key='" << key << "'");
            }
            cbdataReferenceDone(ch->extacl_entry);
            entry = NULL;
        }
    }

    external_acl_message = "MISSING REQUIRED INFORMATION";

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
        key = makeExternalAclKey(ch, acl);

        if (!key) {
            /* Not sufficient data to process */
            return ACCESS_DUNNO;
        }

        entry = static_cast<external_acl_entry *>(hash_lookup(acl->def->cache, key));

        external_acl_entry *staleEntry = entry;
        if (entry && external_acl_entry_expired(acl->def, entry))
            entry = NULL;

        if (entry && external_acl_grace_expired(acl->def, entry)) {
            // refresh in the background
            ExternalACLLookup::Start(ch, acl, true);
            debugs(82, 4, HERE << "no need to wait for the refresh of '" <<
                   key << "' in '" << acl->def->name << "' (ch=" << ch << ").");
        }

        if (!entry) {
            debugs(82, 2, HERE << acl->def->name << "(\"" << key << "\") = lookup needed");
            debugs(82, 2, HERE << "\"" << key << "\": entry=@" <<
                   entry << ", age=" << (entry ? (long int) squid_curtime - entry->date : 0));

            if (acl->def->theHelper->stats.queue_size < (int)acl->def->theHelper->childs.n_active) {
                debugs(82, 2, HERE << "\"" << key << "\": queueing a call.");
                ch->changeState(ExternalACLLookup::Instance());
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
        // async authentication is not needed (asyncNeeded), then we are done.
        if (!checklist->asyncNeeded())
            checklist->markFinished(answer, "aclMatchExternal exception");
        return -1; // other
    }
}

wordlist *
ACLExternal::dump() const
{
    external_acl_data const *acl = data;
    wordlist *result = NULL;
    wordlist *arg;
    MemBuf mb;
    mb.init();
    mb.Printf("%s", acl->def->name);

    for (arg = acl->arguments; arg; arg = arg->next) {
        mb.Printf(" %s", arg->key);
    }

    wordlistAdd(&result, mb.buf);
    mb.clean();
    return result;
}

/******************************************************************
 * external_acl cache
 */

static void
external_acl_cache_touch(external_acl * def, external_acl_entry * entry)
{
    // this must not be done when nothing is being cached.
    if (def->cache_size <= 0 || (def->ttl <= 0 && entry->result == 1) || (def->negative_ttl <= 0 && entry->result != 1))
        return;

    dlinkDelete(&entry->lru, &def->lru_list);
    dlinkAdd(entry, &entry->lru, &def->lru_list);
}

static char *
makeExternalAclKey(ACLFilledChecklist * ch, external_acl_data * acl_data)
{
    static MemBuf mb;
    char buf[256];
    int first = 1;
    wordlist *arg;
    external_acl_format *format;
    HttpRequest *request = ch->request;
    HttpReply *reply = ch->reply;
    mb.reset();
    bool data_used = false;

    for (format = acl_data->def->format; format; format = format->next) {
        const char *str = NULL;
        String sb;

        switch (format->type) {
#if USE_AUTH
        case _external_acl_format::EXT_ACL_LOGIN:
            // if this ACL line was the cause of credentials fetch
            // they may not already be in the checklist
            if (ch->auth_user_request == NULL && ch->request)
                ch->auth_user_request = ch->request->auth_user_request;

            if (ch->auth_user_request != NULL)
                str = ch->auth_user_request->username();
            break;
#endif
#if USE_IDENT
        case _external_acl_format::EXT_ACL_IDENT:
            str = ch->rfc931;

            if (!str || !*str) {
                ch->changeState(IdentLookup::Instance());
                return NULL;
            }

            break;
#endif

        case _external_acl_format::EXT_ACL_SRC:
            str = ch->src_addr.NtoA(buf,sizeof(buf));
            break;

        case _external_acl_format::EXT_ACL_SRCPORT:
            snprintf(buf, sizeof(buf), "%d", request->client_addr.GetPort());
            str = buf;
            break;

#if USE_SQUID_EUI
        case _external_acl_format::EXT_ACL_SRCEUI48:
            if (request->clientConnectionManager.valid() && request->clientConnectionManager->clientConnection != NULL &&
                    request->clientConnectionManager->clientConnection->remoteEui48.encode(buf, sizeof(buf)))
                str = buf;
            break;

        case _external_acl_format::EXT_ACL_SRCEUI64:
            if (request->clientConnectionManager.valid() && request->clientConnectionManager->clientConnection != NULL &&
                    request->clientConnectionManager->clientConnection->remoteEui64.encode(buf, sizeof(buf)))
                str = buf;
            break;
#endif

        case _external_acl_format::EXT_ACL_MYADDR:
            str = request->my_addr.NtoA(buf, sizeof(buf));
            break;

        case _external_acl_format::EXT_ACL_MYPORT:
            snprintf(buf, sizeof(buf), "%d", request->my_addr.GetPort());
            str = buf;
            break;

        case _external_acl_format::EXT_ACL_URI:
            str = urlCanonical(request);
            break;

        case _external_acl_format::EXT_ACL_DST:
            str = request->GetHost();
            break;

        case _external_acl_format::EXT_ACL_PROTO:
            str = AnyP::ProtocolType_str[request->protocol];
            break;

        case _external_acl_format::EXT_ACL_PORT:
            snprintf(buf, sizeof(buf), "%d", request->port);
            str = buf;
            break;

        case _external_acl_format::EXT_ACL_PATH:
            str = request->urlpath.termedBuf();
            break;

        case _external_acl_format::EXT_ACL_METHOD:
            str = RequestMethodStr(request->method);
            break;

        case _external_acl_format::EXT_ACL_HEADER_REQUEST:
            sb = request->header.getByName(format->header);
            str = sb.termedBuf();
            break;

        case _external_acl_format::EXT_ACL_HEADER_REQUEST_ID:
            sb = request->header.getStrOrList(format->header_id);
            str = sb.termedBuf();
            break;

        case _external_acl_format::EXT_ACL_HEADER_REQUEST_MEMBER:
            sb = request->header.getByNameListMember(format->header, format->member, format->separator);
            str = sb.termedBuf();
            break;

        case _external_acl_format::EXT_ACL_HEADER_REQUEST_ID_MEMBER:
            sb = request->header.getListMember(format->header_id, format->member, format->separator);
            str = sb.termedBuf();
            break;

        case _external_acl_format::EXT_ACL_HEADER_REPLY:
            if (reply) {
                sb = reply->header.getByName(format->header);
                str = sb.termedBuf();
            }
            break;

        case _external_acl_format::EXT_ACL_HEADER_REPLY_ID:
            if (reply) {
                sb = reply->header.getStrOrList(format->header_id);
                str = sb.termedBuf();
            }
            break;

        case _external_acl_format::EXT_ACL_HEADER_REPLY_MEMBER:
            if (reply) {
                sb = reply->header.getByNameListMember(format->header, format->member, format->separator);
                str = sb.termedBuf();
            }
            break;

        case _external_acl_format::EXT_ACL_HEADER_REPLY_ID_MEMBER:
            if (reply) {
                sb = reply->header.getListMember(format->header_id, format->member, format->separator);
                str = sb.termedBuf();
            }
            break;
#if USE_SSL

        case _external_acl_format::EXT_ACL_USER_CERT_RAW:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificatePEM(ssl);
            }

            break;

        case _external_acl_format::EXT_ACL_USER_CERTCHAIN_RAW:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificateChainPEM(ssl);
            }

            break;

        case _external_acl_format::EXT_ACL_USER_CERT:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetUserAttribute(ssl, format->header);
            }

            break;

        case _external_acl_format::EXT_ACL_USER_CA_CERT:

            if (ch->conn() != NULL && Comm::IsConnOpen(ch->conn()->clientConnection)) {
                SSL *ssl = fd_table[ch->conn()->clientConnection->fd].ssl;

                if (ssl)
                    str = sslGetCAAttribute(ssl, format->header);
            }

            break;
#endif
#if USE_AUTH
        case _external_acl_format::EXT_ACL_EXT_USER:
            str = request->extacl_user.termedBuf();
            break;
#endif
        case _external_acl_format::EXT_ACL_EXT_LOG:
            str = request->extacl_log.termedBuf();
            break;
        case _external_acl_format::EXT_ACL_TAG:
            str = request->tag.termedBuf();
            break;
        case _external_acl_format::EXT_ACL_ACLNAME:
            str = acl_data->name;
            break;
        case _external_acl_format::EXT_ACL_ACLDATA:
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
        case _external_acl_format::EXT_ACL_PERCENT:
            str = "%";
            break;
        case _external_acl_format::EXT_ACL_UNKNOWN:

        case _external_acl_format::EXT_ACL_END:
            fatal("unknown external_acl format error");
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
external_acl_entry_expired(external_acl * def, external_acl_entry * entry)
{
    if (def->cache_size <= 0)
        return 1;

    if (entry->date + (entry->result == 1 ? def->ttl : def->negative_ttl) < squid_curtime)
        return 1;
    else
        return 0;
}

static int
external_acl_grace_expired(external_acl * def, external_acl_entry * entry)
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

static external_acl_entry *
external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const & data)
{
    ExternalACLEntry *entry;

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

    if (entry) {
        debugs(82, 3, "ExternalACLEntry::update: updating existing entry");
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
external_acl_cache_delete(external_acl * def, external_acl_entry * entry)
{
    assert(def->cache_size > 0 && entry->def == def);
    hash_remove_link(def->cache, entry);
    dlinkDelete(&entry->lru, &def->lru_list);
    def->cache_entries -= 1;
    delete entry;
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
 *   tag= 	A string tag to be applied to the request that triggered the acl match.
 *   		applies to both OK and ERR responses.
 *   		Won't override existing request tags.
 *   log=	A string to be used in access logging
 *
 * Other keywords may be added to the protocol later
 *
 * value needs to be enclosed in quotes if it may contain whitespace, or
 * the whitespace escaped using \ (\ escaping obviously also applies to
 * any " characters)
 */

static void
externalAclHandleReply(void *data, char *reply)
{
    externalAclState *state = static_cast<externalAclState *>(data);
    externalAclState *next;
    char *status;
    char *token;
    char *value;
    char *t = NULL;
    ExternalACLEntryData entryData;
    entryData.result = ACCESS_DENIED;
    external_acl_entry *entry = NULL;

    debugs(82, 2, "externalAclHandleReply: reply=\"" << reply << "\"");

    if (reply) {
        status = strwordtok(reply, &t);

        if (status && strcmp(status, "OK") == 0)
            entryData.result = ACCESS_ALLOWED;

        while ((token = strwordtok(NULL, &t))) {
            value = strchr(token, '=');

            if (value) {
                *value = '\0';	/* terminate the token, and move up to the value */
                ++value;

                if (state->def->quote == external_acl::QUOTE_METHOD_URL)
                    rfc1738_unescape(value);

                if (strcmp(token, "message") == 0)
                    entryData.message = value;
                else if (strcmp(token, "error") == 0)
                    entryData.message = value;
                else if (strcmp(token, "tag") == 0)
                    entryData.tag = value;
                else if (strcmp(token, "log") == 0)
                    entryData.log = value;
#if USE_AUTH
                else if (strcmp(token, "user") == 0)
                    entryData.user = value;
                else if (strcmp(token, "password") == 0)
                    entryData.password = value;
                else if (strcmp(token, "passwd") == 0)
                    entryData.password = value;
                else if (strcmp(token, "login") == 0)
                    entryData.user = value;
#endif
            }
        }
    }

    dlinkDelete(&state->list, &state->def->queue);

    if (cbdataReferenceValid(state->def)) {
        if (reply)
            entry = external_acl_cache_add(state->def, state->key, entryData);
        else {
            external_acl_entry *oldentry = (external_acl_entry *)hash_lookup(state->def->cache, state->key);

            if (oldentry)
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
    assert(key);

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
    checklist->asyncInProgress(true);
    ACLExternal::ExternalAclLookup(checklist, me);
}

/// Called when an async lookup returns
void
ExternalACLLookup::LookupDone(void *data, void *result)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    checklist->extacl_entry = cbdataReference((external_acl_entry *)result);
    checklist->asyncInProgress(false);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->matchNonBlocking();
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

ACLExternal::ACLExternal (char const *theClass) : data (NULL), class_ (xstrdup (theClass))
{}

ACLExternal::ACLExternal (ACLExternal const & old) : data (NULL), class_ (old.class_ ? xstrdup (old.class_) : NULL)
{
    /* we don't have copy constructors for the data yet */
    assert (!old.data);
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

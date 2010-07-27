
/*
 * $Id$
 *
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
#include "CacheManager.h"
#include "ExternalACL.h"
#include "ExternalACLEntry.h"
#include "auth/UserRequest.h"
#include "SquidTime.h"
#include "Store.h"
#include "fde.h"
#include "acl/FilledChecklist.h"
#include "acl/Acl.h"
#if USE_IDENT
#include "ident/AclIdent.h"
#endif
#include "ip/tools.h"
#include "client_side.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "auth/Acl.h"
#include "auth/Gadgets.h"
#include "helper.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "URLScheme.h"
#include "wordlist.h"

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

    void add
    (ExternalACLEntry *);

    void trimCache();

    int ttl;

    int negative_ttl;

    int grace;

    char *name;

    external_acl_format *format;

    wordlist *cmdline;

    int children;

    int concurrency;

    helper *theHelper;

    hash_table *cache;

    dlink_list lru_list;

    int cache_size;

    int cache_entries;

    dlink_list queue;

    bool require_auth;

    enum {
        QUOTE_METHOD_SHELL = 1,
        QUOTE_METHOD_URL
    } quote;

    IpAddress local_addr;
};

struct _external_acl_format {
    enum format_type {
        EXT_ACL_UNKNOWN,
        EXT_ACL_LOGIN,
#if USE_IDENT
        EXT_ACL_IDENT,
#endif
        EXT_ACL_SRC,
        EXT_ACL_SRCPORT,
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
        EXT_ACL_CA_CERT,
        EXT_ACL_USER_CERT_RAW,
        EXT_ACL_USER_CERTCHAIN_RAW,
#endif
        EXT_ACL_EXT_USER,
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
        helperFree(p->theHelper);
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
        *member++ = '\0';

        if (!xisalnum(*member))
            format->separator = *member++;
        else
            format->separator = ',';

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
    a->children = DEFAULT_EXTERNAL_ACL_CHILDREN;
    a->cache_size = 256*1024;
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
            a->children = atoi(token + 9);
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            a->concurrency = atoi(token + 12);
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
                debugs(3, 0, "WARNING: Error converting " << a->local_addr << " to IPv4 in " << a->name );
            }
        } else if (strcmp(token, "ipv6") == 0) {
            if (!Ip::EnableIpv6)
                debugs(3, 0, "WARNING: --enable-ipv6 required for external ACL helpers to use IPv6: " << a->name );
            // else nothing to do.
        } else {
            break;
        }

        token = strtok(NULL, w_space);
    }

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
            debugs(82, DBG_IMPORTANT, "WARNING: external_acl_type format %{...} is being replaced by %>{...} for : " << token);
            parse_header_token(format, (token+2), _external_acl_format::EXT_ACL_HEADER_REQUEST);
        } else if (strncmp(token, "%>{", 3) == 0) {
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REQUEST);
        } else if (strncmp(token, "%<{", 3) == 0) {
            parse_header_token(format, (token+3), _external_acl_format::EXT_ACL_HEADER_REPLY);
        } else if (strcmp(token, "%LOGIN") == 0) {
            format->type = _external_acl_format::EXT_ACL_LOGIN;
            a->require_auth = true;
        }

#if USE_IDENT
        else if (strcmp(token, "%IDENT") == 0)
            format->type = _external_acl_format::EXT_ACL_IDENT;

#endif

        else if (strcmp(token, "%SRC") == 0)
            format->type = _external_acl_format::EXT_ACL_SRC;
        else if (strcmp(token, "%SRCPORT") == 0)
            format->type = _external_acl_format::EXT_ACL_SRCPORT;
        else if (strcmp(token, "%MYADDR") == 0)
            format->type = _external_acl_format::EXT_ACL_MYADDR;
        else if (strcmp(token, "%MYPORT") == 0)
            format->type = _external_acl_format::EXT_ACL_MYPORT;
        else if (strcmp(token, "%URI") == 0)
            format->type = _external_acl_format::EXT_ACL_URI;
        else if (strcmp(token, "%DST") == 0)
            format->type = _external_acl_format::EXT_ACL_DST;
        else if (strcmp(token, "%PROTO") == 0)
            format->type = _external_acl_format::EXT_ACL_PROTO;
        else if (strcmp(token, "%PORT") == 0)
            format->type = _external_acl_format::EXT_ACL_PORT;
        else if (strcmp(token, "%PATH") == 0)
            format->type = _external_acl_format::EXT_ACL_PATH;
        else if (strcmp(token, "%METHOD") == 0)
            format->type = _external_acl_format::EXT_ACL_METHOD;

#if USE_SSL

        else if (strcmp(token, "%USER_CERT") == 0)
            format->type = _external_acl_format::EXT_ACL_USER_CERT_RAW;
        else if (strcmp(token, "%USER_CERTCHAIN") == 0)
            format->type = _external_acl_format::EXT_ACL_USER_CERTCHAIN_RAW;
        else if (strncmp(token, "%USER_CERT_", 11) == 0) {
            format->type = _external_acl_format::EXT_ACL_USER_CERT;
            format->header = xstrdup(token + 11);
        } else if (strncmp(token, "%CA_CERT_", 11) == 0) {
            format->type = _external_acl_format::EXT_ACL_USER_CERT;
            format->header = xstrdup(token + 11);
        }

#endif
        else if (strcmp(token, "%EXT_USER") == 0)
            format->type = _external_acl_format::EXT_ACL_EXT_USER;
        else {
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

        if (node->children != DEFAULT_EXTERNAL_ACL_CHILDREN)
            storeAppendPrintf(sentry, " children=%d", node->children);

        if (node->concurrency)
            storeAppendPrintf(sentry, " concurrency=%d", node->concurrency);

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

                DUMP_EXT_ACL_TYPE(LOGIN);
#if USE_IDENT

                DUMP_EXT_ACL_TYPE(IDENT);
#endif

                DUMP_EXT_ACL_TYPE(SRC);
                DUMP_EXT_ACL_TYPE(SRCPORT);
                DUMP_EXT_ACL_TYPE(MYADDR);
                DUMP_EXT_ACL_TYPE(MYPORT);
                DUMP_EXT_ACL_TYPE(URI);
                DUMP_EXT_ACL_TYPE(DST);
                DUMP_EXT_ACL_TYPE(PROTO);
                DUMP_EXT_ACL_TYPE(PORT);
                DUMP_EXT_ACL_TYPE(PATH);
                DUMP_EXT_ACL_TYPE(METHOD);
#if USE_SSL

            case _external_acl_format::EXT_ACL_USER_CERT_RAW:
                storeAppendPrintf(sentry, " %%USER_CERT");
                break;

            case _external_acl_format::EXT_ACL_USER_CERTCHAIN_RAW:
                storeAppendPrintf(sentry, " %%USER_CERTCHAIN");
                break;

            case _external_acl_format::EXT_ACL_USER_CERT:
                storeAppendPrintf(sentry, " %%USER_CERT_%s", format->header);
                break;

            case _external_acl_format::EXT_ACL_CA_CERT:
                storeAppendPrintf(sentry, " %%USER_CERT_%s", format->header);
                break;
#endif

                DUMP_EXT_ACL_TYPE(EXT_USER);

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

external_acl::add
(ExternalACLEntry *anEntry)
{
    trimCache();
    assert (anEntry->def == NULL);
    anEntry->def = this;
    hash_join(cache, anEntry);
    dlinkAdd(anEntry, &anEntry->lru, &lru_list);
    cache_entries++;
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
    wordlist *arguments;
};

CBDATA_TYPE(external_acl_data);
static void
free_external_acl_data(void *data)
{
    external_acl_data *p = static_cast<external_acl_data *>(data);
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

    while ((token = strtokFile())) {
        wordlistAdd(&data->arguments, token);
    }
}

bool
ACLExternal::valid () const
{
    if (data->def->require_auth) {
        if (authenticateSchemeCount() == 0) {
            debugs(28, 0, "Can't use proxy auth because no authentication schemes were compiled.");
            return false;
        }

        if (authenticateActiveSchemeCount() == 0) {
            debugs(28, 0, "Can't use proxy auth because no authentication schemes are fully configured.");
            return false;
        }
    }

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

static int
aclMatchExternal(external_acl_data *acl, ACLFilledChecklist *ch)
{
    int result;
    external_acl_entry *entry;
    const char *key = "";
    debugs(82, 9, "aclMatchExternal: acl=\"" << acl->def->name << "\"");
    entry = ch->extacl_entry;

    if (entry) {
        if (cbdataReferenceValid(entry) && entry->def == acl->def &&
                strcmp((char *)entry->key, key) == 0) {
            /* Ours, use it.. */
        } else {
            /* Not valid, or not ours.. get rid of it */
            cbdataReferenceDone(ch->extacl_entry);
            entry = NULL;
        }
    }

    external_acl_message = "MISSING REQUIRED INFORMATION";

    if (!entry) {
        if (acl->def->require_auth) {
            int ti;
            /* Make sure the user is authenticated */

            if ((ti = AuthenticateAcl(ch)) != 1) {
                debugs(82, 2, "aclMatchExternal: " << acl->def->name << " user not authenticated (" << ti << ")");
                return ti;
            }
        }

        key = makeExternalAclKey(ch, acl);

        if (acl->def->require_auth)
            AUTHUSERREQUESTUNLOCK(ch->auth_user_request, "ACLChecklist via aclMatchExternal");

        if (!key) {
            /* Not sufficient data to process */
            return -1;
        }

        entry = static_cast<external_acl_entry *>(hash_lookup(acl->def->cache, key));

        if (!entry || external_acl_grace_expired(acl->def, entry)) {
            debugs(82, 2, "aclMatchExternal: " << acl->def->name << "(\"" << key << "\") = lookup needed");
            debugs(82, 2, "aclMatchExternal: \"" << key << "\": entry=@" <<
                   entry << ", age=" << (entry ? (long int) squid_curtime - entry->date : 0));

            if (acl->def->theHelper->stats.queue_size <= acl->def->theHelper->n_running) {
                debugs(82, 2, "aclMatchExternal: \"" << key << "\": queueing a call.");
                ch->changeState (ExternalACLLookup::Instance());

                if (entry == NULL) {
                    debugs(82, 2, "aclMatchExternal: \"" << key << "\": return -1.");
                    return -1;
                }
            } else {
                if (!entry) {
                    debugs(82, 1, "aclMatchExternal: '" << acl->def->name <<
                           "' queue overload. Request rejected '" << key << "'.");
                    external_acl_message = "SYSTEM TOO BUSY, TRY AGAIN LATER";
                    return -1;
                } else {
                    debugs(82, 1, "aclMatchExternal: '" << acl->def->name <<
                           "' queue overload. Using stale result. '" << key << "'.");
                    /* Fall thru to processing below */
                }
            }
        }
    }

    external_acl_cache_touch(acl->def, entry);
    result = entry->result;
    external_acl_message = entry->message.termedBuf();

    debugs(82, 2, "aclMatchExternal: " << acl->def->name << " = " << result);

    if (ch->request) {
        if (entry->user.size())
            ch->request->extacl_user = entry->user;

        if (entry->password.size())
            ch->request->extacl_passwd = entry->password;

        if (!ch->request->tag.size())
            ch->request->tag = entry->tag;

        if (entry->log.size())
            ch->request->extacl_log = entry->log;

        if (entry->message.size())
            ch->request->extacl_message = entry->message;
    }

    return result;
}

int
ACLExternal::match(ACLChecklist *checklist)
{
    return aclMatchExternal (data, Filled(checklist));
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

    for (format = acl_data->def->format; format; format = format->next) {
        const char *str = NULL;
        String sb;

        switch (format->type) {

        case _external_acl_format::EXT_ACL_LOGIN:
            assert (ch->auth_user_request);
            str = ch->auth_user_request->username();
            break;
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
            str = ProtocolStr[request->protocol];
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

            if (ch->conn() != NULL) {
                SSL *ssl = fd_table[ch->conn()->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificatePEM(ssl);
            }

            break;

        case _external_acl_format::EXT_ACL_USER_CERTCHAIN_RAW:

            if (ch->conn() != NULL) {
                SSL *ssl = fd_table[ch->conn()->fd].ssl;

                if (ssl)
                    str = sslGetUserCertificateChainPEM(ssl);
            }

            break;

        case _external_acl_format::EXT_ACL_USER_CERT:

            if (ch->conn() != NULL) {
                SSL *ssl = fd_table[ch->conn()->fd].ssl;

                if (ssl)
                    str = sslGetUserAttribute(ssl, format->header);
            }

            break;

        case _external_acl_format::EXT_ACL_CA_CERT:

            if (ch->conn() != NULL) {
                SSL *ssl = fd_table[ch->conn()->fd].ssl;

                if (ssl)
                    str = sslGetCAAttribute(ssl, format->header);
            }

            break;
#endif

        case _external_acl_format::EXT_ACL_EXT_USER:
            str = request->extacl_user.termedBuf();
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

    return mb.buf;
}

static int
external_acl_entry_expired(external_acl * def, external_acl_entry * entry)
{
    if (entry->date + (entry->result == 1 ? def->ttl : def->negative_ttl) < squid_curtime)
        return 1;
    else
        return 0;
}

static int
external_acl_grace_expired(external_acl * def, external_acl_entry * entry)
{
    int ttl;
    ttl = entry->result == 1 ? def->ttl : def->negative_ttl;
    ttl = (ttl * (100 - def->grace)) / 100;

    if (entry->date + ttl < squid_curtime)
        return 1;
    else
        return 0;
}

static external_acl_entry *
external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const & data)
{
    ExternalACLEntry *entry = static_cast<ExternalACLEntry *>(hash_lookup(def->cache, key));
    debugs(82, 2, "external_acl_cache_add: Adding '" << key << "' = " << data.result);

    if (entry) {
        debugs(82, 3, "ExternalACLEntry::update: updating existing entry");
        entry->update (data);
        external_acl_cache_touch(def, entry);

        return entry;
    }

    entry = new ExternalACLEntry;
    entry->key = xstrdup(key);
    entry->update (data);

    def->add
    (entry);

    return entry;
}

static void
external_acl_cache_delete(external_acl * def, external_acl_entry * entry)
{
    assert (entry->def == def);
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
    char *t;
    ExternalACLEntryData entryData;
    entryData.result = 0;
    external_acl_entry *entry = NULL;

    debugs(82, 2, "externalAclHandleReply: reply=\"" << reply << "\"");

    if (reply) {
        status = strwordtok(reply, &t);

        if (status && strcmp(status, "OK") == 0)
            entryData.result = 1;

        while ((token = strwordtok(NULL, &t))) {
            value = strchr(token, '=');

            if (value) {
                *value++ = '\0';	/* terminate the token, and move up to the value */

                if (state->def->quote == external_acl::QUOTE_METHOD_URL)
                    rfc1738_unescape(value);

                if (strcmp(token, "user") == 0)
                    entryData.user = value;
                else if (strcmp(token, "message") == 0)
                    entryData.message = value;
                else if (strcmp(token, "error") == 0)
                    entryData.message = value;
                else if (strcmp(token, "tag") == 0)
                    entryData.tag = value;
                else if (strcmp(token, "log") == 0)
                    entryData.log = value;
                else if (strcmp(token, "password") == 0)
                    entryData.password = value;
                else if (strcmp(token, "passwd") == 0)
                    entryData.password = value;
                else if (strcmp(token, "login") == 0)
                    entryData.user = value;
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
ACLExternal::ExternalAclLookup(ACLChecklist *checklist, ACLExternal * me, EAH * callback, void *callback_data)
{
    MemBuf buf;
    external_acl_data *acl = me->data;
    external_acl *def = acl->def;
    externalAclState *state;
    dlink_node *node;
    externalAclState *oldstate = NULL;
    bool graceful = 0;

    ACLFilledChecklist *ch = Filled(checklist);
    if (acl->def->require_auth) {
        int ti;
        /* Make sure the user is authenticated */

        if ((ti = AuthenticateAcl(ch)) != 1) {
            debugs(82, 1, "externalAclLookup: " << acl->def->name <<
                   " user authentication failure (" << ti << ", ch=" << ch << ")");
            callback(callback_data, NULL);
            return;
        }
    }

    const char *key = makeExternalAclKey(ch, acl);

    if (!key) {
        debugs(82, 1, "externalAclLookup: lookup in '" << def->name <<
               "', prerequisit failure (ch=" << ch << ")");
        callback(callback_data, NULL);
        return;
    }

    debugs(82, 2, "externalAclLookup: lookup in '" << def->name << "' for '" << key << "'");

    external_acl_entry *entry = static_cast<external_acl_entry *>(hash_lookup(def->cache, key));

    if (entry && external_acl_entry_expired(def, entry))
        entry = NULL;

    /* Check for a pending lookup to hook into */
    for (node = def->queue.head; node; node = node->next) {
        externalAclState *oldstatetmp = static_cast<externalAclState *>(node->data);

        if (strcmp(key, oldstatetmp->key) == 0) {
            oldstate = oldstatetmp;
            break;
        }
    }

    if (entry && external_acl_grace_expired(def, entry)) {
        if (oldstate) {
            debugs(82, 4, "externalAclLookup: in grace period, but already pending lookup ('" << key << "', ch=" << ch << ")");
            callback(callback_data, entry);
            return;
        } else {
            graceful = 1; // grace expired, (neg)ttl did not, and we must start a new lookup.
        }
    }

    // The entry is in the cache, grace_ttl did not expired.
    if (!graceful && entry && !external_acl_grace_expired(def, entry)) {
        /* Should not really happen, but why not.. */
        callback(callback_data, entry);
        debugs(82, 4, "externalAclLookup: no lookup pending for '" << key << "', and grace not expired");
        debugs(82, 4, "externalAclLookup: (what tha' hell?)");
        return;
    }

    /* No pending lookup found. Sumbit to helper */
    state = cbdataAlloc(externalAclState);

    state->def = cbdataReference(def);

    state->key = xstrdup(key);

    if (!graceful) {
        state->callback = callback;
        state->callback_data = cbdataReference(callback_data);
    }

    if (oldstate) {
        /* Hook into pending lookup */
        state->queue = oldstate->queue;
        oldstate->queue = state;
    } else {
        /* Check for queue overload */

        if (def->theHelper->stats.queue_size >= def->theHelper->n_running) {
            debugs(82, 1, "externalAclLookup: '" << def->name << "' queue overload (ch=" << ch << ")");
            cbdataFree(state);
            callback(callback_data, entry);
            return;
        }

        /* Send it off to the helper */
        buf.init();

        buf.Printf("%s\n", key);

        debugs(82, 4, "externalAclLookup: looking up for '" << key << "' in '" << def->name << "'.");

        helperSubmit(def->theHelper, buf.buf, externalAclHandleReply, state);

        dlinkAdd(state, &state->list, &def->queue);

        buf.clean();
    }

    if (graceful) {
        /* No need to wait during grace period */
        debugs(82, 4, "externalAclLookup: no need to wait for the result of '" <<
               key << "' in '" << def->name << "' (ch=" << ch << ").");
        debugs(82, 4, "externalAclLookup: using cached entry " << entry);

        if (entry != NULL) {
            debugs(82, 4, "externalAclLookup: entry = { date=" <<
                   (long unsigned int) entry->date << ", result=" <<
                   entry->result << ", user=" << entry->user << " tag=" <<
                   entry->tag << " log=" << entry->log << " }");

        }

        callback(callback_data, entry);
        return;
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
    CacheManager::GetInstance()->
    registerAction("external_acl",
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
            p->theHelper = helperCreate(p->name);

        p->theHelper->cmdline = p->cmdline;

        p->theHelper->n_to_start = p->children;

        p->theHelper->concurrency = p->concurrency;

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
    ACLExternal::ExternalAclLookup(checklist, me, LookupDone, checklist);
}

void
ExternalACLLookup::LookupDone(void *data, void *result)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    checklist->extacl_entry = cbdataReference((external_acl_entry *)result);
    checklist->asyncInProgress(false);
    checklist->changeState (ACLChecklist::NullState::Instance());
    checklist->check();
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
    return data->def->require_auth;
}

/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
#include "client_side_request.h"
#include "comm/Connection.h"
#include "ConfigParser.h"
#include "ExternalACL.h"
#include "ExternalACLEntry.h"
#include "fde.h"
#include "format/Token.h"
#include "helper.h"
#include "helper/Reply.h"
#include "http/Stream.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "Store.h"
#include "tools.h"
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

#ifndef DEFAULT_EXTERNAL_ACL_TTL
#define DEFAULT_EXTERNAL_ACL_TTL 1 * 60 * 60
#endif
#ifndef DEFAULT_EXTERNAL_ACL_CHILDREN
#define DEFAULT_EXTERNAL_ACL_CHILDREN 5
#endif

static void external_acl_cache_delete(external_acl * def, const ExternalACLEntryPointer &entry);
static int external_acl_entry_expired(external_acl * def, const ExternalACLEntryPointer &entry);
static int external_acl_grace_expired(external_acl * def, const ExternalACLEntryPointer &entry);
static void external_acl_cache_touch(external_acl * def, const ExternalACLEntryPointer &entry);
static ExternalACLEntryPointer external_acl_cache_add(external_acl * def, const char *key, ExternalACLEntryData const &data);

/******************************************************************
 * external_acl directive
 */

class external_acl
{
    /* XXX: These are not really cbdata, but it is an easy way
     * to get them pooled, refcounted, accounted and freed properly...
     * Use RefCountable MEMPROXY_CLASS instead
     */
    CBDATA_CLASS(external_acl);

public:
    external_acl();
    ~external_acl();

    external_acl *next;

    void add(const ExternalACLEntryPointer &);

    void trimCache();

    bool maybeCacheable(const Acl::Answer &) const;

    int ttl;

    int negative_ttl;

    int grace;

    char *name;

    Format::Format format;

    wordlist *cmdline;

    Helper::ChildConfig children;

    Helper::Client::Pointer theHelper;

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

    Format::Quoting quote; // default quoting to use, set by protocol= parameter

    Ip::Address local_addr;
};

CBDATA_CLASS_INIT(external_acl);

external_acl::external_acl() :
    next(nullptr),
    ttl(DEFAULT_EXTERNAL_ACL_TTL),
    negative_ttl(-1),
    grace(1),
    name(nullptr),
    format("external_acl_type"),
    cmdline(nullptr),
    children(DEFAULT_EXTERNAL_ACL_CHILDREN),
    theHelper(nullptr),
    cache(nullptr),
    cache_size(256*1024),
    cache_entries(0),
#if USE_AUTH
    require_auth(0),
#endif
    quote(Format::LOG_QUOTE_URL)
{
    local_addr.setLocalhost();
}

external_acl::~external_acl()
{
    xfree(name);
    wordlistDestroy(&cmdline);

    if (theHelper) {
        helperShutdown(theHelper);
        theHelper = nullptr;
    }

    while (lru_list.tail) {
        ExternalACLEntryPointer e(static_cast<ExternalACLEntry *>(lru_list.tail->data));
        external_acl_cache_delete(this, e);
    }
    if (cache)
        hashFreeMemory(cache);

    while (next) {
        external_acl *node = next;
        next = node->next;
        node->next = nullptr; // prevent recursion
        delete node;
    }
}

void
parse_externalAclHelper(external_acl ** list)
{
    char *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    external_acl *a = new external_acl;
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
        } else if (strncmp(token, "queue-size=", 11) == 0) {
            a->children.queue_size = atoi(token + 11);
            a->children.defaultQueueSize = false;
        } else if (strncmp(token, "cache=", 6) == 0) {
            a->cache_size = atoi(token + 6);
        } else if (strncmp(token, "grace=", 6) == 0) {
            a->grace = atoi(token + 6);
        } else if (strcmp(token, "protocol=2.5") == 0) {
            a->quote = Format::LOG_QUOTE_SHELL;
        } else if (strcmp(token, "protocol=3.0") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option protocol=3.0 is deprecated. Remove this from your config.");
            a->quote = Format::LOG_QUOTE_URL;
        } else if (strcmp(token, "quote=url") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option quote=url is deprecated. Remove this from your config.");
            a->quote = Format::LOG_QUOTE_URL;
        } else if (strcmp(token, "quote=shell") == 0) {
            debugs(3, DBG_PARSE_NOTE(2), "WARNING: external_acl_type option quote=shell is deprecated. Use protocol=2.5 if still needed.");
            a->quote = Format::LOG_QUOTE_SHELL;

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

    if (a->children.defaultQueueSize)
        a->children.queue_size = 2 * a->children.n_max;

    /* Legacy external_acl_type format parser.
     * Handles a series of %... tokens where any non-% means
     * the start of another parameter field (ie the path to binary).
     */
    enum Format::Quoting quote = Format::LOG_QUOTE_NONE;
    Format::Token **fmt = &a->format.format;
    bool data_used = false;
    while (token) {
        /* stop on first non-% token found */
        if (*token != '%')
            break;

        *fmt = new Format::Token;
        // these tokens are whitespace delimited
        (*fmt)->space = true;

        // set the default encoding to match the protocol= config
        // this will be overridden by explicit %macro attributes
        (*fmt)->quote = a->quote;

        // compatibility for old tokens incompatible with Format::Token syntax
#if USE_OPENSSL // do not bother unless we have to.
        if (strncmp(token, "%USER_CERT_", 11) == 0) {
            (*fmt)->type = Format::LFT_EXT_ACL_USER_CERT;
            (*fmt)->data.string = xstrdup(token + 11);
            (*fmt)->data.header.header = (*fmt)->data.string;
        } else if (strncmp(token, "%USER_CA_CERT_", 14) == 0) {
            (*fmt)->type = Format::LFT_EXT_ACL_USER_CA_CERT;
            (*fmt)->data.string = xstrdup(token + 14);
            (*fmt)->data.header.header = (*fmt)->data.string;
        } else if (strncmp(token, "%CA_CERT_", 9) == 0) {
            debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type %CA_CERT_* code is obsolete. Use %USER_CA_CERT_* instead");
            (*fmt)->type = Format::LFT_EXT_ACL_USER_CA_CERT;
            (*fmt)->data.string = xstrdup(token + 9);
            (*fmt)->data.header.header = (*fmt)->data.string;
        } else
#endif
            if (strncmp(token,"%<{", 3) == 0) {
                SBuf tmp("%<h");
                tmp.append(token+2);
                debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %<{...} is deprecated. Use " << tmp);
                const size_t parsedLen = (*fmt)->parse(tmp.c_str(), &quote);
                assert(parsedLen == tmp.length());
                assert((*fmt)->type == Format::LFT_REPLY_HEADER ||
                       (*fmt)->type == Format::LFT_REPLY_HEADER_ELEM);

            } else if (strncmp(token,"%>{", 3) == 0) {
                SBuf tmp("%>ha");
                tmp.append(token+2);
                debugs(82, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: external_acl_type format %>{...} is deprecated. Use " << tmp);
                const size_t parsedLen = (*fmt)->parse(tmp.c_str(), &quote);
                assert(parsedLen == tmp.length());
                assert((*fmt)->type == Format::LFT_ADAPTED_REQUEST_HEADER ||
                       (*fmt)->type == Format::LFT_ADAPTED_REQUEST_HEADER_ELEM);

            } else {
                // we can use the Format::Token::parse() method since it
                // only pulls off one token. Since we already checked
                // for '%' prefix above this is guaranteed to be a token.
                const size_t len = (*fmt)->parse(token, &quote);
                assert(len == strlen(token));
            }

        // process special token-specific actions (only if necessary)
#if USE_AUTH
        if ((*fmt)->type == Format::LFT_USER_LOGIN)
            a->require_auth = true;
#endif

        if ((*fmt)->type == Format::LFT_EXT_ACL_DATA)
            data_used = true;

        fmt = &((*fmt)->next);
        token = ConfigParser::NextToken();
    }

    /* There must be at least one format token */
    if (!a->format.format) {
        delete a;
        self_destruct();
        return;
    }

    // format has implicit %DATA on the end if not used explicitly
    if (!data_used) {
        *fmt = new Format::Token;
        (*fmt)->type = Format::LFT_EXT_ACL_DATA;
        (*fmt)->quote = Format::LOG_QUOTE_NONE;
    }

    /* helper */
    if (!token) {
        delete a;
        self_destruct();
        return;
    }

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

        if (node->children.n_startup != 0) // sync with helper/ChildConfig.cc default
            storeAppendPrintf(sentry, " children-startup=%d", node->children.n_startup);

        if (node->children.n_idle != 1) // sync with helper/ChildConfig.cc default
            storeAppendPrintf(sentry, " children-idle=%d", node->children.n_idle);

        if (node->children.concurrency != 0)
            storeAppendPrintf(sentry, " concurrency=%d", node->children.concurrency);

        if (node->cache)
            storeAppendPrintf(sentry, " cache=%d", node->cache_size);

        if (node->quote == Format::LOG_QUOTE_SHELL)
            storeAppendPrintf(sentry, " protocol=2.5");

        node->format.dump(sentry, nullptr, false);

        for (word = node->cmdline; word; word = word->next)
            storeAppendPrintf(sentry, " %s", word->key);

        storeAppendPrintf(sentry, "\n");
    }
}

void
free_externalAclHelper(external_acl ** list)
{
    delete *list;
    *list = nullptr;
}

static external_acl *
find_externalAclHelper(const char *name)
{
    external_acl *node;

    for (node = Config.externalAclHelperList; node; node = node->next) {
        if (strcmp(node->name, name) == 0)
            return node;
    }

    return nullptr;
}

void
external_acl::add(const ExternalACLEntryPointer &anEntry)
{
    trimCache();
    assert(anEntry != nullptr);
    assert (anEntry->def == nullptr);
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

bool
external_acl::maybeCacheable(const Acl::Answer &result) const
{
    if (cache_size <= 0)
        return false; // cache is disabled

    if (result == ACCESS_DUNNO)
        return false; // non-cacheable response

    if ((result.allowed() ? ttl : negative_ttl) <= 0)
        return false; // not caching this type of response

    return true;
}

/******************************************************************
 * external acl type
 */

class external_acl_data
{
    CBDATA_CLASS(external_acl_data);

public:
    explicit external_acl_data(external_acl * const aDef): def(cbdataReference(aDef)), arguments(nullptr) {}
    ~external_acl_data();

    external_acl *def;
    SBuf name;
    wordlist *arguments;
};

CBDATA_CLASS_INIT(external_acl_data);

external_acl_data::~external_acl_data()
{
    wordlistDestroy(&arguments);
    cbdataReferenceDone(def);
}

void
ACLExternal::parse()
{
    if (data) {
        self_destruct();
        return;
    }

    char *token = ConfigParser::strtokFile();

    if (!token) {
        self_destruct();
        return;
    }

    data = new external_acl_data(find_externalAclHelper(token));

    if (!data->def) {
        delete data;
        self_destruct();
        return;
    }

    // def->name is the name of the external_acl_type.
    // this is the name of the 'acl' directive being tested
    data->name = name;

    while ((token = ConfigParser::strtokFile())) {
        wordlistAdd(&data->arguments, token);
    }
}

bool
ACLExternal::valid () const
{
#if USE_AUTH
    if (data->def->require_auth) {
        if (authenticateSchemeCount() == 0) {
            debugs(28, DBG_CRITICAL, "ERROR: Cannot use proxy auth because no authentication schemes were compiled.");
            return false;
        }

        if (authenticateActiveSchemeCount() == 0) {
            debugs(28, DBG_CRITICAL, "ERROR: Cannot use proxy auth because no authentication schemes are fully configured.");
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
    delete data;
    xfree(class_);
}

static void
copyResultsFromEntry(const HttpRequest::Pointer &req, const ExternalACLEntryPointer &entry)
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

// TODO: Diff reduction. Rename this helper method to match_() or similar.
Acl::Answer
ACLExternal::aclMatchExternal(external_acl_data *acl, ACLFilledChecklist *ch) const
{
    // Despite its external_acl C++ type name, acl->def is not an ACL (i.e. not
    // a reference-counted Acl::Node) and gets invalidated by reconfiguration.
    // TODO: RefCount external_acl, so that we do not have to bail here.
    if (!cbdataReferenceValid(acl->def)) {
        debugs(82, 3, "cannot resume matching; external_acl gone");
        return ACCESS_DUNNO;
    }

    debugs(82, 9, "acl=\"" << acl->def->name << "\"");
    ExternalACLEntryPointer entry = ch->extacl_entry;

    external_acl_message = "MISSING REQUIRED INFORMATION";

    if (entry != nullptr) {
        if (entry->def == acl->def) {
            /* Ours, use it.. if the key matches */
            const char *key = makeExternalAclKey(ch, acl);
            if (!key)
                return ACCESS_DUNNO; // insufficient data to continue
            if (strcmp(key, (char*)entry->key) != 0) {
                debugs(82, 9, "entry key='" << (char *)entry->key << "', our key='" << key << "' do not match. Discarded.");
                // too bad. need a new lookup.
                entry = ch->extacl_entry = nullptr;
            }
        } else {
            /* Not ours.. get rid of it */
            debugs(82, 9, "entry " << entry << " not valid or not ours. Discarded.");
            if (entry != nullptr) {
                debugs(82, 9, "entry def=" << entry->def << ", our def=" << acl->def);
                const char *key = makeExternalAclKey(ch, acl); // may be nil
                debugs(82, 9, "entry key='" << (char *)entry->key << "', our key='" << key << "'");
            }
            entry = ch->extacl_entry = nullptr;
        }
    }

    if (!entry) {
        debugs(82, 9, "No helper entry available");
#if USE_AUTH
        if (acl->def->require_auth) {
            /* Make sure the user is authenticated */
            debugs(82, 3, acl->def->name << " check user authenticated.");
            const auto ti = AuthenticateAcl(ch, *this);
            if (!ti.allowed()) {
                debugs(82, 2, acl->def->name << " user not authenticated (" << ti << ")");
                return ti;
            }
            debugs(82, 3, acl->def->name << " user is authenticated.");
        }
#endif
        const char *key = makeExternalAclKey(ch, acl);

        if (!key) {
            /* Not sufficient data to process */
            return ACCESS_DUNNO;
        }

        entry = static_cast<ExternalACLEntry *>(hash_lookup(acl->def->cache, key));

        const ExternalACLEntryPointer staleEntry = entry;
        if (entry != nullptr && external_acl_entry_expired(acl->def, entry))
            entry = nullptr;

        if (entry != nullptr && external_acl_grace_expired(acl->def, entry)) {
            // refresh in the background
            startLookup(ch, acl, true);
            debugs(82, 4, "no need to wait for the refresh of '" <<
                   key << "' in '" << acl->def->name << "' (ch=" << ch << ").");
        }

        if (!entry) {
            debugs(82, 2, acl->def->name << "(\"" << key << "\") = lookup needed");

            // TODO: All other helpers allow temporary overload. Should not we?
            if (!acl->def->theHelper->willOverload()) {
                debugs(82, 2, "\"" << key << "\": queueing a call.");
                if (!ch->goAsync(StartLookup, *this))
                    debugs(82, 2, "\"" << key << "\": no async support!");
                debugs(82, 2, "\"" << key << "\": return -1.");
                return ACCESS_DUNNO; // expired cached or simply absent entry
            } else {
                if (!staleEntry) {
                    debugs(82, DBG_IMPORTANT, "WARNING: external ACL '" << acl->def->name <<
                           "' queue full. Request rejected '" << key << "'.");
                    external_acl_message = "SYSTEM TOO BUSY, TRY AGAIN LATER";
                    return ACCESS_DUNNO;
                } else {
                    debugs(82, DBG_IMPORTANT, "WARNING: external ACL '" << acl->def->name <<
                           "' queue full. Using stale result. '" << key << "'.");
                    entry = staleEntry;
                    /* Fall thru to processing below */
                }
            }
        }
    }

    debugs(82, 4, "entry = { date=" <<
           (long unsigned int) entry->date <<
           ", result=" << entry->result <<
           " tag=" << entry->tag <<
           " log=" << entry->log << " }");
#if USE_AUTH
    debugs(82, 4, "entry user=" << entry->user);
#endif

    external_acl_cache_touch(acl->def, entry);
    external_acl_message = entry->message.termedBuf();

    debugs(82, 2, acl->def->name << " = " << entry->result);
    copyResultsFromEntry(ch->request, entry);
    return entry->result;
}

int
ACLExternal::match(ACLChecklist *checklist)
{
    auto answer = aclMatchExternal(data, Filled(checklist));

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
    if (!def->maybeCacheable(entry->result))
        return;

    dlinkDelete(&entry->lru, &def->lru_list);
    ExternalACLEntry *e = const_cast<ExternalACLEntry *>(entry.getRaw()); // XXX: make hash a std::map of Pointer.
    dlinkAdd(e, &entry->lru, &def->lru_list);
}

char *
ACLExternal::makeExternalAclKey(ACLFilledChecklist * ch, external_acl_data * acl_data) const
{
    static MemBuf mb;
    mb.reset();

    // check for special case tokens in the format
    for (Format::Token *t = acl_data->def->format.format; t ; t = t->next) {

        if (t->type == Format::LFT_EXT_ACL_NAME) {
            // setup for %ACL
            ch->al->lastAclName = acl_data->name;
        }

        if (t->type == Format::LFT_EXT_ACL_DATA) {
            // setup string for %DATA
            SBuf sb;
            for (auto arg = acl_data->arguments; arg; arg = arg->next) {
                if (sb.length())
                    sb.append(" ", 1);

                if (acl_data->def->quote == Format::LOG_QUOTE_URL) {
                    const char *quoted = rfc1738_escape(arg->key);
                    sb.append(quoted, strlen(quoted));
                } else {
                    static MemBuf mb2;
                    mb2.init();
                    strwordquote(&mb2, arg->key);
                    sb.append(mb2.buf, mb2.size);
                    mb2.clean();
                }
            }

            ch->al->lastAclData = sb;
        }
    }

    // assemble the full helper lookup string
    acl_data->def->format.assemble(mb, ch->al, 0);

    return mb.buf;
}

static int
external_acl_entry_expired(external_acl * def, const ExternalACLEntryPointer &entry)
{
    if (def->cache_size <= 0 || entry->result == ACCESS_DUNNO)
        return 1;

    if (entry->date + (entry->result.allowed() ? def->ttl : def->negative_ttl) < squid_curtime)
        return 1;
    else
        return 0;
}

static int
external_acl_grace_expired(external_acl * def, const ExternalACLEntryPointer &entry)
{
    if (def->cache_size <= 0 || entry->result == ACCESS_DUNNO)
        return 1;

    int ttl;
    ttl = entry->result.allowed() ? def->ttl : def->negative_ttl;
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

    if (!def->maybeCacheable(data.result)) {
        debugs(82,6, MYNAME);

        if (data.result == ACCESS_DUNNO) {
            if (const ExternalACLEntryPointer oldentry = static_cast<ExternalACLEntry *>(hash_lookup(def->cache, key)))
                external_acl_cache_delete(def, oldentry);
        }
        entry = new ExternalACLEntry;
        entry->key = xstrdup(key);
        entry->update(data);
        entry->def = def;
        return entry;
    }

    entry = static_cast<ExternalACLEntry *>(hash_lookup(def->cache, key));
    debugs(82, 2, "external_acl_cache_add: Adding '" << key << "' = " << data.result);

    if (entry != nullptr) {
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
    assert(entry != nullptr);
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

class externalAclState
{
    CBDATA_CLASS(externalAclState);

public:
    externalAclState(external_acl* aDef, const char *aKey) :
        callback(nullptr),
        callback_data(nullptr),
        key(xstrdup(aKey)),
        def(cbdataReference(aDef)),
        queue(nullptr)
    {}
    ~externalAclState();

    EAH *callback;
    void *callback_data;
    char *key;
    external_acl *def;
    dlink_node list;
    externalAclState *queue;
};

CBDATA_CLASS_INIT(externalAclState);

externalAclState::~externalAclState()
{
    xfree(key);
    cbdataReferenceDone(callback_data);
    cbdataReferenceDone(def);
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

    debugs(82, 2, "reply=" << reply);

    if (reply.result == Helper::Okay)
        entryData.result = ACCESS_ALLOWED;
    else if (reply.result == Helper::Error)
        entryData.result = ACCESS_DENIED;
    else //BrokenHelper,TimedOut or Unknown. Should not cached.
        entryData.result = ACCESS_DUNNO;

    // XXX: make entryData store a proper Helper::Reply object instead of copying.

    entryData.notes.append(&reply.notes);

    const char *label = reply.notes.findFirst("tag");
    if (label != nullptr && *label != '\0')
        entryData.tag = label;

    label = reply.notes.findFirst("message");
    if (label != nullptr && *label != '\0')
        entryData.message = label;

    label = reply.notes.findFirst("log");
    if (label != nullptr && *label != '\0')
        entryData.log = label;

#if USE_AUTH
    label = reply.notes.findFirst("user");
    if (label != nullptr && *label != '\0')
        entryData.user = label;

    label = reply.notes.findFirst("password");
    if (label != nullptr && *label != '\0')
        entryData.password = label;
#endif

    // XXX: This state->def access conflicts with the cbdata validity check
    // below.
    dlinkDelete(&state->list, &state->def->queue);

    ExternalACLEntryPointer entry;
    if (cbdataReferenceValid(state->def))
        entry = external_acl_cache_add(state->def, state->key, entryData);

    do {
        void *cbdata;
        if (state->callback && cbdataReferenceValidDone(state->callback_data, &cbdata))
            state->callback(cbdata, entry);

        next = state->queue;
        state->queue = nullptr;

        delete state;

        state = next;
    } while (state);
}

/// Asks the helper (if needed) or returns the [cached] result (otherwise).
/// Does not support "background" lookups. See also: ACLExternal::Start().
void
ACLExternal::StartLookup(ACLFilledChecklist &checklist, const Acl::Node &acl)
{
    const auto &me = dynamic_cast<const ACLExternal&>(acl);
    me.startLookup(&checklist, me.data, false);
}

// If possible, starts an asynchronous lookup of an external ACL.
// Otherwise, asserts (or bails if background refresh is requested).
void
ACLExternal::startLookup(ACLFilledChecklist *ch, external_acl_data *acl, bool inBackground) const
{
    external_acl *def = acl->def;

    const char *key = makeExternalAclKey(ch, acl);
    assert(key);

    debugs(82, 2, (inBackground ? "bg" : "fg") << " lookup in '" <<
           def->name << "' for '" << key << "'");

    /* Check for a pending lookup to hook into */
    // only possible if we are caching results.
    externalAclState *oldstate = nullptr;
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
        debugs(82, 7, "'" << def->name << "' queue is already being refreshed (ch=" << ch << ")");
        return;
    }

    externalAclState *state = new externalAclState(def, key);

    if (!inBackground) {
        state->callback = &LookupDone;
        state->callback_data = cbdataReference(ch);
    }

    if (oldstate) {
        /* Hook into pending lookup */
        state->queue = oldstate->queue;
        oldstate->queue = state;
    } else {
        /* No pending lookup found. Sumbit to helper */

        MemBuf buf;
        buf.init();
        buf.appendf("%s\n", key);
        debugs(82, 4, "externalAclLookup: looking up for '" << key << "' in '" << def->name << "'.");

        if (!def->theHelper->trySubmit(buf.buf, externalAclHandleReply, state)) {
            debugs(82, 7, "'" << def->name << "' submit to helper failed");
            assert(inBackground); // or the caller should have checked
            delete state;
            return;
        }

        dlinkAdd(state, &state->list, &def->queue);

        buf.clean();
    }

    debugs(82, 4, "externalAclLookup: will wait for the result of '" << key <<
           "' in '" << def->name << "' (ch=" << ch << ").");
}

static void
externalAclStats(StoreEntry * sentry)
{
    for (external_acl *p = Config.externalAclHelperList; p; p = p->next) {
        storeAppendPrintf(sentry, "External ACL Statistics: %s\n", p->name);
        storeAppendPrintf(sentry, "Cache size: %d\n", p->cache->count);
        assert(p->theHelper);
        p->theHelper->packStatsInto(sentry);
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
    for (external_acl *p = Config.externalAclHelperList; p; p = p->next) {
        if (!p->cache)
            p->cache = hash_create((HASHCMP *) strcmp, hashPrime(1024), hash4);

        if (!p->theHelper)
            p->theHelper = Helper::Client::Make("external_acl_type");

        p->theHelper->cmdline = p->cmdline;

        p->theHelper->childs.updateLimits(p->children);

        p->theHelper->ipc_type = IPC_TCP_SOCKET;

        p->theHelper->addr = p->local_addr;

        p->theHelper->openSessions();
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

/// Called when an async lookup returns
void
ACLExternal::LookupDone(void *data, const ExternalACLEntryPointer &result)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
    checklist->extacl_entry = result;
    checklist->resumeNonBlockingCheck();
}

ACLExternal::ACLExternal(char const *theClass) : data(nullptr), class_(xstrdup(theClass))
{}

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


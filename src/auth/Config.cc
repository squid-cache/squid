/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "format/Format.h"
#include "globals.h"
#include "Store.h"
#include "wordlist.h"

Auth::ConfigVector Auth::TheConfig;

/**
 * Get an User credentials object filled out for the given Proxy- or WWW-Authenticate header.
 * Any decoding which needs to be done will be done.
 *
 * It may be a cached AuthUser or a new Unauthenticated object.
 * It may also be NULL reflecting that no user could be created.
 */
Auth::UserRequest::Pointer
Auth::Config::CreateAuthUser(const char *proxy_auth, AccessLogEntry::Pointer &al)
{
    assert(proxy_auth != NULL);
    debugs(29, 9, HERE << "header = '" << proxy_auth << "'");

    Auth::Config *config = Find(proxy_auth);

    if (config == NULL || !config->active()) {
        debugs(29, (shutting_down?3:DBG_IMPORTANT), (shutting_down?"":"WARNING: ") <<
               "Unsupported or unconfigured/inactive proxy-auth scheme, '" << proxy_auth << "'");
        return NULL;
    }
    static MemBuf rmb;
    rmb.reset();
    if (config->keyExtras) {
        // %credentials and %username, which normally included in
        // request_format, are - at this time, but that is OK
        // because user name is added to key explicitly, and we do
        // not want to store authenticated credentials at all.
        config->keyExtras->assemble(rmb, al, 0);
    }

    return config->decode(proxy_auth, rmb.hasContent() ? rmb.content() : NULL);
}

Auth::Config *
Auth::Config::Find(const char *proxy_auth)
{
    for (Auth::ConfigVector::iterator  i = Auth::TheConfig.begin(); i != Auth::TheConfig.end(); ++i)
        if (strncasecmp(proxy_auth, (*i)->type(), strlen((*i)->type())) == 0)
            return *i;

    return NULL;
}

/** Default behaviour is to expose nothing */
void
Auth::Config::registerWithCacheManager(void)
{}

void
Auth::Config::parse(Auth::Config * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "program") == 0) {
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("Authentication helper program", authenticateProgram->key);

    } else if (strcmp(param_str, "realm") == 0) {
        realm.clear();

        char *token = ConfigParser::NextQuotedOrToEol();

        while (token && *token && xisspace(*token))
            ++token;

        if (!token || !*token) {
            debugs(29, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Missing auth_param " << scheme->type() << " realm");
            self_destruct();
            return;
        }

        realm = token;

    } else if (strcmp(param_str, "children") == 0) {
        authenticateChildren.parseConfig();

    } else if (strcmp(param_str, "key_extras") == 0) {
        keyExtrasLine = ConfigParser::NextQuotedToken();
        Format::Format *nlf =  new ::Format::Format(scheme->type());
        if (!nlf->parse(keyExtrasLine.termedBuf())) {
            debugs(29, DBG_CRITICAL, "FATAL: Failed parsing key_extras formatting value");
            self_destruct();
            return;
        }
        if (keyExtras)
            delete keyExtras;

        keyExtras = nlf;

        if (char *t = strtok(NULL, w_space)) {
            debugs(29, DBG_CRITICAL, "FATAL: Unexpected argument '" << t << "' after request_format specification");
            self_destruct();
        }
    } else {
        debugs(29, DBG_CRITICAL, "Unrecognised " << scheme->type() << " auth scheme parameter '" << param_str << "'");
    }
}

bool
Auth::Config::dump(StoreEntry *entry, const char *name, Auth::Config *scheme) const
{
    if (!authenticateProgram)
        return false; // not configured

    wordlist *list = authenticateProgram;
    storeAppendPrintf(entry, "%s %s", name, scheme->type());
    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }
    storeAppendPrintf(entry, "\n");

    storeAppendPrintf(entry, "%s %s realm " SQUIDSBUFPH "\n", name, scheme->type(), SQUIDSBUFPRINT(realm));

    storeAppendPrintf(entry, "%s %s children %d startup=%d idle=%d concurrency=%d\n",
                      name, scheme->type(),
                      authenticateChildren.n_max, authenticateChildren.n_startup,
                      authenticateChildren.n_idle, authenticateChildren.concurrency);

    if (keyExtrasLine.size() > 0)
        storeAppendPrintf(entry, "%s %s key_extras \"%s\"\n", name, scheme->type(), keyExtrasLine.termedBuf());

    return true;
}

void
Auth::Config::done()
{
    delete keyExtras;
    keyExtras = NULL;
    keyExtrasLine.clean();
}

Auth::User::Pointer
Auth::Config::findUserInCache(const char *nameKey, Auth::Type authType)
{
    AuthUserHashPointer *usernamehash;
    debugs(29, 9, "Looking for user '" << nameKey << "'");

    if (nameKey && (usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, nameKey)))) {
        while (usernamehash) {
            if ((usernamehash->user()->auth_type == authType) &&
                    !strcmp(nameKey, (char const *)usernamehash->key))
                return usernamehash->user();

            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        }
    }

    return NULL;
}


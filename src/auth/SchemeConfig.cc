/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "auth/Config.h"
#include "auth/forward.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "errorpage.h"
#include "format/Format.h"
#include "globals.h"
#include "Store.h"
#include "wordlist.h"

/**
 * Get an User credentials object filled out for the given Proxy- or WWW-Authenticate header.
 * Any decoding which needs to be done will be done.
 *
 * It may be a cached AuthUser or a new Unauthenticated object.
 * It may also be NULL reflecting that no user could be created.
 */
Auth::UserRequest::Pointer
Auth::SchemeConfig::CreateAuthUser(const char *proxy_auth, AccessLogEntry::Pointer &al)
{
    assert(proxy_auth != NULL);
    debugs(29, 9, HERE << "header = '" << proxy_auth << "'");

    Auth::SchemeConfig *config = Find(proxy_auth);

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

    return config->decode(proxy_auth, al->request, rmb.hasContent() ? rmb.content() : nullptr);
}

Auth::SchemeConfig *
Auth::SchemeConfig::Find(const char *proxy_auth)
{
    for (auto *scheme : Auth::TheConfig.schemes) {
        if (strncasecmp(proxy_auth, scheme->type(), strlen(scheme->type())) == 0)
            return scheme;
    }

    return NULL;
}

Auth::SchemeConfig *
Auth::SchemeConfig::GetParsed(const char *proxy_auth)
{
    if (auto *cfg = Find(proxy_auth))
        return cfg;
    fatalf("auth_schemes: required authentication method '%s' is not configured", proxy_auth);
    return nullptr;
}

/** Default behaviour is to expose nothing */
void
Auth::SchemeConfig::registerWithCacheManager(void)
{}

void
Auth::SchemeConfig::parse(Auth::SchemeConfig * scheme, int, char *param_str)
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
    } else if (strcmp(param_str, "keep_alive") == 0) {
        parse_onoff(&keep_alive);
    } else if (strcmp(param_str, "utf8") == 0) {
        parse_onoff(&utf8);
    } else {
        debugs(29, DBG_CRITICAL, "Unrecognised " << scheme->type() << " auth scheme parameter '" << param_str << "'");
    }
}

bool
Auth::SchemeConfig::dump(StoreEntry *entry, const char *name, Auth::SchemeConfig *scheme) const
{
    if (!authenticateProgram)
        return false; // not configured

    const char *schemeType = scheme->type();

    wordlist *list = authenticateProgram;
    storeAppendPrintf(entry, "%s %s", name, schemeType);
    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }
    storeAppendPrintf(entry, "\n");

    storeAppendPrintf(entry, "%s %s realm " SQUIDSBUFPH "\n", name, schemeType, SQUIDSBUFPRINT(realm));

    storeAppendPrintf(entry, "%s %s children %d startup=%d idle=%d concurrency=%d\n",
                      name, schemeType,
                      authenticateChildren.n_max, authenticateChildren.n_startup,
                      authenticateChildren.n_idle, authenticateChildren.concurrency);

    if (keyExtrasLine.size() > 0) // default is none
        storeAppendPrintf(entry, "%s %s key_extras \"%s\"\n", name, schemeType, keyExtrasLine.termedBuf());

    if (!keep_alive) // default is on
        storeAppendPrintf(entry, "%s %s keep_alive off\n", name, schemeType);

    if (utf8) // default is off
        storeAppendPrintf(entry, "%s %s utf8 on\n", name, schemeType);

    return true;
}

void
Auth::SchemeConfig::done()
{
    delete keyExtras;
    keyExtras = NULL;
    keyExtrasLine.clean();
}

bool
Auth::SchemeConfig::isCP1251EncodingAllowed(const HttpRequest *request)
{
    String hdr;

    if (!request || !request->header.getList(Http::HdrType::ACCEPT_LANGUAGE, &hdr))
        return false;

    char lang[256];
    size_t pos = 0; // current parsing position in header string

    while (strHdrAcptLangGetItem(hdr, lang, 256, pos)) {

        /* wildcard uses the configured default language */
        if (lang[0] == '*' && lang[1] == '\0')
            return false;

        if ((strncmp(lang, "ru", 2) == 0 // Russian
                || strncmp(lang, "uk", 2) == 0 // Ukrainian
                || strncmp(lang, "be", 2) == 0 // Belorussian
                || strncmp(lang, "bg", 2) == 0 // Bulgarian
                || strncmp(lang, "sr", 2) == 0)) { // Serbian
            if (lang[2] == '-') {
                if (strcmp(lang + 3, "latn") == 0) // not Cyrillic
                    return false;
            } else if (xisalpha(lang[2])) {
                return false;
            }

            return true;
        }
    }

    return false;
}


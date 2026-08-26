/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 29    Bearer Authentication
 */
#include "squid.h"
#include "auth/bearer/Config.h"
#include "auth/bearer/Scheme.h"
#include "auth/bearer/Token.h"
#include "auth/bearer/User.h"
#include "auth/bearer/UserRequest.h"
#include "base/CharacterSet.h"
#include "cache_cf.h"
#include "helper.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "mgr/Registration.h"
#include "parser/Tokenizer.h"
#include "Store.h"
#include "wordlist.h"

static AUTHSSTATS authenticateBearerStats;
static int authbearer_initialised = 0;
static const auto * BearerDefaultScope = "proxy:HTTP";

Helper::ClientPointer bearerauthenticators;

bool
Auth::Bearer::Config::active() const
{
    return authbearer_initialised == 1;
}

bool
Auth::Bearer::Config::configured() const
{
    if (authenticateProgram && (authenticateChildren.n_max != 0) &&
            !realm.isEmpty() && bearerAuthScope) {
        debugs(29, 8, "yes");
        return true;
    }

    debugs(29, 8, "no");
    return false;
}

const char *
Auth::Bearer::Config::type() const
{
    return Scheme::GetInstance()->type();
}

void
Auth::Bearer::Config::fixHeader(Auth::UserRequest::Pointer, HttpReply *rep, Http::HdrType hdrType, HttpRequest *)
{
    if (authenticateProgram) {
        debugs(29, 2, "Sending type=" << hdrType << ", field-value='Bearer realm=\"" << realm << "\", scope=\"" << bearerAuthScope << "\"'");
        httpHeaderPutStrf(&rep->header, hdrType, "Bearer realm=\"" SQUIDSBUFPH "\", scope=\"%s\"", SQUIDSBUFPRINT(realm), bearerAuthScope);
    }
}

void
Auth::Bearer::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (bearerauthenticators)
        helperShutdown(bearerauthenticators);

    /* dynamic helper restart will ensure they start up again as needed. */
}

/** shutdown the auth helpers and free any allocated configuration details */
void
Auth::Bearer::Config::done()
{
    SchemeConfig::done();

    authbearer_initialised = 0;

    if (bearerauthenticators)
        helperShutdown(bearerauthenticators);

    bearerauthenticators = nullptr;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);

    safe_free(bearerAuthScope);
}

bool
Auth::Bearer::Config::dump(StoreEntry *entry, const char *name, SchemeConfig *scheme) const
{
    if (!SchemeConfig::dump(entry, name, scheme))
        return false; // not configured

    if (bearerAuthScope != BearerDefaultScope)
        entry->appendf("%s bearer scope %s\n", name, bearerAuthScope);

    return true;
}

Auth::Bearer::Config::Config()
{
    static const SBuf defaultRealm("Squid proxy-caching web server");
    realm = defaultRealm;
    bearerAuthScope = BearerDefaultScope;
}

Auth::Bearer::Config::~Config()
{
    if (bearerAuthScope != BearerDefaultScope)
        xfree(bearerAuthScope);
}

void
Auth::Bearer::Config::parse(SchemeConfig *scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "scope") == 0) {
        char *tmpS = nullptr;
        parse_eol(&tmpS);
        if (strcmp(bearerAuthScope, tmpS) != 0) {
            debugs(3, DBG_PARSE_NOTE(2), "NOTICE: Bearer scope already set to: " << tmpS);
            xfree(tmpS);
        } else
            bearerAuthScope = tmpS;

    } else
        SchemeConfig::parse(scheme, n_configured, param_str);
}

static void
authenticateBearerStats(StoreEntry * sentry)
{
    if (bearerauthenticators)
        bearerauthenticators->packStatsInto(sentry, "Bearer Authenticator Statistics");
}

/**
 * Decode a Bearer [Proxy-]Auth string. Looking for an existing
 * Auth::UserRequest structure with matching token, or create a
 * new one if needed.
 *
 * An Auth::UserRequest with a nil user field means
 * "cannot decode credentials".
 */
Auth::UserRequest::Pointer
Auth::Bearer::Config::decode(char const *proxy_auth, const HttpRequest *, const char *aRequestRealm)
{
    Auth::UserRequest::Pointer auth_user_request = new Auth::Bearer::UserRequest;

    SBuf tmp(proxy_auth);
    ::Parser::Tokenizer tok(tmp);

    // trim prefix: OWS "Bearer" RWS
    SBuf label;
    if (tok.token(label, CharacterSet::WSP)) {
        if (label.cmp("Bearer") != 0) // case sensitive
            return auth_user_request;
    } else
        return auth_user_request;

    // RFC 6750
    //   b64token  = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    // aka. RFC 7235 token68
    SBuf blob;
    if (tok.prefix(blob, CharacterSet::TOKEN68C)) {
        while (tok.skip('='))
            blob.append('=');
        (void)tok.skipAll(CharacterSet::WSP);
    } else
        return auth_user_request;

    // garbage after token68
    if (!tok.atEnd())
        return auth_user_request;

    Auth::User::Pointer auth_user;

    // if there is a cached entry for this token use it
    if (const auto *entry = Token::Cache.get(blob)) {
        auth_user = (*entry)->user;
        assert(auth_user);

    } else {
        // generate a User object for this token and cache the token
        std::unique_ptr<Auth::Bearer::User> usr;
        usr.reset(new Bearer::User(this, aRequestRealm, blob));
        usr->auth_type = Auth::AUTH_BEARER;

        auto ttl = usr->token->expires - squid_curtime; // negative if already expired
        Token::Cache.add(blob, usr->token, ttl);
        auth_user = usr.release();
    }

    debugs(29, 3, "found Bearer token " << blob << ", user=" << auth_user->username() << ", " << auth_user);

    auth_user_request->user(auth_user);
    return auth_user_request;
}

/**
 * Initialize helpers and the like for this auth scheme.
 * Called AFTER parsing the config file
 */
void
Auth::Bearer::Config::init(SchemeConfig *)
{
    if (authenticateProgram && !authbearer_initialised) {
        authbearer_initialised = 1;

        if (!bearerauthenticators)
            bearerauthenticators = Helper::Client::Make("bearerauthenticator");

        bearerauthenticators->cmdline = authenticateProgram;
        bearerauthenticators->childs.updateLimits(authenticateChildren);
        bearerauthenticators->ipc_type = IPC_STREAM;
        bearerauthenticators->openSessions();
    }
}

void
Auth::Bearer::Config::registerWithCacheManager()
{
    Mgr::RegisterAction("bearerauthenticator",
                        "Bearer User Authenticator Stats",
                        authenticateBearerStats, 0, 1);
}

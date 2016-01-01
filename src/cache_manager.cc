/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager Objects */

#include "squid.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "Debug.h"
#include "errorpage.h"
#include "fde.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "mgr/Action.h"
#include "mgr/ActionCreator.h"
#include "mgr/ActionPasswordList.h"
#include "mgr/ActionProfile.h"
#include "mgr/BasicActions.h"
#include "mgr/Command.h"
#include "mgr/Forwarder.h"
#include "mgr/FunAction.h"
#include "mgr/QueryParams.h"
#include "protos.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"
#include "wordlist.h"

#include <algorithm>

/// \ingroup CacheManagerInternal
#define MGR_PASSWD_SZ 128

/// creates Action using supplied Action::Create method and command
class ClassActionCreator: public Mgr::ActionCreator
{
public:
    typedef Mgr::Action::Pointer Handler(const Mgr::Command::Pointer &cmd);

public:
    ClassActionCreator(Handler *aHandler): handler(aHandler) {}

    virtual Mgr::Action::Pointer create(const Mgr::Command::Pointer &cmd) const {
        return handler(cmd);
    }

private:
    Handler *handler;
};

/// Registers new profiles, ignoring attempts to register a duplicate
void
CacheManager::registerProfile(const Mgr::ActionProfile::Pointer &profile)
{
    Must(profile != NULL);
    if (!CacheManager::findAction(profile->name)) {
        menu_.push_back(profile);
        debugs(16, 3, HERE << "registered profile: " << *profile);
    } else {
        debugs(16, 2, HERE << "skipped duplicate profile: " << *profile);
    }
}

/**
 \ingroup CacheManagerAPI
 * Registers a C-style action, which is implemented as a pointer to a function
 * taking as argument a pointer to a StoreEntry and returning void.
 * Implemented via CacheManagerActionLegacy.
 */
void
CacheManager::registerProfile(char const * action, char const * desc, OBJH * handler, int pw_req_flag, int atomic)
{
    debugs(16, 3, HERE << "registering legacy " << action);
    const Mgr::ActionProfile::Pointer profile = new Mgr::ActionProfile(action,
            desc, pw_req_flag, atomic, new Mgr::FunActionCreator(handler));
    registerProfile(profile);
}

/**
 * \ingroup CacheManagerAPI
 * Registers a C++-style action, via a pointer to a subclass of
 * a CacheManagerAction object, whose run() method will be invoked when
 * CacheManager identifies that the user has requested the action.
 */
void
CacheManager::registerProfile(char const * action, char const * desc,
                              ClassActionCreator::Handler *handler,
                              int pw_req_flag, int atomic)
{
    const Mgr::ActionProfile::Pointer profile = new Mgr::ActionProfile(action,
            desc, pw_req_flag, atomic, new ClassActionCreator(handler));
    registerProfile(profile);
}

/**
 \ingroup CacheManagerInternal
 * Locates an action in the actions registry ActionsList.
\retval NULL  if Action not found
\retval CacheManagerAction* if the action was found
 */
Mgr::ActionProfile::Pointer
CacheManager::findAction(char const * action) const
{
    Must(action != NULL);
    Menu::const_iterator a;

    debugs(16, 5, "CacheManager::findAction: looking for action " << action);
    for (a = menu_.begin(); a != menu_.end(); ++a) {
        if (0 == strcmp((*a)->name, action)) {
            debugs(16, 6, " found");
            return *a;
        }
    }

    debugs(16, 6, "Action not found.");
    return Mgr::ActionProfilePointer();
}

Mgr::Action::Pointer
CacheManager::createNamedAction(const char *actionName)
{
    Must(actionName);

    Mgr::Command::Pointer cmd = new Mgr::Command;
    cmd->profile = findAction(actionName);
    cmd->params.actionName = actionName;

    Must(cmd->profile != NULL);
    return cmd->profile->creator->create(cmd);
}

Mgr::Action::Pointer
CacheManager::createRequestedAction(const Mgr::ActionParams &params)
{
    Mgr::Command::Pointer cmd = new Mgr::Command;
    cmd->params = params;
    cmd->profile = findAction(params.actionName.termedBuf());
    Must(cmd->profile != NULL);
    return cmd->profile->creator->create(cmd);
}

/**
 \ingroup CacheManagerInternal
 * define whether the URL is a cache-manager URL and parse the action
 * requested by the user. Checks via CacheManager::ActionProtection() that the
 * item is accessible by the user.
 \retval CacheManager::cachemgrStateData state object for the following handling
 \retval NULL if the action can't be found or can't be accessed by the user
 */
Mgr::Command::Pointer
CacheManager::ParseUrl(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    LOCAL_ARRAY(char, params, MAX_URL);
    host[0] = 0;
    request[0] = 0;
    password[0] = 0;
    params[0] = 0;
    int pos = -1;
    int len = strlen(url);
    Must(len > 0);
    t = sscanf(url, "cache_object://%[^/]/%[^@?]%n@%[^?]?%s", host, request, &pos, password, params);
    if (t < 3) {
        t = sscanf(url, "cache_object://%[^/]/%[^?]%n?%s", host, request, &pos, params);
    }
    if (t < 1) {
        t = sscanf(url, "http://%[^/]/squid-internal-mgr/%[^?]%n?%s", host, request, &pos, params);
    }
    if (t < 1) {
        t = sscanf(url, "https://%[^/]/squid-internal-mgr/%[^?]%n?%s", host, request, &pos, params);
    }
    if (t < 2) {
        if (strncmp("cache_object://",url,15)==0)
            xstrncpy(request, "menu", MAX_URL);
        else
            xstrncpy(request, "index", MAX_URL);
    }

#if _SQUID_OS2_
    if (t == 2 && request[0] == '\0') {
        /*
         * emx's sscanf insists of returning 2 because it sets request
         * to null
         */
        if (strncmp("cache_object://",url,15)==0)
            xstrncpy(request, "menu", MAX_URL);
        else
            xstrncpy(request, "index", MAX_URL);
    }
#endif

    debugs(16, 3, HERE << "MGR request: t=" << t << ", host='" << host << "', request='" << request << "', pos=" << pos <<
           ", password='" << password << "', params='" << params << "'");

    Mgr::ActionProfile::Pointer profile = findAction(request);
    if (!profile) {
        debugs(16, DBG_IMPORTANT, "CacheManager::ParseUrl: action '" << request << "' not found");
        return NULL;
    }

    const char *prot = ActionProtection(profile);
    if (!strcmp(prot, "disabled") || !strcmp(prot, "hidden")) {
        debugs(16, DBG_IMPORTANT, "CacheManager::ParseUrl: action '" << request << "' is " << prot);
        return NULL;
    }

    Mgr::Command::Pointer cmd = new Mgr::Command;
    if (!Mgr::QueryParams::Parse(params, cmd->params.queryParams))
        return NULL;
    cmd->profile = profile;
    cmd->params.httpUri = url;
    cmd->params.userName = String();
    cmd->params.password = password;
    cmd->params.actionName = request;
    return cmd;
}

/// \ingroup CacheManagerInternal
/*
 \ingroup CacheManagerInternal
 * Decodes the headers needed to perform user authentication and fills
 * the details into the cachemgrStateData argument
 */
void
CacheManager::ParseHeaders(const HttpRequest * request, Mgr::ActionParams &params)
{
    assert(request);

    params.httpMethod = request->method.id();
    params.httpFlags = request->flags;

#if HAVE_AUTH_MODULE_BASIC
    // TODO: use the authentication system decode to retrieve these details properly.

    /* base 64 _decoded_ user:passwd pair */
    const char *basic_cookie = request->header.getAuth(HDR_AUTHORIZATION, "Basic");

    if (!basic_cookie)
        return;

    const char *passwd_del;
    if (!(passwd_del = strchr(basic_cookie, ':'))) {
        debugs(16, DBG_IMPORTANT, "CacheManager::ParseHeaders: unknown basic_cookie format '" << basic_cookie << "'");
        return;
    }

    /* found user:password pair, reset old values */
    params.userName.limitInit(basic_cookie, passwd_del - basic_cookie);
    params.password = passwd_del + 1;

    /* warning: this prints decoded password which maybe not be what you want to do @?@ @?@ */
    debugs(16, 9, "CacheManager::ParseHeaders: got user: '" <<
           params.userName << "' passwd: '" << params.password << "'");
#endif
}

/**
 \ingroup CacheManagerInternal
 *
 \retval 0  if mgr->password is good or "none"
 \retval 1  if mgr->password is "disable"
 \retval !0 if mgr->password does not match configured password
 */
int
CacheManager::CheckPassword(const Mgr::Command &cmd)
{
    assert(cmd.profile != NULL);
    const char *action = cmd.profile->name;
    char *pwd = PasswdGet(Config.passwd_list, action);

    debugs(16, 4, "CacheManager::CheckPassword for action " << action);

    if (pwd == NULL)
        return cmd.profile->isPwReq;

    if (strcmp(pwd, "disable") == 0)
        return 1;

    if (strcmp(pwd, "none") == 0)
        return 0;

    if (!cmd.params.password.size())
        return 1;

    return cmd.params.password != pwd;
}

/**
 \ingroup CacheManagerAPI
 * Main entry point in the Cache Manager's activity. Gets called as part
 * of the forward chain if the right URL is detected there. Initiates
 * all needed internal work and renders the response.
 */
void
CacheManager::Start(const Comm::ConnectionPointer &client, HttpRequest * request, StoreEntry * entry)
{
    debugs(16, 3, "CacheManager::Start: '" << entry->url() << "'" );

    Mgr::Command::Pointer cmd = ParseUrl(entry->url());
    if (!cmd) {
        ErrorState *err = new ErrorState(ERR_INVALID_URL, Http::scNotFound, request);
        err->url = xstrdup(entry->url());
        errorAppendEntry(entry, err);
        entry->expires = squid_curtime;
        return;
    }

    const char *actionName = cmd->profile->name;

    entry->expires = squid_curtime;

    debugs(16, 5, "CacheManager: " << client << " requesting '" << actionName << "'");

    /* get additional info from request headers */
    ParseHeaders(request, cmd->params);

    const char *userName = cmd->params.userName.size() ?
                           cmd->params.userName.termedBuf() : "unknown";

    /* Check password */

    if (CheckPassword(*cmd) != 0) {
        /* build error message */
        ErrorState errState(ERR_CACHE_MGR_ACCESS_DENIED, Http::scUnauthorized, request);
        /* warn if user specified incorrect password */

        if (cmd->params.password.size()) {
            debugs(16, DBG_IMPORTANT, "CacheManager: " <<
                   userName << "@" <<
                   client << ": incorrect password for '" <<
                   actionName << "'" );
        } else {
            debugs(16, DBG_IMPORTANT, "CacheManager: " <<
                   userName << "@" <<
                   client << ": password needed for '" <<
                   actionName << "'" );
        }

        HttpReply *rep = errState.BuildHttpReply();

#if HAVE_AUTH_MODULE_BASIC
        /*
         * add Authenticate header using action name as a realm because
         * password depends on the action
         */
        rep->header.putAuth("Basic", actionName);
#endif
        // Allow cachemgr and other XHR scripts access to our version string
        if (request->header.has(HDR_ORIGIN)) {
            rep->header.putExt("Access-Control-Allow-Origin",request->header.getStr(HDR_ORIGIN));
#if HAVE_AUTH_MODULE_BASIC
            rep->header.putExt("Access-Control-Allow-Credentials","true");
#endif
            rep->header.putExt("Access-Control-Expose-Headers","Server");
        }

        /* store the reply */
        entry->replaceHttpReply(rep);

        entry->expires = squid_curtime;

        entry->complete();

        return;
    }

    if (request->header.has(HDR_ORIGIN)) {
        cmd->params.httpOrigin = request->header.getStr(HDR_ORIGIN);
    }

    debugs(16, 2, "CacheManager: " <<
           userName << "@" <<
           client << " requesting '" <<
           actionName << "'" );

    // special case: /squid-internal-mgr/ index page
    if (!strcmp(cmd->profile->name, "index")) {
        ErrorState err(MGR_INDEX, Http::scOkay, request);
        err.url = xstrdup(entry->url());
        HttpReply *rep = err.BuildHttpReply();
        if (strncmp(rep->body.content(),"Internal Error:", 15) == 0)
            rep->sline.set(Http::ProtocolVersion(1,1), Http::scNotFound);
        // Allow cachemgr and other XHR scripts access to our version string
        if (request->header.has(HDR_ORIGIN)) {
            rep->header.putExt("Access-Control-Allow-Origin",request->header.getStr(HDR_ORIGIN));
#if HAVE_AUTH_MODULE_BASIC
            rep->header.putExt("Access-Control-Allow-Credentials","true");
#endif
            rep->header.putExt("Access-Control-Expose-Headers","Server");
        }
        entry->replaceHttpReply(rep);
        entry->complete();
        return;
    }

    if (UsingSmp() && IamWorkerProcess()) {
        // is client the right connection to pass here?
        AsyncJob::Start(new Mgr::Forwarder(client, cmd->params, request, entry));
        return;
    }

    Mgr::Action::Pointer action = cmd->profile->creator->create(cmd);
    Must(action != NULL);
    action->run(entry, true);
}

/*
 \ingroup CacheManagerInternal
 * Renders the protection level text for an action.
 * Also doubles as a check for the protection level.
 */
const char *
CacheManager::ActionProtection(const Mgr::ActionProfile::Pointer &profile)
{
    assert(profile != NULL);
    const char *pwd = PasswdGet(Config.passwd_list, profile->name);

    if (!pwd)
        return profile->isPwReq ? "hidden" : "public";

    if (!strcmp(pwd, "disable"))
        return "disabled";

    if (strcmp(pwd, "none") == 0)
        return "public";

    return "protected";
}

/*
 * \ingroup CacheManagerInternal
 * gets from the global Config the password the user would need to supply
 * for the action she queried
 */
char *
CacheManager::PasswdGet(Mgr::ActionPasswordList * a, const char *action)
{
    wordlist *w;

    while (a != NULL) {
        for (w = a->actions; w != NULL; w = w->next) {
            if (0 == strcmp(w->key, action))
                return a->passwd;

            if (0 == strcmp(w->key, "all"))
                return a->passwd;
        }

        a = a->next;
    }

    return NULL;
}

CacheManager* CacheManager::instance=0;

/**
 \ingroup CacheManagerAPI
 * Singleton accessor method.
 */
CacheManager*
CacheManager::GetInstance()
{
    if (instance == 0) {
        debugs(16, 6, "CacheManager::GetInstance: starting cachemanager up");
        instance = new CacheManager;
        Mgr::RegisterBasics();
    }
    return instance;
}


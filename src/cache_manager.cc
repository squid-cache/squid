/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager Objects */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "debug/Stream.h"
#include "error/ExceptionErrorDetail.h"
#include "errorpage.h"
#include "fde.h"
#include "HttpHdrCc.h"
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
#include "parser/Tokenizer.h"
#include "protos.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "Store.h"
#include "tools.h"
#include "wordlist.h"

#include <algorithm>
#include <memory>

/// \ingroup CacheManagerInternal
#define MGR_PASSWD_SZ 128

/// creates Action using supplied Action::Create method and command
class ClassActionCreator: public Mgr::ActionCreator
{
public:
    typedef Mgr::Action::Pointer Handler(const Mgr::Command::Pointer &cmd);

public:
    ClassActionCreator(Handler *aHandler): handler(aHandler) {}

    Mgr::Action::Pointer create(const Mgr::Command::Pointer &cmd) const override {
        return handler(cmd);
    }

private:
    Handler *handler;
};

/// Registers new profiles, ignoring attempts to register a duplicate
void
CacheManager::registerProfile(const Mgr::ActionProfile::Pointer &profile)
{
    Must(profile != nullptr);
    if (!CacheManager::findAction(profile->name)) {
        menu_.push_back(profile);
        debugs(16, 3, "registered profile: " << *profile);
    } else {
        debugs(16, 2, "skipped duplicate profile: " << *profile);
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
    debugs(16, 3, "registering legacy " << action);
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
    Must(action != nullptr);
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

    Must(cmd->profile != nullptr);
    return cmd->profile->creator->create(cmd);
}

Mgr::Action::Pointer
CacheManager::createRequestedAction(const Mgr::ActionParams &params)
{
    Mgr::Command::Pointer cmd = new Mgr::Command;
    cmd->params = params;
    cmd->profile = findAction(params.actionName.termedBuf());
    Must(cmd->profile != nullptr);
    return cmd->profile->creator->create(cmd);
}

static const CharacterSet &
MgrFieldChars(const AnyP::ProtocolType &protocol)
{
    // Deprecated cache_object:// scheme used '@' to delimit passwords
    if (protocol == AnyP::PROTO_CACHE_OBJECT) {
        static const CharacterSet fieldChars = CharacterSet("cache-object-field", "@?#").complement();
        return fieldChars;
    }

    static const CharacterSet actionChars = CharacterSet("mgr-field", "?#").complement();
    return actionChars;
}

const SBuf &
CacheManager::WellKnownUrlPathPrefix()
{
    static const SBuf prefix("/squid-internal-mgr/");
    return prefix;
}

/**
 * define whether the URL is a cache-manager URL and parse the action
 * requested by the user. Checks via CacheManager::ActionProtection() that the
 * item is accessible by the user.
 *
 * Syntax:
 *
 *  scheme "://" authority [ '/squid-internal-mgr' ] path-absolute [ '@' unreserved ] '?' query-string
 *
 * see RFC 3986 for definitions of scheme, authority, path-absolute, query-string
 *
 * \returns Mgr::Command object with action to perform and parameters it might use
 */
Mgr::Command::Pointer
CacheManager::ParseUrl(const AnyP::Uri &uri)
{
    Parser::Tokenizer tok(uri.path());

    Assure(tok.skip(WellKnownUrlPathPrefix()));

    Mgr::Command::Pointer cmd = new Mgr::Command();
    cmd->params.httpUri = SBufToString(uri.absolute());

    const auto &fieldChars = MgrFieldChars(uri.getScheme());

    SBuf action;
    if (!tok.prefix(action, fieldChars)) {
        if (uri.getScheme() == AnyP::PROTO_CACHE_OBJECT) {
            static const SBuf menuReport("menu");
            action = menuReport;
        } else {
            static const SBuf indexReport("index");
            action = indexReport;
        }
    }
    cmd->params.actionName = SBufToString(action);

    const auto profile = findAction(action.c_str());
    if (!profile)
        throw TextException(ToSBuf("action '", action, "' not found"), Here());

    const char *prot = ActionProtection(profile);
    if (!strcmp(prot, "disabled") || !strcmp(prot, "hidden"))
        throw TextException(ToSBuf("action '", action, "' is ", prot), Here());
    cmd->profile = profile;

    SBuf passwd;
    if (uri.getScheme() == AnyP::PROTO_CACHE_OBJECT && tok.skip('@')) {
        (void)tok.prefix(passwd, fieldChars);
        cmd->params.password = SBufToString(passwd);
    }

    // TODO: fix when AnyP::Uri::parse() separates path?query#fragment
    SBuf params;
    if (tok.skip('?')) {
        params = tok.remaining();
        Mgr::QueryParams::Parse(tok, cmd->params.queryParams);
    }

    if (!tok.skip('#') && !tok.atEnd())
        throw TextException("invalid characters in URL", Here());
    // else ignore #fragment (if any)

    debugs(16, 3, "MGR request: host=" << uri.host() << ", action=" << action <<
           ", password=" << passwd << ", params=" << params);

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
    const auto basic_cookie(request->header.getAuthToken(Http::HdrType::AUTHORIZATION, "Basic"));

    if (basic_cookie.isEmpty())
        return;

    const auto colonPos = basic_cookie.find(':');
    if (colonPos == SBuf::npos) {
        debugs(16, DBG_IMPORTANT, "ERROR: CacheManager::ParseHeaders: unknown basic_cookie format '" << basic_cookie << "'");
        return;
    }

    /* found user:password pair, reset old values */
    params.userName = SBufToString(basic_cookie.substr(0, colonPos));
    params.password = SBufToString(basic_cookie.substr(colonPos+1));

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
    assert(cmd.profile != nullptr);
    const char *action = cmd.profile->name;
    char *pwd = PasswdGet(Config.passwd_list, action);

    debugs(16, 4, "CacheManager::CheckPassword for action " << action);

    if (pwd == nullptr)
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
CacheManager::start(const Comm::ConnectionPointer &client, HttpRequest *request, StoreEntry *entry, const AccessLogEntry::Pointer &ale)
{
    debugs(16, 3, "request-url= '" << request->url << "', entry-url='" << entry->url() << "'");

    Mgr::Command::Pointer cmd;
    try {
        cmd = ParseUrl(request->url);

    } catch (...) {
        debugs(16, 2, "request URL error: " << CurrentException);
        const auto err = new ErrorState(ERR_INVALID_URL, Http::scNotFound, request, ale);
        err->url = xstrdup(entry->url());
        err->detailError(new ExceptionErrorDetail(Here().id()));
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
        ErrorState errState(ERR_CACHE_MGR_ACCESS_DENIED, Http::scUnauthorized, request, ale);
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

        const auto originOrNil = request->header.getStr(Http::HdrType::ORIGIN);
        PutCommonResponseHeaders(*rep, originOrNil);

        /* store the reply */
        entry->replaceHttpReply(rep);

        entry->expires = squid_curtime;

        entry->complete();

        return;
    }

    if (request->header.has(Http::HdrType::ORIGIN)) {
        cmd->params.httpOrigin = request->header.getStr(Http::HdrType::ORIGIN);
    }

    debugs(16, 2, "CacheManager: " <<
           userName << "@" <<
           client << " requesting '" <<
           actionName << "'" );

    // special case: an index page
    if (!strcmp(cmd->profile->name, "index")) {
        ErrorState err(MGR_INDEX, Http::scOkay, request, ale);
        err.url = xstrdup(entry->url());
        HttpReply *rep = err.BuildHttpReply();
        if (strncmp(rep->body.content(),"Internal Error:", 15) == 0)
            rep->sline.set(Http::ProtocolVersion(1,1), Http::scNotFound);

        const auto originOrNil = request->header.getStr(Http::HdrType::ORIGIN);
        PutCommonResponseHeaders(*rep, originOrNil);

        entry->replaceHttpReply(rep);
        entry->complete();
        return;
    }

    if (UsingSmp() && IamWorkerProcess()) {
        // is client the right connection to pass here?
        AsyncJob::Start(new Mgr::Forwarder(client, cmd->params, request, entry, ale));
        return;
    }

    Mgr::Action::Pointer action = cmd->profile->creator->create(cmd);
    Must(action != nullptr);
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
    assert(profile != nullptr);
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
    while (a) {
        for (auto &w : a->actions) {
            if (w.cmp(action) == 0)
                return a->passwd;

            static const SBuf allAction("all");
            if (w == allAction)
                return a->passwd;
        }

        a = a->next;
    }

    return nullptr;
}

void
CacheManager::PutCommonResponseHeaders(HttpReply &response, const char *httpOrigin)
{
    // Allow cachemgr and other XHR scripts access to our version string
    if (httpOrigin) {
        response.header.putExt("Access-Control-Allow-Origin", httpOrigin);
#if HAVE_AUTH_MODULE_BASIC
        response.header.putExt("Access-Control-Allow-Credentials", "true");
#endif
        response.header.putExt("Access-Control-Expose-Headers", "Server");
    }

    std::unique_ptr<HttpHdrCc> cc(new HttpHdrCc());
    // this is honored by more caches but allows pointless revalidation;
    // revalidation will always fail because we do not support it (yet?)
    cc->noCache(String());
    // this is honored by fewer caches but prohibits pointless revalidation
    cc->noStore(true);
    response.putCc(cc.release());
}

CacheManager*
CacheManager::GetInstance()
{
    static CacheManager *instance = nullptr;
    if (!instance) {
        debugs(16, 6, "starting cachemanager up");
        instance = new CacheManager;
        Mgr::RegisterBasics();
    }
    return instance;
}


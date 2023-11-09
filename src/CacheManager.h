/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEMANAGER_H
#define SQUID_CACHEMANAGER_H

#include "anyp/forward.h"
#include "comm/forward.h"
#include "log/forward.h"
#include "mgr/Action.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"
#include "mgr/forward.h"

#include <vector>

class HttpRequest;
class HttpReply;

/**
 * a CacheManager - the menu system for interacting with squid.
 * This is currently just an adapter to the global cachemgr* routines to
 * provide looser coupling between modules, but once fully transitioned,
 * an instance of this class will represent a single independent manager.
 * TODO: update documentation to reflect the new singleton model.
 */
class CacheManager
{
public:
    typedef std::vector<Mgr::ActionProfilePointer> Menu;

    /// initial URL path characters that identify cache manager requests
    static const SBuf &WellKnownUrlPathPrefix();

    void registerProfile(char const * action, char const * desc,
                         OBJH * handler,
                         int pw_req_flag, int atomic);
    void registerProfile(char const * action, char const * desc,
                         Mgr::ClassActionCreationHandler *handler,
                         int pw_req_flag, int atomic);
    Mgr::ActionProfilePointer findAction(char const * action) const;
    Mgr::Action::Pointer createNamedAction(const char *actionName);
    Mgr::Action::Pointer createRequestedAction(const Mgr::ActionParams &);
    const Menu& menu() const { return menu_; }

    void start(const Comm::ConnectionPointer &client, HttpRequest *request, StoreEntry *entry, const AccessLogEntryPointer &ale);

    static CacheManager* GetInstance();
    const char *ActionProtection(const Mgr::ActionProfilePointer &profile);

    /// Add HTTP response headers specific/common to all cache manager replies,
    /// including cache manager errors and Action reports.
    /// \param httpOrigin the value of Origin header in the trigger HTTP request (or nil)
    static void PutCommonResponseHeaders(HttpReply &, const char *httpOrigin);

protected:
    CacheManager() {} ///< use Instance() instead

    Mgr::CommandPointer ParseUrl(const AnyP::Uri &);
    void ParseHeaders(const HttpRequest * request, Mgr::ActionParams &params);
    int CheckPassword(const Mgr::Command &cmd);
    char *PasswdGet(Mgr::ActionPasswordList *, const char *);

    void registerProfile(const Mgr::ActionProfilePointer &profile);

    Menu menu_;
};

#endif /* SQUID_CACHEMANAGER_H */


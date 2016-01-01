/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEMANAGER_H
#define SQUID_CACHEMANAGER_H

#include "comm/forward.h"
#include "mgr/Action.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"
#include "mgr/forward.h"
#include "typedefs.h"

#include <vector>

/**
 \defgroup CacheManagerAPI Cache Manager API
 \ingroup Components
 *
 \defgroup CacheManagerInternal Cache Manager intenal API (not for public use)
 \ingroup CacheManagerAPI
 */

class HttpRequest;
namespace Mgr
{
class ActionPasswordList;
} //namespace Mgr
/**
 \ingroup CacheManagerAPI
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

    void Start(const Comm::ConnectionPointer &client, HttpRequest * request, StoreEntry * entry);

    static CacheManager* GetInstance();
    const char *ActionProtection(const Mgr::ActionProfilePointer &profile);

protected:
    CacheManager() {} ///< use Instance() instead

    Mgr::CommandPointer ParseUrl(const char *url);
    void ParseHeaders(const HttpRequest * request, Mgr::ActionParams &params);
    int CheckPassword(const Mgr::Command &cmd);
    char *PasswdGet(Mgr::ActionPasswordList *, const char *);

    void registerProfile(const Mgr::ActionProfilePointer &profile);

    Menu menu_;

private:
    static CacheManager* instance;
};

#endif /* SQUID_CACHEMANAGER_H */


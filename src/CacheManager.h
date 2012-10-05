
/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
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

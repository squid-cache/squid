/*
 * AUTHOR: Francesco Chemolli
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

#include "squid.h"
#include "CacheManager.h"
#include "mgr/Registration.h"

Mgr::Action::Pointer
CacheManager::createNamedAction(char const* action)
{
    fatal ("Not implemented");
    return NULL;
}

void
CacheManager::Start(int fd, HttpRequest * request, StoreEntry * entry)
{
    return;
}

CacheManager*
CacheManager::GetInstance(void)
{
    static CacheManager *instance = 0;
    if (!instance)
        instance = new CacheManager();
    return instance;
}

void
Mgr::RegisterAction(char const*, char const*, OBJH, int, int)
{
}

void
Mgr::RegisterAction(char const * action, char const * desc,
                    Mgr::ClassActionCreationHandler *handler,
                    int pw_req_flag, int atomic)
{
}

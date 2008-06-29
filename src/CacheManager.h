
/*
 * $Id: CacheManager.h,v 1.2 2008/02/26 21:49:34 amosjeffries Exp $
 *
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

#include "squid.h"

/**
 \defgroup CacheManagerAPI Cache Manager API
 \ingroup Components
 */

/// \ingroup CacheManagerAPI
extern void cachemgrStart(int fd, HttpRequest * request, StoreEntry * entry);

/**
 \ingroup CacheManagerAPI
 * A single menu item in the cache manager - an 'action'.
 */
class CacheManagerAction
{

public:
    char *action;
    char *desc;
    OBJH *handler;

    struct
    {
        unsigned int pw_req:1;
        unsigned int atomic:1;
    } flags;

    CacheManagerAction *next;
};


/// \ingroup CacheManagerInternal
typedef struct
{
    StoreEntry *entry;
    char *action;
    char *user_name;
    char *passwd;
} cachemgrStateData;

/**
 \ingroup CacheManagerAPI
 * a CacheManager - the menu system for interacting with squid.
 * This is currently just an adapter to the global cachemgr* routines to
 * provide looser coupling between modules, but once fully transitioned,
 * an instance of this class will represent a single independent manager.
 */
class CacheManager
{

public:
    /* the holy trinity - assignment, copy cons, destructor */
    /* unimplemented - prevents bugs from synthetic */
    CacheManager & operator = (CacheManager &);
    /* unimplemented - prevents bugs from synthetic */
    CacheManager(CacheManager const &);
    /* inline so that we dont need to link in cachemgr.cc at all in tests */
    virtual ~CacheManager() {}

    virtual void registerAction(char const * action, char const * desc, OBJH * handler, int pw_req_flag, int atomic);
    virtual CacheManagerAction * findAction(char const * action);

    virtual void Start(int fd, HttpRequest * request, StoreEntry * entry);

    static CacheManager* GetInstance();

protected:
    CacheManager(); 
    virtual cachemgrStateData* ParseUrl(const char *url);
    virtual void ParseHeaders(cachemgrStateData * mgr, const HttpRequest * request);

private:
    static CacheManager* instance;


};

#endif /* SQUID_CACHEMANAGER_H */


/*
 * $Id: authenticate.h,v 1.14 2004/08/30 03:28:58 robertc Exp $
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

#ifndef SQUID_AUTHENTICATE_H
#define SQUID_AUTHENTICATE_H

#include "client_side.h"

class AuthUser;

struct AuthUserHashPointer : public hash_link
{
    /* first two items must be same as hash_link */

public:
    static void removeFromCache (void *anAuthUserHashPointer);

    AuthUserHashPointer (AuthUser *);

    void *operator new (size_t byteCount);
    void operator delete (void *address);
    AuthUser *user() const;

private:
    static MemPool *pool;

    AuthUser *auth_user;
};

class ConnStateData;

class AuthScheme;

/* authenticate.c authenticate scheme routines typedefs */
/* TODO: this should be a generic cachemgr API type ? */
typedef void AUTHSSTATS(StoreEntry *);

/* subsumed by the C++ interface */
extern void authenticateAuthUserMerge(auth_user_t *, auth_user_t *);

extern void authenticateInit(authConfig *);
extern void authenticateShutdown(void);
extern int authenticateAuthUserInuse(auth_user_t * auth_user);

extern void authenticateFreeProxyAuthUserACLResults(void *data);
extern int authenticateActiveSchemeCount(void);
extern int authenticateSchemeCount(void);

extern void authenticateUserCacheRestart(void);
extern void authenticateOnCloseConnection(ConnStateData * conn);

#endif /* SQUID_AUTHENTICATE_H */


/*
 * $Id: AuthUser.cc,v 1.2 2006/08/07 02:28:22 robertc Exp $
 *
 * DEBUG: section 29    Authenticator
 * AUTHOR:  Robert Collins
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "AuthUser.h"
#include "AuthUserRequest.h"
#include "AuthConfig.h"
#include "authenticate.h"
#include "ACL.h"
#include "event.h"

#ifndef _USE_INLINE_
#include "AuthUser.cci"
#endif

AuthUser::AuthUser (AuthConfig *aConfig) :
        auth_type (AUTH_UNKNOWN), config(aConfig),
        usernamehash (NULL), ipcount (0), expiretime (0), references (0), username_(NULL)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
    proxy_match_cache.head = proxy_match_cache.tail = NULL;
    ip_list.head = ip_list.tail = NULL;
    requests.head = requests.tail = NULL;
    debug(29, 5) ("AuthUser::AuthUser: Initialised auth_user '%p' with refcount '%ld'.\n", this, (long int) references);
}

/* Combine two user structs. ONLY to be called from within a scheme
 * module. The scheme module is responsible for ensuring that the
 * two users _can_ be merged without invalidating all the request
 * scheme data. The scheme is also responsible for merging any user
 * related scheme data itself.
 */
void
AuthUser::absorb (AuthUser *from)
{
    auth_user_request_t *auth_user_request;
    /*
     * XXX combine two authuser structs. Incomplete: it should merge
     * in hash references too and ask the module to merge in scheme
     * data
     */
    debug(29, 5) ("authenticateAuthUserMerge auth_user '%p' into auth_user '%p'.\n", from, this);
    dlink_node *link = from->requests.head;

    while (link) {
        auth_user_request = static_cast<auth_user_request_t *>(link->data);
        dlink_node *tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, &from->requests);
        dlinkAddTail(auth_user_request, tmplink, &requests);
        auth_user_request->user(this);
    }

    references += from->references;
    from->references = 0;
    delete from;
}

AuthUser::~AuthUser()
{
    auth_user_request_t *auth_user_request;
    dlink_node *link, *tmplink;
    debug(29, 5) ("AuthUser::~AuthUser: Freeing auth_user '%p' with refcount '%ld'.\n", this, (long int) references);
    assert(references == 0);
    /* were they linked in by username ? */

    if (usernamehash) {
        assert(usernamehash->user() == this);
        debug(29, 5) ("AuthUser::~AuthUser: removing usernamehash entry '%p'\n", usernamehash);
        hash_remove_link(proxy_auth_username_cache,
                         (hash_link *) usernamehash);
        /* don't free the key as we use the same user string as the auth_user
         * structure */
        delete usernamehash;
    }

    /* remove any outstanding requests */
    link = requests.head;

    while (link) {
        debug(29, 5) ("AuthUser::~AuthUser: removing request entry '%p'\n", link->data);
        auth_user_request = static_cast<auth_user_request_t *>(link->data);
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, &requests);
        dlinkNodeDelete(tmplink);
        delete auth_user_request;
    }

    /* free cached acl results */
    aclCacheMatchFlush(&proxy_match_cache);

    /* free seen ip address's */
    clearIp();

    if (username())
        xfree((char *)username());

    /* prevent accidental reuse */
    auth_type = AUTH_UNKNOWN;
}

void
AuthUser::cacheInit(void)
{
    if (!proxy_auth_username_cache) {
        /* First time around, 7921 should be big enough */
        proxy_auth_username_cache =
            hash_create((HASHCMP *) strcmp, 7921, hash_string);
        assert(proxy_auth_username_cache);
        eventAdd("User Cache Maintenance", cacheCleanup, NULL, Config.authenticateGCInterval, 1);
    }
}

void
AuthUser::CachedACLsReset()
{
    /*
     * We walk the hash by username as that is the unique key we use.
     * This must complete all at once, because we are ensuring correctness.
     */
    AuthUserHashPointer *usernamehash;
    auth_user_t *auth_user;
    char const *username = NULL;
    debug(29, 3) ("AuthUser::CachedACLsReset: Flushing the ACL caches for all users.\n");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        username = auth_user->username();
        /* free cached acl results */
        aclCacheMatchFlush(&auth_user->proxy_match_cache);

    }

    debug(29, 3) ("AuthUser::CachedACLsReset: Finished.\n");
}

void
AuthUser::cacheCleanup(void *datanotused)
{
    /*
     * We walk the hash by username as that is the unique key we use.
     * For big hashs we could consider stepping through the cache, 100/200
     * entries at a time. Lets see how it flys first.
     */
    AuthUserHashPointer *usernamehash;
    auth_user_t *auth_user;
    char const *username = NULL;
    debug(29, 3) ("AuthUser::cacheCleanup: Cleaning the user cache now\n");
    debug(29, 3) ("AuthUser::cacheCleanup: Current time: %ld\n", (long int) current_time.tv_sec);
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        username = auth_user->username();

        /* if we need to have inpedendent expiry clauses, insert a module call
         * here */
        debug(29, 4) ("AuthUser::cacheCleanup: Cache entry:\n\tType: %d\n\tUsername: %s\n\texpires: %ld\n\treferences: %ld\n", auth_user->auth_type, username, (long int) (auth_user->expiretime + Config.authenticateTTL), (long int) auth_user->references);

        if (auth_user->expiretime + Config.authenticateTTL <= current_time.tv_sec) {
            debug(29, 5) ("AuthUser::cacheCleanup: Removing user %s from cache due to timeout.\n", username);
            /* the minus 1 accounts for the cache lock */

            if (!(authenticateAuthUserInuse(auth_user) - 1))
                /* we don't warn if we leave the user in the cache,
                 * because other modules (ie delay pools) may keep
                 * locks on users, and thats legitimate
                 */
                auth_user->unlock();
        }
    }

    debug(29, 3) ("AuthUser::cacheCleanup: Finished cleaning the user cache.\n");
    eventAdd("User Cache Maintenance", cacheCleanup, NULL, Config.authenticateGCInterval, 1);
}

void
AuthUser::clearIp()
{
    auth_user_ip_t *ipdata, *tempnode;

    ipdata = (auth_user_ip_t *) ip_list.head;

    while (ipdata) {
        tempnode = (auth_user_ip_t *) ipdata->node.next;
        /* walk the ip list */
        dlinkDelete(&ipdata->node, &ip_list);
        cbdataFree(ipdata);
        /* catch incipient underflow */
        assert(ipcount);
        ipcount--;
        ipdata = tempnode;
    }

    /* integrity check */
    assert(ipcount == 0);
}

void

AuthUser::lock()
{
    debug(29, 9) ("authenticateAuthUserLock auth_user '%p'.\n", this);
    assert(this != NULL);
    references++;
    debug(29, 9) ("authenticateAuthUserLock auth_user '%p' now at '%ld'.\n", this, (long int) references);
}

void
AuthUser::unlock()
{
    debug(29, 9) ("authenticateAuthUserUnlock auth_user '%p'.\n", this);
    assert(this != NULL);

    if (references > 0) {
        references--;
    } else {
        debug(29, 1) ("Attempt to lower Auth User %p refcount below 0!\n", this);
    }

    debug(29, 9) ("authenticateAuthUserUnlock auth_user '%p' now at '%ld'.\n", this, (long int) references);

    if (references == 0)
        delete this;
}

/* addToNameCache: add a auth_user structure to the username cache */
void
AuthUser::addToNameCache()
{
    usernamehash = new AuthUserHashPointer (this);
}

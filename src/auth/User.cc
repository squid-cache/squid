/*
 * $Id$
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
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "event.h"
#include "SquidTime.h"

#ifndef _USE_INLINE_
#include "auth/User.cci"
#endif

// This should be converted into a pooled type. Does not need to be cbdata
CBDATA_TYPE(auth_user_ip_t);

AuthUser::AuthUser (AuthConfig *aConfig) :
        auth_type (AUTH_UNKNOWN), config(aConfig),
        usernamehash (NULL), ipcount (0), expiretime (0), references (0), username_(NULL)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
    proxy_match_cache.head = proxy_match_cache.tail = NULL;
    ip_list.head = ip_list.tail = NULL;
    requests.head = requests.tail = NULL;
    debugs(29, 5, "AuthUser::AuthUser: Initialised auth_user '" << this << "' with refcount '" << references << "'.");
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
    AuthUserRequest *auth_user_request;
    /*
     * XXX combine two authuser structs. Incomplete: it should merge
     * in hash references too and ask the module to merge in scheme
     * data
     */
    debugs(29, 5, "authenticateAuthUserMerge auth_user '" << from << "' into auth_user '" << this << "'.");
    dlink_node *link = from->requests.head;

    while (link) {
        auth_user_request = static_cast<AuthUserRequest *>(link->data);
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
    AuthUserRequest *auth_user_request;
    dlink_node *link, *tmplink;
    debugs(29, 5, "AuthUser::~AuthUser: Freeing auth_user '" << this << "' with refcount '" << references << "'.");
    assert(references == 0);
    /* were they linked in by username ? */

    if (usernamehash) {
        assert(usernamehash->user() == this);
        debugs(29, 5, "AuthUser::~AuthUser: removing usernamehash entry '" << usernamehash << "'");
        hash_remove_link(proxy_auth_username_cache,
                         (hash_link *) usernamehash);
        /* don't free the key as we use the same user string as the auth_user
         * structure */
        delete usernamehash;
    }

    /* remove any outstanding requests */
    link = requests.head;

    while (link) {
        debugs(29, 5, "AuthUser::~AuthUser: removing request entry '" << link->data << "'");
        auth_user_request = static_cast<AuthUserRequest *>(link->data);
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

    if (username_)
        xfree((char*)username_);

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
    AuthUser *auth_user;
    debugs(29, 3, "AuthUser::CachedACLsReset: Flushing the ACL caches for all users.");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        /* free cached acl results */
        aclCacheMatchFlush(&auth_user->proxy_match_cache);

    }

    debugs(29, 3, "AuthUser::CachedACLsReset: Finished.");
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
    AuthUser *auth_user;
    char const *username = NULL;
    debugs(29, 3, "AuthUser::cacheCleanup: Cleaning the user cache now");
    debugs(29, 3, "AuthUser::cacheCleanup: Current time: " << current_time.tv_sec);
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        username = auth_user->username();

        /* if we need to have inpedendent expiry clauses, insert a module call
         * here */
        debugs(29, 4, "AuthUser::cacheCleanup: Cache entry:\n\tType: " <<
               auth_user->auth_type << "\n\tUsername: " << username <<
               "\n\texpires: " <<
               (long int) (auth_user->expiretime + Config.authenticateTTL) <<
               "\n\treferences: " << (long int) auth_user->references);

        if (auth_user->expiretime + Config.authenticateTTL <= current_time.tv_sec) {
            debugs(29, 5, "AuthUser::cacheCleanup: Removing user " << username << " from cache due to timeout.");
            /* the minus 1 accounts for the cache lock */

            if (!(authenticateAuthUserInuse(auth_user) - 1))
                /* we don't warn if we leave the user in the cache,
                 * because other modules (ie delay pools) may keep
                 * locks on users, and thats legitimate
                 */
                auth_user->unlock();
        }
    }

    debugs(29, 3, "AuthUser::cacheCleanup: Finished cleaning the user cache.");
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
AuthUser::removeIp(IpAddress ipaddr)
{
    auth_user_ip_t *ipdata = (auth_user_ip_t *) ip_list.head;

    while (ipdata) {
        /* walk the ip list */

        if (ipdata->ipaddr == ipaddr) {
            /* remove the node */
            dlinkDelete(&ipdata->node, &ip_list);
            cbdataFree(ipdata);
            /* catch incipient underflow */
            assert(ipcount);
            ipcount--;
            return;
        }

        ipdata = (auth_user_ip_t *) ipdata->node.next;
    }

}

void
AuthUser::addIp(IpAddress ipaddr)
{
    auth_user_ip_t *ipdata = (auth_user_ip_t *) ip_list.head;
    int found = 0;

    CBDATA_INIT_TYPE(auth_user_ip_t);

    /*
     * we walk the entire list to prevent the first item in the list
     * preventing old entries being flushed and locking a user out after
     * a timeout+reconfigure
     */
    while (ipdata) {
        auth_user_ip_t *tempnode = (auth_user_ip_t *) ipdata->node.next;
        /* walk the ip list */

        if (ipdata->ipaddr == ipaddr) {
            /* This ip has already been seen. */
            found = 1;
            /* update IP ttl */
            ipdata->ip_expiretime = squid_curtime;
        } else if (ipdata->ip_expiretime + Config.authenticateIpTTL < squid_curtime) {
            /* This IP has expired - remove from the seen list */
            dlinkDelete(&ipdata->node, &ip_list);
            cbdataFree(ipdata);
            /* catch incipient underflow */
            assert(ipcount);
            ipcount--;
        }

        ipdata = tempnode;
    }

    if (found)
        return;

    /* This ip is not in the seen list */
    ipdata = cbdataAlloc(auth_user_ip_t);

    ipdata->ip_expiretime = squid_curtime;

    ipdata->ipaddr = ipaddr;

    dlinkAddTail(ipdata, &ipdata->node, &ip_list);

    ipcount++;

    debugs(29, 2, "authenticateAuthUserAddIp: user '" << username() << "' has been seen at a new IP address (" << ipaddr << ")");
}


void
AuthUser::lock()
{
    debugs(29, 9, "authenticateAuthUserLock auth_user '" << this << "'.");
    assert(this != NULL);
    references++;
    debugs(29, 9, "authenticateAuthUserLock auth_user '" << this << "' now at '" << references << "'.");
}

void
AuthUser::unlock()
{
    debugs(29, 9, "authenticateAuthUserUnlock auth_user '" << this << "'.");
    assert(this != NULL);

    if (references > 0) {
        references--;
    } else {
        debugs(29, 1, "Attempt to lower Auth User " << this << " refcount below 0!");
    }

    debugs(29, 9, "authenticateAuthUserUnlock auth_user '" << this << "' now at '" << references << "'.");

    if (references == 0)
        delete this;
}

/* addToNameCache: add a auth_user structure to the username cache */
void
AuthUser::addToNameCache()
{
    usernamehash = new AuthUserHashPointer (this);
}

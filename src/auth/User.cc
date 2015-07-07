/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "event.h"
#include "globals.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

time_t Auth::User::last_discard = 0;

Auth::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
    auth_type(Auth::AUTH_UNKNOWN),
    config(aConfig),
    ipcount(0),
    expiretime(0),
    notes(),
    credentials_state(Auth::Unchecked),
    username_(NULL),
    userKey_(NULL)
{
    requestRealm_ = aRequestRealm ? xstrdup(aRequestRealm) : NULL;
    proxy_match_cache.head = proxy_match_cache.tail = NULL;
    ip_list.head = ip_list.tail = NULL;
    debugs(29, 5, HERE << "Initialised auth_user '" << this << "'.");
}

Auth::CredentialState
Auth::User::credentials() const
{
    return credentials_state;
}

void
Auth::User::credentials(CredentialState newCreds)
{
    credentials_state = newCreds;
}

/**
 * Combine two user structs. ONLY to be called from within a scheme
 * module. The scheme module is responsible for ensuring that the
 * two users _can_ be merged without invalidating all the request
 * scheme data. The scheme is also responsible for merging any user
 * related scheme data itself.
 * The caller is responsible for altering all refcount pointers to
 * the 'from' object. They are invalid once this method is complete.
 */
void
Auth::User::absorb(Auth::User::Pointer from)
{
    /*
     * XXX Incomplete: it should merge in hash references too and ask the module to merge in scheme data
     *  dlink_list proxy_match_cache;
     */

    debugs(29, 5, HERE << "auth_user '" << from << "' into auth_user '" << this << "'.");

    // combine the helper response annotations. Ensuring no duplicates are copied.
    notes.appendNewOnly(&from->notes);

    /* absorb the list of IP address sources (for max_user_ip controls) */
    AuthUserIP *new_ipdata;
    while (from->ip_list.head != NULL) {
        new_ipdata = static_cast<AuthUserIP *>(from->ip_list.head->data);

        /* If this IP has expired - ignore the expensive merge actions. */
        if (new_ipdata->ip_expiretime <= squid_curtime) {
            /* This IP has expired - remove from the source list */
            dlinkDelete(&new_ipdata->node, &(from->ip_list));
            delete new_ipdata;
            /* catch incipient underflow */
            -- from->ipcount;
        } else {
            /* add to our list. replace if already present. */
            AuthUserIP *ipdata = static_cast<AuthUserIP *>(ip_list.head->data);
            bool found = false;
            while (ipdata) {
                AuthUserIP *tempnode = static_cast<AuthUserIP *>(ipdata->node.next->data);

                if (ipdata->ipaddr == new_ipdata->ipaddr) {
                    /* This IP has already been seen. */
                    found = true;
                    /* update IP ttl and stop searching. */
                    ipdata->ip_expiretime = max(ipdata->ip_expiretime, new_ipdata->ip_expiretime);
                    break;
                } else if (ipdata->ip_expiretime <= squid_curtime) {
                    /* This IP has expired - cleanup the destination list */
                    dlinkDelete(&ipdata->node, &ip_list);
                    delete ipdata;
                    /* catch incipient underflow */
                    assert(ipcount);
                    -- ipcount;
                }

                ipdata = tempnode;
            }

            if (!found) {
                /* This ip is not in the seen list. Add it. */
                dlinkAddTail(&new_ipdata->node, &ipdata->node, &ip_list);
                ++ipcount;
                /* remove from the source list */
                dlinkDelete(&new_ipdata->node, &(from->ip_list));
                ++from->ipcount;
            }
        }
    }
}

Auth::User::~User()
{
    debugs(29, 5, HERE << "Freeing auth_user '" << this << "'.");
    assert(LockCount() == 0);

    /* free cached acl results */
    aclCacheMatchFlush(&proxy_match_cache);

    /* free seen ip address's */
    clearIp();

    if (username_)
        xfree((char*)username_);
    if (requestRealm_)
        xfree((char*)requestRealm_);
    if (userKey_)
        xfree((char*)userKey_);

    /* prevent accidental reuse */
    auth_type = Auth::AUTH_UNKNOWN;
}

void
Auth::User::cacheInit(void)
{
    if (!proxy_auth_username_cache) {
        /* First time around, 7921 should be big enough */
        proxy_auth_username_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
        assert(proxy_auth_username_cache);
        eventAdd("User Cache Maintenance", cacheCleanup, NULL, ::Config.authenticateGCInterval, 1);
        last_discard = squid_curtime;
    }
}

void
Auth::User::CachedACLsReset()
{
    /*
     * This must complete all at once, because we are ensuring correctness.
     */
    AuthUserHashPointer *usernamehash;
    Auth::User::Pointer auth_user;
    debugs(29, 3, HERE << "Flushing the ACL caches for all users.");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        /* free cached acl results */
        aclCacheMatchFlush(&auth_user->proxy_match_cache);
    }

    debugs(29, 3, HERE << "Finished.");
}

void
Auth::User::cacheCleanup(void *datanotused)
{
    /*
     * We walk the hash by username as that is the unique key we use.
     * For big hashs we could consider stepping through the cache, 100/200
     * entries at a time. Lets see how it flys first.
     */
    AuthUserHashPointer *usernamehash;
    Auth::User::Pointer auth_user;
    char const *username = NULL;
    debugs(29, 3, HERE << "Cleaning the user cache now");
    debugs(29, 3, HERE << "Current time: " << current_time.tv_sec);
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        username = auth_user->username();

        /* if we need to have indedendent expiry clauses, insert a module call
         * here */
        debugs(29, 4, HERE << "Cache entry:\n\tType: " <<
               auth_user->auth_type << "\n\tUsername: " << username <<
               "\n\texpires: " <<
               (long int) (auth_user->expiretime + ::Config.authenticateTTL) <<
               "\n\treferences: " << auth_user->LockCount());

        if (auth_user->expiretime + ::Config.authenticateTTL <= current_time.tv_sec) {
            debugs(29, 5, HERE << "Removing user " << username << " from cache due to timeout.");

            /* Old credentials are always removed. Existing users must hold their own
             * Auth::User::Pointer to the credentials. Cache exists only for finding
             * and re-using current valid credentials.
             */
            hash_remove_link(proxy_auth_username_cache, usernamehash);
            delete usernamehash;
        }
    }

    debugs(29, 3, HERE << "Finished cleaning the user cache.");
    eventAdd("User Cache Maintenance", cacheCleanup, NULL, ::Config.authenticateGCInterval, 1);
    last_discard = squid_curtime;
}

void
Auth::User::clearIp()
{
    AuthUserIP *ipdata, *tempnode;

    ipdata = (AuthUserIP *) ip_list.head;

    while (ipdata) {
        tempnode = (AuthUserIP *) ipdata->node.next;
        /* walk the ip list */
        dlinkDelete(&ipdata->node, &ip_list);
        delete ipdata;
        /* catch incipient underflow */
        assert(ipcount);
        -- ipcount;
        ipdata = tempnode;
    }

    /* integrity check */
    assert(ipcount == 0);
}

void
Auth::User::removeIp(Ip::Address ipaddr)
{
    AuthUserIP *ipdata = (AuthUserIP *) ip_list.head;

    while (ipdata) {
        /* walk the ip list */

        if (ipdata->ipaddr == ipaddr) {
            /* remove the node */
            dlinkDelete(&ipdata->node, &ip_list);
            delete ipdata;
            /* catch incipient underflow */
            assert(ipcount);
            -- ipcount;
            return;
        }

        ipdata = (AuthUserIP *) ipdata->node.next;
    }

}

void
Auth::User::addIp(Ip::Address ipaddr)
{
    AuthUserIP *ipdata = (AuthUserIP *) ip_list.head;
    int found = 0;

    /*
     * we walk the entire list to prevent the first item in the list
     * preventing old entries being flushed and locking a user out after
     * a timeout+reconfigure
     */
    while (ipdata) {
        AuthUserIP *tempnode = (AuthUserIP *) ipdata->node.next;
        /* walk the ip list */

        if (ipdata->ipaddr == ipaddr) {
            /* This ip has already been seen. */
            found = 1;
            /* update IP ttl */
            ipdata->ip_expiretime = squid_curtime;
        } else if (ipdata->ip_expiretime <= squid_curtime) {
            /* This IP has expired - remove from the seen list */
            dlinkDelete(&ipdata->node, &ip_list);
            delete ipdata;
            /* catch incipient underflow */
            assert(ipcount);
            -- ipcount;
        }

        ipdata = tempnode;
    }

    if (found)
        return;

    /* This ip is not in the seen list */
    ipdata = new AuthUserIP(ipaddr, squid_curtime + ::Config.authenticateIpTTL);

    dlinkAddTail(ipdata, &ipdata->node, &ip_list);

    ++ipcount;

    debugs(29, 2, HERE << "user '" << username() << "' has been seen at a new IP address (" << ipaddr << ")");
}

SBuf
Auth::User::BuildUserKey(const char *username, const char *realm)
{
    SBuf key;
    if (realm)
        key.Printf("%s:%s", username, realm);
    else
        key.append(username, strlen(username));
    return key;
}

/**
 * Add the Auth::User structure to the username cache.
 */
void
Auth::User::addToNameCache()
{
    /* AuthUserHashPointer will self-register with the username cache */
    new AuthUserHashPointer(this);
}

/**
 * Dump the username cache statictics for viewing...
 */
void
Auth::User::UsernameCacheStats(StoreEntry *output)
{
    AuthUserHashPointer *usernamehash;

    /* overview of username cache */
    storeAppendPrintf(output, "Cached Usernames: %d of %d\n", proxy_auth_username_cache->count, proxy_auth_username_cache->size);
    storeAppendPrintf(output, "Next Garbage Collection in %d seconds.\n",
                      static_cast<int32_t>(last_discard + ::Config.authenticateGCInterval - squid_curtime));

    /* cache dump column titles */
    storeAppendPrintf(output, "\n%-15s %-9s %-9s %-9s %s\n",
                      "Type",
                      "State",
                      "Check TTL",
                      "Cache TTL",
                      "Username");
    storeAppendPrintf(output, "--------------- --------- --------- --------- ------------------------------\n");

    hash_first(proxy_auth_username_cache);
    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        Auth::User::Pointer auth_user = usernamehash->user();

        storeAppendPrintf(output, "%-15s %-9s %-9d %-9d %s\n",
                          Auth::Type_str[auth_user->auth_type],
                          CredentialState_str[auth_user->credentials()],
                          auth_user->ttl(),
                          static_cast<int32_t>(auth_user->expiretime - squid_curtime + ::Config.authenticateTTL),
                          auth_user->username()
                         );
    }
}

void
Auth::User::username(char const *aString)
{
    SBuf key;

    if (aString) {
        assert(!username_);
        username_ = xstrdup(aString);
        key = BuildUserKey(username_, requestRealm_);
        // XXX; performance regression. c_str() reallocates, then xstrdup() reallocates
        userKey_ = xstrdup(key.c_str());
    } else {
        safe_free(username_);
        safe_free(userKey_)
    }
}


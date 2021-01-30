/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
#include "auth/CredentialsCache.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "event.h"
#include "globals.h"
#include "SquidTime.h"
#include "Store.h"

Auth::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    auth_type(Auth::AUTH_UNKNOWN),
    config(aConfig),
    ipcount(0),
    expiretime(0),
    credentials_state(Auth::Unchecked),
    username_(nullptr),
    requestRealm_(aRequestRealm)
{
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

    /* prevent accidental reuse */
    auth_type = Auth::AUTH_UNKNOWN;
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
            ipdata->ip_expiretime = squid_curtime + Auth::TheConfig.ipTtl;
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
    ipdata = new AuthUserIP(ipaddr, squid_curtime + Auth::TheConfig.ipTtl);

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
 * Dump the username cache statictics for viewing...
 */
void
Auth::User::CredentialsCacheStats(StoreEntry *output)
{
    auto userlist = authenticateCachedUsersList();
    storeAppendPrintf(output, "Cached Usernames: %d", static_cast<int32_t>(userlist.size()));
    storeAppendPrintf(output, "\n%-15s %-9s %-9s %-9s %s\t%s\n",
                      "Type",
                      "State",
                      "Check TTL",
                      "Cache TTL",
                      "Username", "Key");
    storeAppendPrintf(output, "--------------- --------- --------- --------- ------------------------------\n");
    for ( auto auth_user : userlist ) {
        storeAppendPrintf(output, "%-15s %-9s %-9d %-9d %s\t" SQUIDSBUFPH "\n",
                          Auth::Type_str[auth_user->auth_type],
                          CredentialState_str[auth_user->credentials()],
                          auth_user->ttl(),
                          static_cast<int32_t>(auth_user->expiretime - squid_curtime + Auth::TheConfig.credentialsTtl),
                          auth_user->username(),
                          SQUIDSBUFPRINT(auth_user->userKey())
                         );
    }
}

void
Auth::User::username(char const *aString)
{
    if (aString) {
        assert(!username_);
        username_ = xstrdup(aString);
        // NP: param #2 is working around a c_str() data-copy performance regression
        userKey_ = BuildUserKey(username_, (!requestRealm_.isEmpty() ? requestRealm_.c_str() : NULL));
    } else {
        safe_free(username_);
        userKey_.clear();
    }
}


/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/Config.h"
#include "auth/CredentialsCache.h"
#include "auth/digest/Config.h"
#include "auth/digest/User.h"
#include "Debug.h"
#include "dlink.h"

Auth::Digest::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm),
    HA1created(0)
{
    memset(HA1, 0, sizeof(HA1));
}

Auth::Digest::User::~User()
{
    dlink_node *link, *tmplink;
    link = nonces.head;

    while (link) {
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, &nonces);
        authDigestNoncePurge(static_cast < digest_nonce_h * >(tmplink->data));
        authDigestNonceUnlink(static_cast < digest_nonce_h * >(tmplink->data));
        delete tmplink;
    }
}

Auth::Ttl
Auth::Digest::User::ttl() const
{
    const Auth::Ttl global_ttl(expiretime - squid_curtime);

    /* find the longest lasting nonce. */
    int32_t latest_nonce = -1;
    dlink_node *link = nonces.head;
    while (link) {
        digest_nonce_h *nonce = static_cast<digest_nonce_h *>(link->data);
        if (nonce->flags.valid && nonce->noncedata.creationtime > latest_nonce)
            latest_nonce = nonce->noncedata.creationtime;

        link = link->next;
    }

    if (latest_nonce == -1) {
        static const Auth::Ttl expired(-1);
        return std::min(expired, global_ttl);
    }

    const Auth::Ttl nonce_ttl(latest_nonce - current_time.tv_sec + static_cast<Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration);

    return std::min(nonce_ttl, global_ttl);
}

digest_nonce_h *
Auth::Digest::User::currentNonce()
{
    digest_nonce_h *nonce = NULL;
    dlink_node *link = nonces.tail;
    if (link) {
        nonce = static_cast<digest_nonce_h *>(link->data);
        if (authDigestNonceIsStale(nonce))
            nonce = NULL;
    }
    return nonce;
}

CbcPointer<Auth::CredentialsCache>
Auth::Digest::User::Cache()
{
    static CbcPointer<Auth::CredentialsCache> p(new Auth::CredentialsCache("digest","GC Digest user credentials"));
    return p;
}

void
Auth::Digest::User::addToNameCache()
{
    Cache()->insert(userKey(), this);
}


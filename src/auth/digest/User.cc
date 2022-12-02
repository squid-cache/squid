/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
#include "debug/Stream.h"

Auth::Digest::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm),
    HA1created(0)
{
    memset(HA1, 0, sizeof(HA1));
}

Auth::Digest::User::~User()
{
    for (const auto &nonce: nonces) {
        authDigestNoncePurge(nonce.getRaw());
    }
}

int32_t
Auth::Digest::User::ttl() const
{
    int32_t global_ttl = static_cast<int32_t>(expiretime - squid_curtime + Auth::TheConfig.credentialsTtl);

    /* find the longest lasting nonce. */
    int32_t latest_nonce = -1;

    for (const auto &nonce: nonces) {
        if (nonce->flags.valid && nonce->noncedata.creationtime > latest_nonce)
            latest_nonce = nonce->noncedata.creationtime;
    }
    if (latest_nonce == -1)
        return min(-1, global_ttl);

    int32_t nonce_ttl = latest_nonce - current_time.tv_sec + static_cast<Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration;

    return min(nonce_ttl, global_ttl);
}

void
Auth::Digest::User::link(const digest_nonce_h::Pointer &nonce)
{
    if (!nonce)
        return;

    if (std::find_if(nonces.begin(), nonces.end(), [&nonce](const digest_nonce_h::Pointer &n){ return n == nonce; }) != nonces.end())
        return;

    nonces.push_back(nonce);

    /* we don't lock this reference because removing the user removes the
     * hash too. Of course if that changes we're stuffed so read the code huh?
     */
    nonce->user = this;
}

void
Auth::Digest::User::unlink(const digest_nonce_h::Pointer &nonce)
{
    if (!nonce)
        return;

    if (!nonce->user)
        return;

    nonces.remove(nonce);

    /* this reference to user was not locked because freeeing the user frees
     * the nonce too.
     */
    nonce->user = nullptr;
}

digest_nonce_h::Pointer
Auth::Digest::User::currentNonce()
{
    if (!nonces.empty()) {
        if (const auto nonce = nonces.back()) {
            if (!nonce->stale())
                return nonce;
        }
    }
    return nullptr;
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


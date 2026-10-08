/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_DIGEST_NONCE_H
#define SQUID_SRC_AUTH_DIGEST_NONCE_H

#include "auth/digest/forward.h"
#include "hash.h"
#include "mem/AllocatorProxy.h"

namespace Auth
{
namespace Digest
{

class Nonce : public hash_link
{
    MEMPROXY_CLASS(Auth::Digest::Nonce);
public:
    /// data to be encoded into the nonce's hex representation
    struct _Data {
        time_t creationtime = 0;
        uint32_t randomdata = 0;
    } noncedata;

    /// number of uses we've seen of this nonce
    unsigned long nc = 0;

    // TODO: replace with RefCountable
    /// reference counting
    uint64_t references = 0;

    /// the auth_user this nonce has been tied to
    Auth::Digest::User *user = nullptr;

    struct {
        bool valid = false; ///< whether this nonce has been invalidated
        bool incache = false; ///< whether this nonce is linked to the digest_nonce_cache
    } flags;
};

} // namespace Digest
} // namespace Auth

// TODO: remove diff-reduction alias
typedef Auth::Digest::Nonce digest_nonce_h;

#endif /* SQUID_SRC_AUTH_DIGEST_NONCE_H */

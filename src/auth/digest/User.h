#ifndef _SQUID_AUTH_DIGEST_USER_H
#define _SQUID_AUTH_DIGEST_USER_H

#include "auth/User.h"

namespace Auth
{
namespace Digest
{

/** User credentials for the Digest authentication protocol */
class User : public Auth::User
{
public:
    MEMPROXY_CLASS(Auth::Digest::User);

    User(Auth::Config *);
    ~User();
    int authenticated() const;

    virtual int32_t ttl() const;

    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;
};

MEMPROXY_CLASS_INLINE(Auth::Digest::User);

} // namespace Digest
} // namespace Auth

#endif /* _SQUID_AUTH_DIGEST_USER_H */

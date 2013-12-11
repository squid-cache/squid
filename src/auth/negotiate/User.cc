#include "squid.h"
#include "auth/Config.h"
#include "auth/negotiate/User.h"
#include "Debug.h"

Auth::Negotiate::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
        Auth::User(aConfig, aRequestRealm)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
}

Auth::Negotiate::User::~User()
{
    debugs(29, 5, HERE << "doing nothing to clear Negotiate scheme data for '" << this << "'");
}

int32_t
Auth::Negotiate::User::ttl() const
{
    return -1; // Negotiate cannot be cached.
}

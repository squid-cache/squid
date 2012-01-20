#include "squid.h"
#include "auth/Config.h"
#include "auth/ntlm/User.h"
#include "Debug.h"

Auth::Ntlm::User::User(Auth::Config *aConfig) :
        Auth::User(aConfig)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
}

Auth::Ntlm::User::~User()
{
    debugs(29, 5, HERE << "doing nothing to clear NTLM scheme data for '" << this << "'");
}

int32_t
Auth::Ntlm::User::ttl() const
{
    return -1; // NTLM credentials cannot be cached.
}

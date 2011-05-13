#ifndef _SQUID_AUTH_CREDENTIALSTATE_H
#define _SQUID_AUTH_CREDENTIALSTATE_H

namespace Auth
{

typedef enum {
    Unchecked,
    Ok,
    Pending,
    Handshake,
    Failed
} CredentialState;

extern const char *CredentialState_str[];

} // namespace Auth

#endif /* _SQUID_AUTH_CREDENTIALSTATE_H */

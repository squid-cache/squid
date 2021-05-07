/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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


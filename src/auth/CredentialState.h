/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_CREDENTIALSTATE_H
#define SQUID_SRC_AUTH_CREDENTIALSTATE_H

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

#endif /* SQUID_SRC_AUTH_CREDENTIALSTATE_H */


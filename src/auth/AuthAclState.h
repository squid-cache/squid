/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_AUTHACLSTATE_H
#define SQUID_SRC_AUTH_AUTHACLSTATE_H

#if USE_AUTH

typedef enum {
    AUTH_ACL_CHALLENGE = -2,
    AUTH_ACL_HELPER = -1,
    AUTH_ACL_CANNOT_AUTHENTICATE = 0,
    AUTH_AUTHENTICATED = 1
} AuthAclState;

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_AUTHACLSTATE_H */


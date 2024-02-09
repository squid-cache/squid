/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PEER_PROXY_NEGOTIATE_AUTH_H
#define SQUID_SRC_PEER_PROXY_NEGOTIATE_AUTH_H

#define PEER_PROXY_NEGOTIATE_NOKEYTAB   1

#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI

/* upstream proxy authentication */
SQUIDCEXTERN char *peer_proxy_negotiate_auth(char *principal_name, char *proxy, int flags);
#endif

#endif /* SQUID_SRC_PEER_PROXY_NEGOTIATE_AUTH_H */


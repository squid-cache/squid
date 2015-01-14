/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PEER_PROXY_NEGOTIATE_AUTH_H_
#define SQUID_PEER_PROXY_NEGOTIATE_AUTH_H_

#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
/* upstream proxy authentication */
SQUIDCEXTERN char *peer_proxy_negotiate_auth(char *principal_name, char *proxy);
#endif

#endif /* SQUID_PEER_PROXY_NEGOTIATE_AUTH_H_ */


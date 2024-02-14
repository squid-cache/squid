/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */
#ifndef SQUID_SRC_AUTH_DIGEST_EDIRECTORY_EDIR_LDAPEXT_H
#define SQUID_SRC_AUTH_DIGEST_EDIRECTORY_EDIR_LDAPEXT_H

#if HAVE_LDAP_H
#include <ldap.h>
#endif

int nds_get_password(LDAP *ld, char *object_dn, size_t * pwd_len, char *pwd);

#endif /* SQUID_SRC_AUTH_DIGEST_EDIRECTORY_EDIR_LDAPEXT_H */


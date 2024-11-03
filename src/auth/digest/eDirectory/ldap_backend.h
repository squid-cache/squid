/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Flavio Pescuma. <flavio@marasystems.com>
 */

#ifndef SQUID_SRC_AUTH_DIGEST_EDIRECTORY_LDAP_BACKEND_H
#define SQUID_SRC_AUTH_DIGEST_EDIRECTORY_LDAP_BACKEND_H

#include "auth/digest/eDirectory/digest_common.h"
extern int LDAPArguments(int argc, char **argv);
extern void LDAPHHA1(RequestData * requestData);

#endif /* SQUID_SRC_AUTH_DIGEST_EDIRECTORY_LDAP_BACKEND_H */


/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_BASIC_SMB_LM_VALID_H
#define SQUID_SRC_AUTH_BASIC_SMB_LM_VALID_H
/* SMB User verification function */

#define NTV_NO_ERROR 0
#define NTV_SERVER_ERROR 1
#define NTV_PROTOCOL_ERROR 2
#define NTV_LOGON_ERROR 3

int Valid_User(char *USERNAME, char *PASSWORD, const char *SERVER, char *BACKUP, const char *DOMAIN);

#endif /* SQUID_SRC_AUTH_BASIC_SMB_LM_VALID_H */


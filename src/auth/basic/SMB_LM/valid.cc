/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/basic/SMB_LM/valid.h"
#include "smblib/smblib.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif

// BACKUP is unused
int
Valid_User(char *USERNAME, char *PASSWORD, const char *SERVER, char *, const char *DOMAIN)
{
    const char *supportedDialects[] = {"PC NETWORK PROGRAM 1.0",
                                       "MICROSOFT NETWORKS 1.03",
                                       "MICROSOFT NETWORKS 3.0",
                                       "LANMAN1.0",
                                       "LM1.2X002",
                                       "Samba",
                                       "NT LM 0.12",
                                       "NT LANMAN 1.0",
                                       NULL
                                      };
    SMB_Handle_Type con;

    SMB_Init();
    con = SMB_Connect_Server(NULL, SERVER, DOMAIN);
    if (con == NULL) {
        return (NTV_SERVER_ERROR);
    }
    if (SMB_Negotiate(con, supportedDialects) < 0) {    /* An error */
        SMB_Discon(con, 0);
        return (NTV_PROTOCOL_ERROR);
    }
    if (SMB_Logon_Server(con, USERNAME, PASSWORD, NULL, 0) < 0) {
        SMB_Discon(con, 0);
        return (NTV_LOGON_ERROR);
    }
    SMB_Discon(con, 0);
    return (NTV_NO_ERROR);
}


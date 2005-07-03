#include "config.h"
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include "smblib-priv.h"
#include "smblib.h"
#include "valid.h"

int
Valid_User(char *USERNAME, char *PASSWORD, char *SERVER, char *BACKUP, char *DOMAIN)
{
    const char *SMB_Prots[] =
    {"PC NETWORK PROGRAM 1.0",
	"MICROSOFT NETWORKS 1.03",
	"MICROSOFT NETWORKS 3.0",
	"LANMAN1.0",
	"LM1.2X002",
	"Samba",
	"NT LM 0.12",
	"NT LANMAN 1.0",
	NULL};
    void *con;

    SMB_Init();
    con = SMB_Connect_Server(NULL, SERVER, DOMAIN);
    if (con == NULL) {		/* Error ... */
	con = SMB_Connect_Server(NULL, BACKUP, DOMAIN);
	if (con == NULL) {
	    return (NTV_SERVER_ERROR);
	}
    }
    if (SMB_Negotiate(con, SMB_Prots) < 0) {	/* An error */
	SMB_Discon(con, 0);
	return (NTV_PROTOCOL_ERROR);
    }
    if (SMB_Logon_Server(con, USERNAME, PASSWORD) < 0) {
	SMB_Discon(con, 0);
	return (NTV_LOGON_ERROR);
    }
    SMB_Discon(con, 0);
    return (NTV_NO_ERROR);
}

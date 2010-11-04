#include "config.h"
#include "libntlmauth/ntlmauth.h"
#include "libntlmauth/smblmauth.h"
#include "libntlmauth/smb.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

/** Do a full authentication sequence against the given server with user/pass/domain.
 * Password is pre-encrypted.
 */
int
smblm_authenticate_atomic(char *username, char *password, char *server, char *backup, char *domain)
{
    int pass_is_precrypted_p = 0;
    char const *supportedDialects[] = {
        /*              "PC NETWORK PROGRAM 1.0", */
        /*              "MICROSOFT NETWORKS 1.03", */
        /*              "MICROSOFT NETWORKS 3.0", */
        "LANMAN1.0",
        "LM1.2X002",
        "Samba",
        /*              "NT LM 0.12", */
        /*              "NT LANMAN 1.0", */
        NULL
    };
    SMB_Handle_Type con;

    SMB_Init();
    con = SMB_Connect_Server(NULL, server, domain);
    if (con == NULL) {		/* Error ... */
        con = SMB_Connect_Server(NULL, backup, domain);
        if (con == NULL) {
            return SMBLM_ERR_SERVER;
        }
    }
    if (SMB_Negotiate(con, supportedDialects) < 0) {	/* An error */
        SMB_Discon(con, 0);
        return SMBLM_ERR_PROTOCOL;
    }
    /* Test for a server in share level mode do not authenticate against it */
    if (con->Security == 0) {
        SMB_Discon(con, 0);
        return SMBLM_ERR_PROTOCOL;
    }
    if (SMB_Logon_Server(con, username, password, domain, pass_is_precrypted_p) < 0) {
        SMB_Discon(con, 0);
        return SMBLM_ERR_LOGON;
    }
    SMB_Discon(con, 0);
    return SMBLM_ERR_NONE;
}

/** Fetches a SMB LanMan challenge nonce from the given server. */
void *
smblm_get_nonce(char *server, char *backup, char *domain, char *nonce)
{
    char const *SMB_Prots[] = {
        /*              "PC NETWORK PROGRAM 1.0", */
        /*              "MICROSOFT NETWORKS 1.03", */
        /*              "MICROSOFT NETWORKS 3.0", */
        "LANMAN1.0",
        "LM1.2X002",
        "Samba",
        /*              "NT LM 0.12", */
        /*              "NT LANMAN 1.0", */
        NULL
    };
    SMB_Handle_Type con;

    SMB_Init();
    con = SMB_Connect_Server(NULL, server, domain);
    if (con == NULL) {		/* Error ... */
        con = SMB_Connect_Server(NULL, backup, domain);
        if (con == NULL) {
            return (NULL);
        }
    }

    if (SMB_Negotiate(con, SMB_Prots) < 0) {	/* An error */
        SMB_Discon(con, 0);
        return (NULL);
    }

    /* Test for a server in share level mode do not authenticate against it */
    if (con->Security == 0) {
        SMB_Discon(con, 0);
        return (NULL);
    }

    memcpy(nonce, con->Encrypt_Key, 8);
    return (con);
}

/** Authenticate with given username/password */
int
smblm_authenticate(void *handle, char *username, char *password, int flag)
{
    SMB_Handle_Type con = handle;

    if (SMB_Logon_Server(con, username, password, NULL, flag) < 0) {
        return SMBLM_ERR_LOGON;
    }
    return SMBLM_ERR_NONE;
}

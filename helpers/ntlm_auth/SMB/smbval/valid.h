#ifndef _VALID_H_
#define _VALID_H_
/* SMB User verification function */

#define NTV_NO_ERROR 0
#define NTV_SERVER_ERROR 1
#define NTV_PROTOCOL_ERROR 2
#define NTV_LOGON_ERROR 3

int Valid_User(char *USERNAME, char *PASSWORD, char *SERVER, char *BACKUP, char *DOMAIN);
void *NTLM_Connect(char *SERVER, char *BACKUP, char *DOMAIN, char *nonce);
int NTLM_Auth(void *handle, char *USERNAME, char *PASSWORD, int flag);
void NTLM_Disconnect(void *handle);

#endif

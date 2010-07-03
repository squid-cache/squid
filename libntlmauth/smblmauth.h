#ifndef _LIBNTLMAUTH_SMBLMAUTH_H
#define _LIBNTLMAUTH_SMBLMAUTH_H

/* TODO: copyright. who owns this? there was none in the original code!! */
/* Maybe Richard Sharpe or maybe not. */

/* SMB LM Error Codes */
#define SMBLM_ERR_NONE        0
#define SMBLM_ERR_SERVER      1
#define SMBLM_ERR_PROTOCOL    2
#define SMBLM_ERR_LOGON       3

/**
 * Connect to a SMB LanMan server and authenticate the provided credentials.
 *
 * TODO: const-correctness on the parameters.
 */
extern int smblm_authenticate_atomic(char *username,
                                     char *password,
                                     char *server,
                                     char *backup,
                                     char *domain);

/** Fetches a SMB LanMan challenge nonce from the given server. */
void * smblm_get_nonce(char *server,
                       char *backup,
                       char *domain,
                       char *nonce);

/** Authenticate with given username/password */
int smblm_authenticate(void *handle,
                       char *username,
                       char *password,
                       int flag);

/** Disconnect a handle from use */
#define smblm_disconnect(x)    SMB_Discon(X, 0)

#endif /* _LIBNTLMAUTH_SMBLMAUTH_H */

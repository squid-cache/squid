/*
 * edir_ldapext.h
 *
 * AUTHOR: Guy Antony Halse <g.halse@ru.ac.za>
 *
 * stubs for FreeRadius's edir_ldapext.h
 *
 */
#define UNIVERSAL_PASS_LEN    256
#define NMAS_SUCCESS          0

extern int berEncodePasswordData(struct berval **requestBV, char *objectDN, char *password, char *password2);
extern int berDecodeLoginData(struct berval *replyBV, int *serverVersion, size_t * retDataLen, void *retData);
extern int nmasldap_get_password(LDAP * ld, char *objectDN, size_t * pwdSize, char *pwd);

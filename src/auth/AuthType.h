#ifndef _SQUID__SRC_AUTH_AUTHTYPE_H
#define _SQUID__SRC_AUTH_AUTHTYPE_H

typedef enum {
    AUTH_UNKNOWN,               /* default */
    AUTH_BASIC,
    AUTH_NTLM,
    AUTH_DIGEST,
    AUTH_NEGOTIATE,
    AUTH_BROKEN                 /* known type, but broken data */
} AuthType;

extern const char *AuthType_str[];

#endif

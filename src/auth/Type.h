#ifndef _SQUID__SRC_AUTH_AUTHTYPE_H
#define _SQUID__SRC_AUTH_AUTHTYPE_H

#if USE_AUTH

namespace Auth
{

typedef enum {
    AUTH_UNKNOWN,               /* default */
    AUTH_BASIC,
    AUTH_NTLM,
    AUTH_DIGEST,
    AUTH_NEGOTIATE,
    AUTH_BROKEN                 /* known type, but broken data */
} Type;

extern const char *Type_str[];

}; // namespace Auth

#endif /* USE_AUTH */
#endif

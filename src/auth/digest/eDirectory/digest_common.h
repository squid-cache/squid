/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Digest helper API details.
 */

#ifndef SQUID_DIGEST_COMMON_H_
#define SQUID_DIGEST_COMMON_H_

#include "hash.h"
#include "rfc2617.h"
#include "util.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

typedef struct _request_data {
    int channelId;
    char *user;
    char *realm;
    char *password;
    HASHHEX HHA1;
    int parsed;
    int error;
} RequestData;

/* to use a backend, include your backend.h file
 * and define thusly:
 * #define ProcessArguments(A, B) MyHandleArguments(A,B)
 * #define GetHHA1(A) MyGetHHA1(A)
 */
typedef void HandleArguments(int, char **);
typedef void HHA1Creator(RequestData *);

#endif /* SQUID_DIGEST_COMMON_H_ */


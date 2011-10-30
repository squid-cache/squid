/*
 * digest_common.h
 *
 * AUTHOR: Robert Collins.
 *
 * Digest helper API details.
 *
 * Copyright (c) 2003  Robert Collins  <robertc@squid-cache.org>
 */

#ifndef SQUID_DIGEST_COMMON_H_
#define SQUID_DIGEST_COMMON_H_

#include "hash.h"
#include "rfc2617.h"
#include "util.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

typedef struct _request_data {
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

/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "md5.h"

static void MDPrint(unsigned char digest[16]);
static void MDString(char *string);

static void
MDString(char *string)
{
    MD5_CTX context;
    unsigned char digest[16];
    unsigned int len = strlen(string);
    xMD5Init(&context);
    xMD5Update(&context, string, len);
    xMD5Final(digest, &context);
    printf("MD5 (\"%s\") = ", string);
    MDPrint(digest);
    printf("\n");
}

static void
MDPrint(unsigned char digest[16])
{
    unsigned int i;
    for (i = 0; i < 16; i++)
        printf("%02x", digest[i]);
}

int
main(int argc, char **argv)
{
    printf("MD5 test suite:\n");
    MDString("");
    MDString("a");
    MDString("abc");
    MDString("message digest");
    MDString("abcdefghijklmnopqrstuvwxyz");
    MDString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    MDString("1234567890123456789012345678901234567890"
             "1234567890123456789012345678901234567890");
    return 0;
}


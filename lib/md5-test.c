/*
 * $Id: md5-test.c,v 1.2 1998/09/23 17:16:11 wessels Exp $
 */

/*
 * COMPILE WITH:
 *      gcc -Wall md5-test.c -I../include md5.o
 */

#include "config.h"
#include "md5.h"
#include "stdio.h"

static void MDPrint(unsigned char digest[16]);
static void MDString(char *string);

static void
MDString(char *string)
{
    MD5_CTX context;
    unsigned char digest[16];
    unsigned int len = strlen(string);
    MD5Init(&context);
    MD5Update(&context, string, len);
    MD5Final(digest, &context);
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
    MDString
	("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    MDString
	("1234567890123456789012345678901234567890\
1234567890123456789012345678901234567890");
    return 0;
}

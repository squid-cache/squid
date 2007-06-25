/*
 * Shamelessly stolen from linux-pam, and adopted to work with
 * OpenSSL md5 implementation and any magic string
 *
 * Origin2: md5_crypt.c,v 1.1.1.1 2000/01/03 17:34:46 gafton Exp
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Origin: Id: crypt.c,v 1.3 1995/05/30 05:42:22 rgrimes Exp
 *
 */

#include <string.h>
#include <stdio.h>
#include "config.h"
#include "md5.h"

#include "crypt_md5.h"

static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void md5to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v & 0x3f];
	v >>= 6;
    }
}

/*
 * MD5 hash a password
 *
 * Use MD5 for what it is best at...
 *
 * If salt begins with $ then it is assumed to be on the form
 *   $magic$salt$...
 * If not the normal UNIX magic $1$ is used.
 */

char *crypt_md5(const char *pw, const char *salt)
{
    const char *magic = "$1$";
    int magiclen = 3;
    static char passwd[120], *p;
    static const char *sp, *ep;
    unsigned char final[16];
    int sl, pl, i, j;
    MD5_CTX ctx, ctx1;
    unsigned long l;

    if (*salt == '$') {
	magic = salt++;
	while(*salt && *salt != '$')
	    salt++;
	if (*salt == '$') {
	    salt++;
	    magiclen = salt - magic;
	} else {
	    salt = magic;
	    magic = "$1$";
	}
    }

    /* Refine the Salt first */
    sp = salt;

    /* It stops at the first '$', max 8 chars */
    for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
	continue;

    /* get the length of the true salt */
    sl = ep - sp;

    MD5Init(&ctx);

    /* The password first, since that is what is most unknown */
    MD5Update(&ctx, (unsigned const char *) pw, strlen(pw));

    /* Then our magic string */
    MD5Update(&ctx, (unsigned const char *) magic, magiclen);

    /* Then the raw salt */
    MD5Update(&ctx, (unsigned const char *) sp, sl);

    /* Then just as many characters of the MD5(pw,salt,pw) */
    MD5Init(&ctx1);
    MD5Update(&ctx1, (unsigned const char *) pw, strlen(pw));
    MD5Update(&ctx1, (unsigned const char *) sp, sl);
    MD5Update(&ctx1, (unsigned const char *) pw, strlen(pw));
    MD5Final(final, &ctx1);
    for (pl = strlen(pw); pl > 0; pl -= 16)
	MD5Update(&ctx, (unsigned const char *) final, pl > 16 ? 16 : pl);

    /* Don't leave anything around in vm they could use. */
    memset(final, 0, sizeof final);

    /* Then something really weird... */
    for (j = 0, i = strlen(pw); i; i >>= 1)
	if (i & 1)
	    MD5Update(&ctx, (unsigned const char *) final + j, 1);
	else
	    MD5Update(&ctx, (unsigned const char *) pw + j, 1);

    /* Now make the output string */
    memset(passwd, 0, sizeof(passwd));
    strncat(passwd, magic, magiclen);
    strncat(passwd, sp, sl);
    strcat(passwd, "$");

    MD5Final(final, &ctx);

    /*
     * and now, just to make sure things don't run too fast
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for (i = 0; i < 1000; i++) {
	MD5Init(&ctx1);
	if (i & 1)
	    MD5Update(&ctx1, (unsigned const char *) pw, strlen(pw));
	else
	    MD5Update(&ctx1, (unsigned const char *) final, 16);

	if (i % 3)
	    MD5Update(&ctx1, (unsigned const char *) sp, sl);

	if (i % 7)
	    MD5Update(&ctx1, (unsigned const char *) pw, strlen(pw));

	if (i & 1)
	    MD5Update(&ctx1, (unsigned const char *) final, 16);
	else
	    MD5Update(&ctx1, (unsigned const char *) pw, strlen(pw));
	MD5Final(final, &ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[0] << 16) | (final[6] << 8) | final[12];
    md5to64(p, l, 4);
    p += 4;
    l = (final[1] << 16) | (final[7] << 8) | final[13];
    md5to64(p, l, 4);
    p += 4;
    l = (final[2] << 16) | (final[8] << 8) | final[14];
    md5to64(p, l, 4);
    p += 4;
    l = (final[3] << 16) | (final[9] << 8) | final[15];
    md5to64(p, l, 4);
    p += 4;
    l = (final[4] << 16) | (final[10] << 8) | final[5];
    md5to64(p, l, 4);
    p += 4;
    l = final[11];
    md5to64(p, l, 2);
    p += 2;
    *p = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(final, 0, sizeof final);

    return passwd;
}

/* Created by Ramon de Carvalho <ramondecarvalho@yahoo.com.br>
   Refined by Rodrigo Rubira Branco <rodrigo@kernelhacking.com>
*/
char *md5sum(const char *s){
   static unsigned char digest[16];
   MD5_CTX ctx;
   int idx;
   static char sum[33];

   memset(digest,0,16);

   MD5Init(&ctx);
   MD5Update(&ctx,(const unsigned char *)s,strlen(s));
   MD5Final(digest,&ctx);

   for(idx=0;idx<16;idx++)
       sprintf(&sum[idx*2],"%02x",digest[idx]);

   sum[32]='\0';

   /* Don't leave anything around in vm they could use. */
   memset(digest, 0, sizeof digest);

   return sum;
}


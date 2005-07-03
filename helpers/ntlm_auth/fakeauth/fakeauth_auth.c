/*
 *
 * AUTHOR: Robert Collins <rbtcollins@hotmail.com>
 *
 * Example ntlm authentication program for Squid, based on the
 * original proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>. Initial ntlm code by
 * Andrew Doran <ad@interlude.eu.org>.
 *
 * This code gets the username and returns it. No validation is done.
 * and by the way: it is a complete patch-up. Use the "real thing" NTLMSSP
 * if you can.
 */

#include "config.h"
#include "ntlmauth.h"
#include "squid_endian.h"

#include "ntlm.h"
#include "util.h"
#include <ctype.h>

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif


#define ERR    "ERR\n"
#define OK     "OK\n"

#if 0
#define NTLM_STATIC_CHALLENGE "deadbeef"
#endif
static char *authenticate_ntlm_domain = "LIFELESSWKS";

/* NTLM authentication by ad@interlude.eu.org - 07/1999 */
/* XXX this is not done cleanly... */

/* makes a null-terminated string lower-case. Changes CONTENTS! */
static void
lc(char *string)
{
    char *p = string, c;
    while ((c = *p)) {
	*p = xtolower(c);
	p++;
    }
}


/*
 * Generates a challenge request. The randomness of the 8 byte 
 * challenge strings can be guarenteed to be poor at best.
 */
void
ntlmMakeChallenge(struct ntlm_challenge *chal)
{
#ifndef NTLM_STATIC_CHALLENGE
    static unsigned hash;
    int r;
#endif
    char *d;
    int i;

    memset(chal, 0, sizeof(*chal));
    memcpy(chal->hdr.signature, "NTLMSSP", 8);
    chal->flags = htole32(0x00018206);
    chal->hdr.type = htole32(NTLM_CHALLENGE);
    chal->unknown[6] = htole16(0x003a);

    d = (char *) chal + 48;
    i = 0;

    if (authenticate_ntlm_domain != NULL)
	while (authenticate_ntlm_domain[i++]);


    chal->target.offset = htole32(48);
    chal->target.maxlen = htole16(i);
    chal->target.len = chal->target.maxlen;

#ifdef NTLM_STATIC_CHALLENGE
    memcpy(chal->challenge, NTLM_STATIC_CHALLENGE, 8);
#else
    r = (int) rand();
    r = (hash ^ r) + r;

    for (i = 0; i < 8; i++) {
	chal->challenge[i] = r;
	r = (r >> 2) ^ r;
    }

    hash = r;
#endif
}

/*
 * Check the vailidity of a request header. Return -1 on error.
 */
int
ntlmCheckHeader(ntlmhdr * hdr, int type)
{
    /* 
     * Must be the correct security package and request type. The
     * 8 bytes compared includes the ASCII 'NUL'. 
     */
    if (memcmp(hdr->signature, "NTLMSSP", 8) != 0) {
	fprintf(stderr, "ntlmCheckHeader: bad header signature\n");
	return (-1);
    }
    if (type == NTLM_ANY)
	return 0;

    if (le32toh(hdr->type) != type) {
/* don't report this error - it's ok as we do a if() around this function */
//      fprintf(stderr, "ntlmCheckHeader: type is %d, wanted %d\n",
	//          le32toh(hdr->type), type);
	return (-1);
    }
    return (0);
}

/*
 * Extract a string from an NTLM request and return as ASCII.
 */
char *
ntlmGetString(ntlmhdr * hdr, strhdr * str, int flags)
{
    static char buf[512];
    u_short *s, c;
    char *d, *sc;
    int l, o;

    l = le16toh(str->len);
    o = le32toh(str->offset);

    /* Sanity checks. XXX values arbitrarialy chosen */
    if (l <= 0 || l >= 32 || o >= 256) {
	fprintf(stderr, "ntlmGetString: insane: l:%d o:%d\n", l, o);
	return (NULL);
    }
    if ((flags & 2) == 0) {
	/* UNICODE string */
	s = (u_short *) ((char *) hdr + o);
	d = buf;

	for (l >>= 1; l; s++, l--) {
	    c = le16toh(*s);
	    if (c > 254 || c == '\0' || !isprint(c)) {
		fprintf(stderr, "ntlmGetString: bad uni: %04x\n", c);
		return (NULL);
	    }
	    *d++ = c;
	    fprintf(stderr, "ntlmGetString: conv: '%c'\n", c);
	}

	*d = 0;
    } else {
	/* ASCII string */
	sc = (char *) hdr + o;
	d = buf;

	for (; l; l--) {
	    if (*sc == '\0' || !isprint((int)(unsigned char)*sc)) {
		fprintf(stderr, "ntlmGetString: bad ascii: %04x\n", *sc);
		return (NULL);
	    }
	    *d++ = *sc++;
	}

	*d = 0;
    }

    return (buf);
}

/*
 * Decode the strings in an NTLM authentication request
 */
int
ntlmDecodeAuth(struct ntlm_authenticate *auth, char *buf, size_t size)
{
    char *p, *origbuf;
    int s;

    if (!buf) {
	return 1;
    }
    origbuf = buf;
    if (ntlmCheckHeader(&auth->hdr, NTLM_AUTHENTICATE)) {

	fprintf(stderr, "ntlmDecodeAuth: header check fails\n");
	return -1;
    }
/* only on when you need to debug
 * fprintf(stderr,"ntlmDecodeAuth: size of %d\n", size);
 * fprintf(stderr,"ntlmDecodeAuth: flg %08x\n", auth->flags);
 * fprintf(stderr,"ntlmDecodeAuth: usr o(%d) l(%d)\n", auth->user.offset, auth->user.len);
 */
    if ((p = ntlmGetString(&auth->hdr, &auth->domain, 2)) == NULL)
	p = authenticate_ntlm_domain;
//      fprintf(stderr,"ntlmDecodeAuth: Domain '%s'.\n",p);
    if ((s = strlen(p) + 1) >= size)
	return 1;
    strcpy(buf, p);
//      fprintf(stdout,"ntlmDecodeAuth: Domain '%s'.\n",buf);

    size -= s;
    buf += (s - 1);
    *buf++ = '\\';		/* Using \ is more consistent with MS-proxy */

    p = ntlmGetString(&auth->hdr, &auth->user, 2);
    if ((s = strlen(p) + 1) >= size)
	return 1;
    while (*p)
	*buf++ = (*p++);	//tolower

    *buf++ = '\0';
    size -= s;
//      fprintf(stderr, "ntlmDecodeAuth: user: %s%s\n",origbuf, p);


    return 0;
}


int
main()
{
    char buf[256];
    char user[256], *p, *cleartext;
    struct ntlm_challenge chal;
    int len;
    char *data = NULL;

    setbuf(stdout, NULL);
    while (fgets(buf, 256, stdin) != NULL) {
	user[0] = '\0';		/*no usercode */

	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */
#if defined(NTLMHELPPROTOCOLV3) || !defined(NTLMHELPPROTOCOLV2)
	if (strncasecmp(buf, "YR", 2) == 0) {
	    ntlmMakeChallenge(&chal);
	    len =
		sizeof(chal) - sizeof(chal.pad) +
		le16toh(chal.target.maxlen);
	    data = (char *) base64_encode_bin((char *) &chal, len);
	    printf("TT %s\n", data);
	} else if (strncasecmp(buf, "KK ", 3) == 0) {
	    cleartext = (char *) uudecode(buf + 3);
	    if (!ntlmCheckHeader((ntlmhdr *) cleartext, NTLM_AUTHENTICATE)) {
		if (!ntlmDecodeAuth((struct ntlm_authenticate *) cleartext, user, 256)) {
		    lc(user);
		    printf("AF %s\n", user);
		} else {
		    lc(user);
		    printf("NA invalid credentials%s\n", user);
		}
	    } else {
		lc(user);
		printf("BH wrong packet type!%s\n", user);
	    }
	}
#endif
#ifdef NTLMHELPPROTOCOLV2
/* V2 of the protocol */
	if (strncasecmp(buf, "RESET", 5) == 0) {
	    printf("RESET OK\n");
	} else {
	    cleartext = (char *) uudecode(buf);
	    if (!ntlmCheckHeader((struct ntlmhdr *) cleartext, NTLM_NEGOTIATE)) {
		ntlmMakeChallenge(&chal);
		len =
		    sizeof(chal) - sizeof(chal.pad) +
		    le16toh(chal.target.maxlen);
		data = (char *) base64_encode_bin((char *) &chal, len);
		printf("CH %s\n", data);
	    } else if (!ntlmCheckHeader
		((struct ntlmhdr *) cleartext, NTLM_AUTHENTICATE)) {
		if (!ntlmDecodeAuth
		    ((struct ntlm_authenticate *) cleartext, user, 256)) {
		    lc(user);
		    printf("OK %s\n", user);
		} else {
		    lc(user);
		    printf("ERR %s\n", user);
		}
	    } else {
		lc(user);
		printf("ERR %s\n", user);
	    }
	}
#endif /*v2 */
    }
    exit(0);
}

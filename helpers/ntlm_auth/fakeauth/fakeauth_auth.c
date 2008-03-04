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
 *
 * Revised by Guido Serassio: <guido.serassio@acmeconsulting.it>
 *
 * - Added negotiation of UNICODE char support
 * - More detailed debugging info
 *
 */

#include "config.h"
#include "ntlmauth.h"
#include "squid_endian.h"

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
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "ntlm.h"

#define ERR    "ERR\n"
#define OK     "OK\n"

#define BUFFER_SIZE 10240

const char *authenticate_ntlm_domain = "WORKGROUP";
int debug_enabled = 0;
int NTLM_packet_debug_enabled = 0;

/* NTLM authentication by ad@interlude.eu.org - 07/1999 */
/* XXX this is not done cleanly... */

static void
hex_dump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    if (!data)
	return;

    if (debug_enabled) {
	unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] =
	{0};
	char addrstr[10] =
	{0};
	char hexstr[16 * 3 + 5] =
	{0};
	char charstr[16 * 1 + 5] =
	{0};
	for (n = 1; n <= size; n++) {
	    if (n % 16 == 1) {
		/* store address for this line */
		snprintf(addrstr, sizeof(addrstr), "%.4x",
		    (int) (p - (unsigned char *) data));
	    }
	    c = *p;
	    if (xisalnum(c) == 0) {
		c = '.';
	    }
	    /* store hex str (for left side) */
	    snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
	    strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

	    /* store char str (for right side) */
	    snprintf(bytestr, sizeof(bytestr), "%c", c);
	    strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

	    if (n % 16 == 0) {
		/* line completed */
		fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
		hexstr[0] = 0;
		charstr[0] = 0;
	    } else if (n % 8 == 0) {
		/* half line: add whitespaces */
		strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
		strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
	    }
	    p++;		/* next byte */
	}

	if (strlen(hexstr) > 0) {
	    /* print rest of buffer if not empty */
	    fprintf(stderr, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
    }
}


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
ntlmMakeChallenge(struct ntlm_challenge *chal, int32_t flags)
{
    static unsigned hash;
    int r;
    char *d;
    int i;

    debug("ntlmMakeChallenge: flg %08x\n", flags);

    memset(chal, 0, sizeof(*chal));
    memcpy(chal->hdr.signature, "NTLMSSP", 8);
    chal->flags = htole32(CHALLENGE_TARGET_IS_DOMAIN |
	NEGOTIATE_ALWAYS_SIGN |
	NEGOTIATE_USE_NTLM |
	NEGOTIATE_REQUEST_TARGET |
	(NEGOTIATE_UNICODE & flags ? NEGOTIATE_UNICODE : NEGOTIATE_ASCII)
	);
    chal->hdr.type = htole32(NTLM_CHALLENGE);
    chal->unknown[6] = htole16(0x003a);

    d = (char *) chal + 48;
    i = 0;

    if (authenticate_ntlm_domain != NULL)
	while (authenticate_ntlm_domain[i++]);


    chal->target.offset = htole32(48);
    chal->target.maxlen = htole16(i);
    chal->target.len = chal->target.maxlen;

    r = (int) rand();
    r = (hash ^ r) + r;

    for (i = 0; i < 8; i++) {
	chal->challenge[i] = r;
	r = (r >> 2) ^ r;
    }

    hash = r;
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
    if ((flags & NEGOTIATE_ASCII) == 0) {
	/* UNICODE string */
	s = (u_short *) ((char *) hdr + o);
	d = buf;

	for (l >>= 1; l; s++, l--) {
	    c = le16toh(*s);
	    if (c > 254 || c == '\0') {
		fprintf(stderr, "ntlmGetString: bad uni: %04x\n", c);
		return (NULL);
	    }
	    *d++ = c;
	}

	*d = 0;
    } else {
	/* ASCII/OEM string */
	sc = (char *) hdr + o;
	d = buf;

	for (; l; l--) {
	    if (*sc == '\0' || !xisprint(*sc)) {
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
static int
ntlmDecodeAuth(struct ntlm_authenticate *auth, char *buf, size_t size)
{
    const char *p;
    char *origbuf;
    int s;

    if (!buf) {
	return 1;
    }
    origbuf = buf;
    if (ntlmCheckHeader(&auth->hdr, NTLM_AUTHENTICATE)) {
	fprintf(stderr, "ntlmDecodeAuth: header check fails\n");
	return -1;
    }
    debug("ntlmDecodeAuth: size of %d\n", (int) size);
    debug("ntlmDecodeAuth: flg %08x\n", auth->flags);
    debug("ntlmDecodeAuth: usr o(%d) l(%d)\n", auth->user.offset, auth->user.len);

    if ((p = ntlmGetString(&auth->hdr, &auth->domain, auth->flags)) == NULL)
	p = authenticate_ntlm_domain;

    debug("ntlmDecodeAuth: Domain '%s'.\n", p);

    if ((s = strlen(p) + 1) >= size)
	return 1;
    strcpy(buf, p);

    debug("ntlmDecodeAuth: Domain '%s'.\n", buf);

    size -= s;
    buf += (s - 1);
    *buf++ = '\\';		/* Using \ is more consistent with MS-proxy */

    p = ntlmGetString(&auth->hdr, &auth->user, auth->flags);
    if ((s = strlen(p) + 1) >= size)
	return 1;
    while (*p)
	*buf++ = (*p++);	//tolower

    *buf++ = '\0';
    size -= s;

    debug("ntlmDecodeAuth: user: %s%s\n", origbuf, p);

    return 0;
}


/*
 * options:
 * -d enable debugging.
 * -v enable verbose NTLM packet debugging.
 * -l if specified, changes behavior on failures to last-ditch.
 */
char *my_program_name = NULL;

static void
usage(void)
{
    fprintf(stderr,
	"Usage: %s [-d] [-v] [-h]\n"
	" -d  enable debugging.\n"
	" -v  enable verbose NTLM packet debugging.\n"
	" -h  this message\n\n",
	my_program_name);
}


static void
process_options(int argc, char *argv[])
{
    int opt, had_error = 0;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hdv"))) {
	switch (opt) {
	case 'd':
	    debug_enabled = 1;
	    break;
	case 'v':
	    debug_enabled = 1;
	    NTLM_packet_debug_enabled = 1;
	    break;
	case 'h':
	    usage();
	    exit(0);
	case '?':
	    opt = optopt;
	    /* fall thru to default */
	default:
	    fprintf(stderr, "unknown option: -%c. Exiting\n", opt);
	    usage();
	    had_error = 1;
	}
    }
    if (had_error)
	exit(1);
}


int
main(int argc, char *argv[])
{
    char buf[BUFFER_SIZE];
    int buflen = 0;
    char user[256], *p, *decoded = NULL;
    struct ntlm_challenge chal;
    struct ntlm_negotiate *nego;
    char helper_command[3];
    int len;
    char *data = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    my_program_name = argv[0];

    process_options(argc, argv);

    debug("%s build " __DATE__ ", " __TIME__ " starting up...\n", my_program_name);

    while (fgets(buf, BUFFER_SIZE, stdin) != NULL) {
	user[0] = '\0';		/*no usercode */

	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */
        buflen = strlen(buf);   /* keep this so we only scan the buffer for \0 once per loop */
	if (buflen > 3)
	    decoded = base64_decode(buf + 3);
	if (buflen > 3 && NTLM_packet_debug_enabled) {
	    strncpy(helper_command, buf, 2);
	    helper_command[2] = '\0';
	    debug("Got '%s' from Squid with data:\n", helper_command);
	    hex_dump(decoded, ((strlen(buf) - 3) * 3) / 4);
	} else
	    debug("Got '%s' from Squid\n", buf);

	if (strncasecmp(buf, "YR", 2) == 0) {
	    if(buflen > 3) {
		nego = (struct ntlm_negotiate *) decoded;
		ntlmMakeChallenge(&chal, nego->flags);
	    } else
		ntlmMakeChallenge(&chal, NEGOTIATE_ASCII);
	    len =
		sizeof(chal) - sizeof(chal.pad) +
		le16toh(chal.target.maxlen);
	    data = (char *) base64_encode_bin((char *) &chal, len);
	    if (NTLM_packet_debug_enabled) {
		printf("TT %s\n", data);
		decoded = base64_decode(data);
		debug("sending 'TT' to squid with data:\n");
		hex_dump(decoded, (strlen(data) * 3) / 4);
	    } else
		SEND2("TT %s", data);
	} else if (strncasecmp(buf, "KK ", 3) == 0) {
	    if (!ntlmCheckHeader((ntlmhdr *) decoded, NTLM_AUTHENTICATE)) {
		if (!ntlmDecodeAuth((struct ntlm_authenticate *) decoded, user, 256)) {
		    lc(user);
		    SEND2("AF %s", user);
		} else {
		    lc(user);
		    SEND2("NA invalid credentials, user=%s", user);
		}
	    } else {
		lc(user);
		SEND2("BH wrong packet type! user=%s", user);
	    }
	}
    }
    exit(0);
}

/*
 * digest_pw_auth.c
 *
 * AUTHOR: Robert Collins. Based on ncsa_auth.c by Arjan de Vet
 * <Arjan.deVet@adv.iae.nl>
 *
 * Example digest authentication program for Squid, based on the original
 * proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>.
 *
 * - comment lines are possible and should start with a '#';
 * - empty or blank lines are possible;
 * - file format is username:password
 * 
 * To build a directory integrated backend, you need to be able to
 * calculate the HA1 returned to squid. To avoid storing a plaintext
 * password you can calculate MD5(username:realm:password) when the
 * user changes their password, and store the tuple username:realm:HA1.
 * then find the matching username:realm when squid asks for the
 * HA1.
 *
 * This implementation could be improved by using such a triple for
 * the file format.  However storing such a triple does little to
 * improve security: If compromised the username:realm:HA1 combination
 * is "plaintext equivalent" - for the purposes of digest authentication
 * they allow the user access. Password syncronisation is not tackled
 * by digest - just preventing on the wire compromise.
 *
 */

#include "config.h"
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
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "util.h"
#include "hash.h"
#include "rfc2617.h"

static hash_table *hash = NULL;
static HASHFREE my_free;

typedef struct _user_data {
    hash_link hash;
    char *passwd;
    char *realm;
} user_data;

static void
my_free(void *p)
{
    user_data *u = p;
    xfree(u->hash.key);
    xfree(u->passwd);
    xfree(u);
}

static void
read_passwd_file(const char *passwdfile, int ha1mode)
{
    FILE *f;
    char buf[8192];
    user_data *u;
    char *user;
    char *passwd;
    int passwdha1;

    if (hash != NULL) {
	hashFreeItems(hash, my_free);
    }
    /* initial setup */
    hash = hash_create((HASHCMP *) strcmp, 7921, hash_string);
    if (NULL == hash) {
	fprintf(stderr, "digest_pw_auth: cannot create hash table\n");
	exit(1);
    }
    f = fopen(passwdfile, "r");
    while (fgets(buf, 8192, f) != NULL) {
	if ((buf[0] == '#') || (buf[0] == ' ') || (buf[0] == '\t') ||
	    (buf[0] == '\n'))
	    continue;
	user = strtok(buf, ":\n");
	passwd = strtok(NULL, ":\n");
	if ((strlen(user) > 0) && passwd) {
 	    passwdha1 = (strncmp("{HHA1}", passwd, 6))?0:1;
 	    if (!ha1mode || passwdha1) {
		u = xmalloc(sizeof(*u));
		u->hash.key = xstrdup(user);
		u->passwd = xstrdup(passwd);
		hash_join(hash, &u->hash);
	    } else {
		/* We cannot accept plaintext passwords when using HA1 encoding,
		 * as the passwords may be output to cache.log if debugging is on.
		 */
		fprintf(stderr, "digest_pw_auth: ignoring %s password for %s\n",
			"plaintext", user);
 	    }
  	}
    }
    fclose(f);
}

int
main(int argc, char **argv)
{
    struct stat sb;
    time_t change_time = 0;
    char buf[256];
    char *user, *realm, *p, *passwdfile=NULL;
    user_data *u;
    HASH HA1;
    HASHHEX HHA1;
    int ha1mode=0;

    setbuf(stdout, NULL);
    if(argc == 2){
        passwdfile = argv[1];
    }
    if((argc == 3) && !strcmp("-c", argv[1])){
        ha1mode=1;
        passwdfile = argv[2];
    }
    if (!passwdfile) {
        fprintf(stderr, "Usage: digest_pw_auth [OPTIONS] <passwordfile>\n");
        fprintf(stderr, "  -c   accept HHA1 passwords rather than plaintext in passwordfile\n");
	exit(1);
    }
    if (stat(passwdfile, &sb) != 0) {
	fprintf(stderr, "cannot stat %s\n", passwdfile);
	exit(1);
    }
    while (fgets(buf, 256, stdin) != NULL) {
	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */
	if (stat(passwdfile, &sb) == 0) {
	    if (sb.st_mtime != change_time) {
		read_passwd_file(passwdfile, ha1mode);
		change_time = sb.st_mtime;
	    }
	}
	if (!hash) {
	    printf("ERR\n");
	    continue;
	}
	if ((user = strtok(buf, "\"")) == NULL) {
	    printf("ERR\n");
	    continue;
	}
	if ((realm = strtok(NULL, "\"")) == NULL) {
	    printf("ERR\n");
	    continue;
	}
	if ((realm = strtok(NULL, "\"")) == NULL) {
	    printf("ERR\n");
	    continue;
	}
	u = (user_data *)hash_lookup(hash, user);
	if (u == NULL) {
	    printf("ERR\n");
	} else {

	    if(! ha1mode )
            {
                DigestCalcHA1("md5", user, realm, u->passwd, NULL, NULL, HA1, HHA1);
                printf("%s\n", HHA1);
                /* fprintf(stderr, "digest_pw_auth: %s:{HHA1}%s\n", user, HHA1); */
            }
            else
            {
		printf("%s\n", &u->passwd[6]);
            }
	}
    }
    exit(0);
}

/*
 * text_backend.c
 *
 * AUTHOR: Robert Collins. Based on ncsa_auth.c by Arjan de Vet
 * <Arjan.deVet@adv.iae.nl>
 *
 * Example digest auth text backend for Squid, based on the original
 * proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>.
 *
 * - comment lines are possible and should start with a '#';
 * - empty or blank lines are possible;
 * - file format is username:plaintext or username:realm:HA1
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
 * Copyright (c) 2003  Robert Collins  <robertc@squid-cache.org>
 */

#include "text_backend.h"

static hash_table *hash = NULL;
static HASHFREE my_free;
static char *passwdfile = NULL;
static int ha1mode = 0;
static time_t change_time = 0;

typedef struct _user_data {
    hash_link hash;
    char *passwd;
    char *ha1;
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
    char *ha1 = NULL;
    char *realm;

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
	realm = strtok(NULL, ":\n");
	passwd = strtok(NULL, ":\n");
	if (!passwd) {
	    passwd = realm;
	    realm = NULL;
	}
	if ((strlen(user) > 0) && passwd) {
	    if (strncmp(passwd, "{HHA1}", 6) == 0) {
		ha1 = passwd + 6;
		passwd = NULL;
	    } else if (ha1mode) {
		ha1 = passwd;
		passwd = NULL;
	    }
	    if (ha1 && strlen(ha1) != 32) {
		/* We cannot accept plaintext passwords when using HA1 encoding,
		 * as the passwords may be output to cache.log if debugging is on.
		 */
		fprintf(stderr, "digest_pw_auth: ignoring invalid password for %s\n", user);
		continue;
	    }
	    u = xmalloc(sizeof(*u));
	    if (realm) {
		int len = strlen(user) + strlen(realm) + 2;
		u->hash.key = malloc(len);
		snprintf(u->hash.key, len, "%s:%s", user, realm);
	    } else {
		u->hash.key = xstrdup(user);
	    }
	    if (ha1)
		u->ha1 = xstrdup(ha1);
	    else
		u->passwd = xstrdup(passwd);
	    hash_join(hash, &u->hash);
	}
    }
    fclose(f);
}

/* replace when changing the backend */
void
TextArguments(int argc, char **argv)
{
    struct stat sb;
    if (argc == 2)
	passwdfile = argv[1];
    if ((argc == 3) && !strcmp("-c", argv[1])) {
	ha1mode = 1;
	passwdfile = argv[2];
    }
    if (!passwdfile) {
	fprintf(stderr, "Usage: digest_pw_auth [OPTIONS] <passwordfile>\n");
	fprintf(stderr, "  -c   accept digest hashed passwords rather than plaintext in passwordfile\n");
	exit(1);
    }
    if (stat(passwdfile, &sb) != 0) {
	fprintf(stderr, "cannot stat %s\n", passwdfile);
	exit(1);
    }
}

static const user_data *
GetPassword(RequestData * requestData)
{
    user_data *u;
    struct stat sb;
    char buf[256];
    int len;
    if (stat(passwdfile, &sb) == 0) {
	if (sb.st_mtime != change_time) {
	    read_passwd_file(passwdfile, ha1mode);
	    change_time = sb.st_mtime;
	}
    }
    if (!hash)
	return NULL;
    len = snprintf(buf, sizeof(buf), "%s:%s", requestData->user, requestData->realm);
    if (len >= sizeof(buf))
	return NULL;
    u = (user_data *) hash_lookup(hash, buf);
    if (u)
	return u;
    u = (user_data *) hash_lookup(hash, requestData->user);
    return u;
}

void
TextHHA1(RequestData * requestData)
{
    const user_data *u = GetPassword(requestData);
    if (!u) {
	requestData->error = -1;
	return;
    }
    if (u->ha1) {
	xstrncpy(requestData->HHA1, u->ha1, sizeof(requestData->HHA1));
    } else {
	HASH HA1;
	DigestCalcHA1("md5", requestData->user, requestData->realm, u->passwd, NULL, NULL, HA1, requestData->HHA1);
    }
}

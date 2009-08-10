/*
 * ncsa_auth.c
 *
 * AUTHOR: Arjan de Vet <Arjan.deVet@adv.iae.nl>
 *
 * Example authentication program for Squid, based on the original
 * proxy_auth code from client_side.c, written by
 * Jon Thackray <jrmt@uk.gdscorp.com>.
 *
 * Uses a NCSA httpd style password file for authentication with the
 * following improvements suggested by various people:
 *
 * - comment lines are possible and should start with a '#';
 * - empty or blank lines are possible;
 * - extra fields in the password file are ignored; this makes it
 *   possible to use a Unix password file but I do not recommend that.
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
#include "crypt_md5.h"

static hash_table *hash = NULL;
static HASHFREE my_free;

typedef struct _user_data {
    /* first two items must be same as hash_link */
    char *user;
    struct _user_data *next;
    char *passwd;
} user_data;

static void
my_free(void *p)
{
    user_data *u = p;
    xfree(u->user);
    xfree(u->passwd);
    xfree(u);
}

static void
read_passwd_file(const char *passwdfile)
{
    FILE *f;
    char buf[8192];
    user_data *u;
    char *user;
    char *passwd;
    if (hash != NULL) {
        hashFreeItems(hash, my_free);
        hashFreeMemory(hash);
    }
    /* initial setup */
    hash = hash_create((HASHCMP *) strcmp, 7921, hash_string);
    if (NULL == hash) {
        fprintf(stderr, "ncsa_auth: cannot create hash table\n");
        exit(1);
    }
    f = fopen(passwdfile, "r");
    if (NULL == f) {
        fprintf(stderr, "%s: %s\n", passwdfile, xstrerror());
        exit(1);
    }
    while (fgets(buf, 8192, f) != NULL) {
        if ((buf[0] == '#') || (buf[0] == ' ') || (buf[0] == '\t') ||
                (buf[0] == '\n'))
            continue;
        user = strtok(buf, ":\n\r");
        passwd = strtok(NULL, ":\n\r");
        if ((strlen(user) > 0) && passwd) {
            u = xmalloc(sizeof(*u));
            u->user = xstrdup(user);
            u->passwd = xstrdup(passwd);
            hash_join(hash, (hash_link *) u);
        }
    }
    fclose(f);
}

int
main(int argc, char **argv)
{
    struct stat sb;
    time_t change_time = -1;
    char buf[256];
    char *user, *passwd, *p;
    user_data *u;
    setbuf(stdout, NULL);
    if (argc != 2) {
        fprintf(stderr, "Usage: ncsa_auth <passwordfile>\n");
        exit(1);
    }
    if (stat(argv[1], &sb) != 0) {
        fprintf(stderr, "cannot stat %s\n", argv[1]);
        exit(1);
    }
    while (fgets(buf, 256, stdin) != NULL) {
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';		/* strip \n */
        if (stat(argv[1], &sb) == 0) {
            if (sb.st_mtime != change_time) {
                read_passwd_file(argv[1]);
                change_time = sb.st_mtime;
            }
        }
        if ((user = strtok(buf, " ")) == NULL) {
            printf("ERR\n");
            continue;
        }
        if ((passwd = strtok(NULL, "")) == NULL) {
            printf("ERR\n");
            continue;
        }
        rfc1738_unescape(user);
        rfc1738_unescape(passwd);
        u = (user_data *) hash_lookup(hash, user);
        if (u == NULL) {
            printf("ERR No such user\n");
#if HAVE_CRYPT
        } else if (strcmp(u->passwd, (char *) crypt(passwd, u->passwd)) == 0) {
            printf("OK\n");
#endif
        } else if (strcmp(u->passwd, (char *) crypt_md5(passwd, u->passwd)) == 0) {
            printf("OK\n");
        } else if (strcmp(u->passwd, (char *) md5sum(passwd)) == 0) {	/* md5 without salt and magic strings - Added by Ramon de Carvalho and Rodrigo Rubira Branco */
            printf("OK\n");
        } else {
            printf("ERR Wrong password\n");
        }
    }
    if (hash != NULL) {
        hashFreeItems(hash, my_free);
        hashFreeMemory(hash);
    }
    exit(0);
}

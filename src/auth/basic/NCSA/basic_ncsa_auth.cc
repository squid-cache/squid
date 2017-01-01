/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
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
 *  MD5 without salt and magic strings - Added by Ramon de Carvalho and Rodrigo Rubira Branco
 */

#include "squid.h"
#include "auth/basic/NCSA/crypt_md5.h"
#include "helper/protocol_defines.h"
#include "rfc1738.h"

#include <string>
#include <unordered_map>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

typedef std::unordered_map<std::string, std::string> usermap_t;
usermap_t usermap;

static void
read_passwd_file(const char *passwdfile)
{
    FILE *f;
    char buf[HELPER_INPUT_BUFFER];
    char *user;
    char *passwd;

    usermap.clear();
    //TODO: change to c++ streams
    f = fopen(passwdfile, "r");
    if (!f) {
        int xerrno = errno;
        fprintf(stderr, "FATAL: %s: %s\n", passwdfile, xstrerr(xerrno));
        exit(1);
    }
    unsigned int lineCount = 0;
    buf[HELPER_INPUT_BUFFER-1] = '\0';
    while (fgets(buf, sizeof(buf)-1, f) != NULL) {
        ++lineCount;
        if ((buf[0] == '#') || (buf[0] == ' ') || (buf[0] == '\t') ||
                (buf[0] == '\n'))
            continue;
        user = strtok(buf, ":\n\r");
        if (user == NULL) {
            fprintf(stderr, "ERROR: Missing user name at %s line %d\n", passwdfile, lineCount);
            continue;
        }
        passwd = strtok(NULL, ":\n\r");
        if ((strlen(user) > 0) && passwd) {
            usermap[user] = passwd;
        }
    }
    fclose(f);
}

int
main(int argc, char **argv)
{
    struct stat sb;
    time_t change_time = -1;
    char buf[HELPER_INPUT_BUFFER];
    char *user, *passwd, *p;
    setbuf(stdout, NULL);
    if (argc != 2) {
        fprintf(stderr, "Usage: ncsa_auth <passwordfile>\n");
        exit(1);
    }
    if (stat(argv[1], &sb) != 0) {
        fprintf(stderr, "FATAL: cannot stat %s\n", argv[1]);
        exit(1);
    }
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';      /* strip \n */
        if (stat(argv[1], &sb) == 0) {
            if (sb.st_mtime != change_time) {
                read_passwd_file(argv[1]);
                change_time = sb.st_mtime;
            }
        }
        if ((user = strtok(buf, " ")) == NULL) {
            SEND_ERR("");
            continue;
        }
        if ((passwd = strtok(NULL, "")) == NULL) {
            SEND_ERR("");
            continue;
        }
        rfc1738_unescape(user);
        rfc1738_unescape(passwd);
        const auto userpassIterator = usermap.find(user);
        if (userpassIterator == usermap.end()) {
            SEND_ERR("No such user");
            continue;
        }
        std::string stored_pass = userpassIterator->second;
        const char *salted = stored_pass.c_str(); // locally stored version contains salt etc.

        char *crypted = NULL;
#if HAVE_CRYPT
        size_t passwordLength = strlen(passwd);
        // Bug 3831: given algorithms more secure than DES crypt() does not truncate, so we can ignore the bug 3107 length checks below
        // '$1$' = MD5, '$2a$' = Blowfish, '$5$' = SHA256 (Linux), '$6$' = SHA256 (BSD) and SHA512
        if (passwordLength > 1 && salted[0] == '$' &&
                (crypted = crypt(passwd, salted)) && stored_pass == crypted) {
            SEND_OK("");
            continue;
        }
        // 'other' prefixes indicate DES algorithm.
        if (passwordLength <= 8 && (crypted = crypt(passwd, salted)) && stored_pass == crypted) {
            SEND_OK("");
            continue;
        }
        if (passwordLength > 8 && (crypted = crypt(passwd, salted)) && stored_pass == crypted) {
            // Bug 3107: crypt() DES functionality silently truncates long passwords.
            SEND_ERR("Password too long. Only 8 characters accepted.");
            continue;
        }

#endif
        if ( (crypted = crypt_md5(passwd, salted)) && stored_pass == crypted) {
            SEND_OK("");
            continue;
        }
        if ( (crypted = md5sum(passwd)) && stored_pass == crypted) {
            SEND_OK("");
            continue;
        }
        SEND_ERR("Wrong password");
    }
    exit(0);
}


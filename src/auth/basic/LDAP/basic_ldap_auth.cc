/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * squid_ldap_auth: authentication via ldap for squid proxy server
 *
 * Authors:
 * Henrik Nordstrom
 * hno@squid-cache.org
 *
 * Glen Newton
 * glen.newton@nrc.ca
 * Advanced Services
 * CISTI
 * National Research Council
 *
 * with contributions from others mentioned in the Changes section below
 *
 * Usage: squid_ldap_auth -b basedn [-s searchscope]
 *                        [-f searchfilter] [-D binddn -w bindpasswd]
 *                        [-u attr] [-h host] [-p port] [-P] [-R] [ldap_server_name[:port]] ...
 *
 * Dependencies: You need to get the OpenLDAP libraries
 * from http://www.openldap.org or another compatible LDAP C-API
 * implementation.
 *
 * If you want to make a TLS enabled connection you will also need the
 * OpenSSL libraries linked into openldap. See http://www.openssl.org/
 *
 * License: squid_ldap_auth is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * Changes:
 * 2019-01-02: Amish
 *             - Use SEND_*() macro and support for BH error
 * 2005-01-07: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added some sanity checks on login names to avoid
 *               users bypassing equality checks by exploring the
 *               overly helpful match capabilities of LDAP
 * 2004-07-17: Henrik Nordstrom <hno@squid-cache.org>
 *             - Corrected non-persistent mode to only issue one
 *               ldap_bind per connection.
 *             - -U option to compare the users password rather
 *               than binding.
 * 2004-03-01: Henrik Nordstrom <hno@squid-cache.org>
 *             - corrected building of search filters to escape
 *               unsafe input
 *             - -d option for "debug" like squid_ldap_group
 * 2004-01-05: Henrik Nordstrom <hno@squid-cache.org>
 *             - Corrected TLS mode
 * 2003-03-01: David J N Begley
 *             - Support for Netscape API method of ldap over SSL
 *               connections
 *             - Timeout option for better recovery when using
 *               multiple LDAP servers
 * 2003-03-01: Christoph Lechleitner <lech@ibcl.at>
 *             - Added -W option to read bindpasswd from file
 * 2003-03-01: Juerg Michel
 *             - Added support for ldap URI via the -H option
 *               (requires OpenLDAP)
 * 2001-12-12: Michael Cunningham <m.cunningham@xpedite.com>
 *             - Added TLS support and partial ldap version 3 support.
 * 2001-10-04: Henrik Nordstrom <hno@squid-cache.org>
 *             - Be consistent with the other helpers in how
 *               spaces are managed. If there is space characters
 *               then these are assumed to be part of the password
 * 2001-09-05: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added ability to specify another default LDAP port to
 *               connect to. Persistent connections moved to -P
 * 2001-05-02: Henrik Nordstrom <hno@squid-cache.org>
 *             - Support newer OpenLDAP 2.x libraries using the
 *               revised Internet Draft API which unfortunately
 *               is not backwards compatible with RFC1823..
 * 2001-04-15: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added command line option for basedn
 *             - Added the ability to search for the user DN
 * 2001-04-16: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added -D binddn -w bindpasswd.
 * 2001-04-17: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added -R to disable referrals
 *             - Added -a to control alias dereferencing
 * 2001-04-17: Henrik Nordstrom <hno@squid-cache.org>
 *             - Added -u, DN username attribute name
 * 2001-04-18: Henrik Nordstrom <hno@squid-cache.org>
 *             - Allow full filter specifications in -f
 */

#include "squid.h"
#include "helper/protocol_defines.h"

#define LDAP_DEPRECATED 1

#include "rfc1738.h"
#include "util.h"

#include <cctype>
#include <cstring>

#if _SQUID_WINDOWS_ && !_SQUID_CYGWIN_
#define snprintf _snprintf
#include <windows.h>
#include <winldap.h>
#ifndef LDAPAPI
#define LDAPAPI __cdecl
#endif
#ifdef LDAP_VERSION3
#ifndef LDAP_OPT_X_TLS
#define LDAP_OPT_X_TLS 0x6000
#endif
/* Some tricks to allow dynamic bind with ldap_start_tls_s entry point at
 * run time.
 */
#undef ldap_start_tls_s
#if LDAP_UNICODE
#define LDAP_START_TLS_S "ldap_start_tls_sW"
typedef WINLDAPAPI ULONG(LDAPAPI * PFldap_start_tls_s) (IN PLDAP, OUT PULONG, OUT LDAPMessage **, IN PLDAPControlW *, IN PLDAPControlW *);
#else
#define LDAP_START_TLS_S "ldap_start_tls_sA"
typedef WINLDAPAPI ULONG(LDAPAPI * PFldap_start_tls_s) (IN PLDAP, OUT PULONG, OUT LDAPMessage **, IN PLDAPControlA *, IN PLDAPControlA *);
#endif /* LDAP_UNICODE */
PFldap_start_tls_s Win32_ldap_start_tls_s;
#define ldap_start_tls_s(l,s,c) Win32_ldap_start_tls_s(l,NULL,NULL,s,c)
#endif /* LDAP_VERSION3 */

#else

#include <lber.h>
#include <ldap.h>

#ifndef LDAP_SECURITY_ERROR
#define LDAP_SECURITY_ERROR(err) (0x2f <= (err) && (err) <= 0x32) // [47, 50]
#endif

#endif

#define PROGRAM_NAME "basic_ldap_auth"

/* Global options */
static const char *basedn;
static const char *searchfilter = nullptr;
static const char *binddn = nullptr;
static const char *bindpasswd = nullptr;
static const char *userattr = "uid";
static const char *passwdattr = nullptr;
static int searchscope = LDAP_SCOPE_SUBTREE;
static int persistent = 0;
static int bind_once = 0;
static int noreferrals = 0;
static int aliasderef = LDAP_DEREF_NEVER;
#if defined(NETSCAPE_SSL)
static const char *sslpath = NULL;
static int sslinit = 0;
#endif
static int connect_timeout = 0;
static int timelimit = LDAP_NO_LIMIT;

/* Added for TLS support and version 3 */
static int use_tls = 0;
static int version = -1;

static int checkLDAP(LDAP * ld, const char *userid, const char *password, const char *server, int port);
static int readSecret(const char *filename);

/* Yuck.. we need to glue to different versions of the API */

#ifndef LDAP_NO_ATTRS
#define LDAP_NO_ATTRS "1.1"
#endif

#if defined(LDAP_API_VERSION) && LDAP_API_VERSION > 1823
static int
squid_ldap_errno(LDAP * ld)
{
    int err = 0;
    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
    return err;
}
static void
squid_ldap_set_aliasderef(LDAP * ld, int deref)
{
    ldap_set_option(ld, LDAP_OPT_DEREF, &deref);
}
static void
squid_ldap_set_referrals(LDAP * ld, int referrals)
{
    int *value = static_cast<int*>(referrals ? LDAP_OPT_ON :LDAP_OPT_OFF);
    ldap_set_option(ld, LDAP_OPT_REFERRALS, value);
}
static void
squid_ldap_set_timelimit(LDAP * ld, int aTimeLimit)
{
    ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &aTimeLimit);
}
static void
squid_ldap_set_connect_timeout(LDAP * ld, int aTimeLimit)
{
#if defined(LDAP_OPT_NETWORK_TIMEOUT)
    struct timeval tv;
    tv.tv_sec = aTimeLimit;
    tv.tv_usec = 0;
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#elif defined(LDAP_X_OPT_CONNECT_TIMEOUT)
    aTimeLimit *= 1000;
    ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT, &aTimeLimit);
#endif
}
static void
squid_ldap_memfree(char *p)
{
    ldap_memfree(p);
}

#else
static int
squid_ldap_errno(LDAP * ld)
{
    return ld->ld_errno;
}
static void
squid_ldap_set_aliasderef(LDAP * ld, int deref)
{
    ld->ld_deref = deref;
}
static void
squid_ldap_set_referrals(LDAP * ld, int referrals)
{
    if (referrals)
        ld->ld_options |= ~LDAP_OPT_REFERRALS;
    else
        ld->ld_options &= ~LDAP_OPT_REFERRALS;
}
static void
squid_ldap_set_timelimit(LDAP * ld, int timelimit)
{
    ld->ld_timelimit = timelimit;
}
static void
squid_ldap_set_connect_timeout(LDAP * ld, int timelimit)
{
    fprintf(stderr, "Connect timeouts not supported in your LDAP library\n");
}
static void
squid_ldap_memfree(char *p)
{
    free(p);
}

#endif

#ifdef LDAP_API_FEATURE_X_OPENLDAP
#if LDAP_VENDOR_VERSION > 194
#define HAS_URI_SUPPORT 1
#endif
#endif

static LDAP *
open_ldap_connection(const char *ldapServer, int port)
{
    LDAP *ld = nullptr;
#if HAS_URI_SUPPORT
    if (strstr(ldapServer, "://") != nullptr) {
        int rc = ldap_initialize(&ld, ldapServer);
        if (rc != LDAP_SUCCESS) {
            fprintf(stderr, "\nUnable to connect to LDAPURI:%s\n", ldapServer);
            exit(EXIT_FAILURE);
        }
    } else
#endif
#if NETSCAPE_SSL
        if (sslpath) {
            if (!sslinit && (ldapssl_client_init(sslpath, NULL) != LDAP_SUCCESS)) {
                fprintf(stderr, "\nUnable to initialise SSL with cert path %s\n",
                        sslpath);
                exit(EXIT_FAILURE);
            } else {
                ++sslinit;
            }
            if ((ld = ldapssl_init(ldapServer, port, 1)) == NULL) {
                fprintf(stderr, "\nUnable to connect to SSL LDAP server: %s port:%d\n",
                        ldapServer, port);
                exit(EXIT_FAILURE);
            }
        } else
#endif
            if ((ld = ldap_init(ldapServer, port)) == nullptr) {
                fprintf(stderr, "\nUnable to connect to LDAP server:%s port:%d\n",
                        ldapServer, port);
                exit(EXIT_FAILURE);
            }
    if (connect_timeout)
        squid_ldap_set_connect_timeout(ld, connect_timeout);

#ifdef LDAP_VERSION3
    if (version == -1) {
        version = LDAP_VERSION3;
    }
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
        fprintf(stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
                version);
        exit(EXIT_FAILURE);
    }
    if (use_tls) {
#ifdef LDAP_OPT_X_TLS
        if (version != LDAP_VERSION3) {
            fprintf(stderr, "TLS requires LDAP version 3\n");
            exit(EXIT_FAILURE);
        } else if (ldap_start_tls_s(ld, nullptr, nullptr) != LDAP_SUCCESS) {
            fprintf(stderr, "Could not Activate TLS connection\n");
            exit(EXIT_FAILURE);
        }
#else
        fprintf(stderr, "TLS not supported with your LDAP library\n");
        exit(EXIT_FAILURE);
#endif
    }
#endif
    squid_ldap_set_timelimit(ld, timelimit);
    squid_ldap_set_referrals(ld, !noreferrals);
    squid_ldap_set_aliasderef(ld, aliasderef);
    return ld;
}

/* Make a sanity check on the username to reject oddly typed names */
static int
validUsername(const char *user)
{
    const unsigned char *p = (const unsigned char *) user;

    /* Leading whitespace? */
    if (xisspace(p[0]))
        return 0;
    while (p[0] && p[1]) {
        if (xisspace(p[0])) {
            /* More than one consequitive space? */
            if (xisspace(p[1]))
                return 0;
            /* or odd space type character used? */
            if (p[0] != ' ')
                return 0;
        }
        ++p;
    }
    /* Trailing whitespace? */
    if (xisspace(p[0]))
        return 0;
    return 1;
}

int
main(int argc, char **argv)
{
    char buf[1024];
    char *user, *passwd;
    char *ldapServer = nullptr;
    LDAP *ld = nullptr;
    int tryagain;
    int port = LDAP_PORT;

    setbuf(stdout, nullptr);

    while (argc > 1 && argv[1][0] == '-') {
        const char *value = "";
        char option = argv[1][1];
        switch (option) {
        case 'P':
        case 'R':
        case 'z':
        case 'Z':
        case 'd':
        case 'O':
            break;
        default:
            if (strlen(argv[1]) > 2) {
                value = argv[1] + 2;
            } else if (argc > 2) {
                value = argv[2];
                ++argv;
                --argc;
            } else
                value = "";
            break;
        }
        ++argv;
        --argc;
        switch (option) {
        case 'H':
#if !HAS_URI_SUPPORT
            fprintf(stderr, "ERROR: Your LDAP library does not have URI support\n");
            exit(EXIT_FAILURE);
#endif
        /* Fall thru to -h */
        case 'h':
            if (ldapServer) {
                int len = strlen(ldapServer) + 1 + strlen(value) + 1;
                char *newhost = static_cast<char*>(xmalloc(len));
                snprintf(newhost, len, "%s %s", ldapServer, value);
                free(ldapServer);
                ldapServer = newhost;
            } else {
                ldapServer = xstrdup(value);
            }
            break;
        case 'b':
            basedn = value;
            break;
        case 'f':
            searchfilter = value;
            break;
        case 'u':
            userattr = value;
            break;
        case 'U':
            passwdattr = value;
            break;
        case 's':
            if (strcmp(value, "base") == 0)
                searchscope = LDAP_SCOPE_BASE;
            else if (strcmp(value, "one") == 0)
                searchscope = LDAP_SCOPE_ONELEVEL;
            else if (strcmp(value, "sub") == 0)
                searchscope = LDAP_SCOPE_SUBTREE;
            else {
                fprintf(stderr, PROGRAM_NAME ": ERROR: Unknown search scope '%s'\n", value);
                exit(EXIT_FAILURE);
            }
            break;
        case 'E':
#if defined(NETSCAPE_SSL)
            sslpath = value;
            if (port == LDAP_PORT)
                port = LDAPS_PORT;
#else
            fprintf(stderr, PROGRAM_NAME " ERROR: -E unsupported with this LDAP library\n");
            exit(EXIT_FAILURE);
#endif
            break;
        case 'c':
            connect_timeout = atoi(value);
            break;
        case 't':
            timelimit = atoi(value);
            break;
        case 'a':
            if (strcmp(value, "never") == 0)
                aliasderef = LDAP_DEREF_NEVER;
            else if (strcmp(value, "always") == 0)
                aliasderef = LDAP_DEREF_ALWAYS;
            else if (strcmp(value, "search") == 0)
                aliasderef = LDAP_DEREF_SEARCHING;
            else if (strcmp(value, "find") == 0)
                aliasderef = LDAP_DEREF_FINDING;
            else {
                fprintf(stderr, PROGRAM_NAME ": ERROR: Unknown alias dereference method '%s'\n", value);
                exit(EXIT_FAILURE);
            }
            break;
        case 'D':
            binddn = value;
            break;
        case 'w':
            bindpasswd = value;
            break;
        case 'W':
            readSecret(value);
            break;
        case 'P':
            persistent = !persistent;
            break;
        case 'O':
            bind_once = !bind_once;
            break;
        case 'p':
            port = atoi(value);
            break;
        case 'R':
            noreferrals = !noreferrals;
            break;
#ifdef LDAP_VERSION3
        case 'v':
            switch (atoi(value)) {
            case 2:
                version = LDAP_VERSION2;
                break;
            case 3:
                version = LDAP_VERSION3;
                break;
            default:
                fprintf(stderr, "Protocol version should be 2 or 3\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'Z':
            if (version == LDAP_VERSION2) {
                fprintf(stderr, "TLS (-Z) is incompatible with version %d\n",
                        version);
                exit(EXIT_FAILURE);
            }
            version = LDAP_VERSION3;
            use_tls = 1;
            break;
#endif
        case 'd':
            debug_enabled = 1;
            break;
        default:
            fprintf(stderr, PROGRAM_NAME ": ERROR: Unknown command line option '%c'\n", option);
            exit(EXIT_FAILURE);
        }
    }

    while (argc > 1) {
        char *value = argv[1];
        if (ldapServer) {
            int len = strlen(ldapServer) + 1 + strlen(value) + 1;
            char *newhost = static_cast<char*>(xmalloc(len));
            snprintf(newhost, len, "%s %s", ldapServer, value);
            free(ldapServer);
            ldapServer = newhost;
        } else {
            ldapServer = xstrdup(value);
        }
        --argc;
        ++argv;
    }
    if (!ldapServer)
        ldapServer = xstrdup("localhost");

    if (!basedn) {
        fprintf(stderr, "Usage: " PROGRAM_NAME " -b basedn [options] [ldap_server_name[:port]]...\n\n");
        fprintf(stderr, "\t-b basedn (REQUIRED)\tbase dn under which to search\n");
        fprintf(stderr, "\t-f filter\t\tsearch filter to locate user DN\n");
        fprintf(stderr, "\t-u userattr\t\tusername DN attribute\n");
        fprintf(stderr, "\t-s base|one|sub\t\tsearch scope\n");
        fprintf(stderr, "\t-D binddn\t\tDN to bind as to perform searches\n");
        fprintf(stderr, "\t-w bindpasswd\t\tpassword for binddn\n");
        fprintf(stderr, "\t-W secretfile\t\tread password for binddn from file secretfile\n");
#if HAS_URI_SUPPORT
        fprintf(stderr, "\t-H URI\t\t\tLDAPURI (defaults to ldap://localhost)\n");
#endif
        fprintf(stderr, "\t-h server\t\tLDAP server (defaults to localhost)\n");
        fprintf(stderr, "\t-p port\t\t\tLDAP server port\n");
        fprintf(stderr, "\t-P\t\t\tpersistent LDAP connection\n");
#if defined(NETSCAPE_SSL)
        fprintf(stderr, "\t-E sslcertpath\t\tenable LDAP over SSL\n");
#endif
        fprintf(stderr, "\t-c timeout\t\tconnect timeout\n");
        fprintf(stderr, "\t-t timelimit\t\tsearch time limit\n");
        fprintf(stderr, "\t-R\t\t\tdo not follow referrals\n");
        fprintf(stderr, "\t-a never|always|search|find\n\t\t\t\twhen to dereference aliases\n");
#ifdef LDAP_VERSION3
        fprintf(stderr, "\t-v 2|3\t\t\tLDAP version\n");
        fprintf(stderr, "\t-Z\t\t\tTLS encrypt the LDAP connection, requires LDAP version 3\n");
#endif
        fprintf(stderr, "\t-d\t\t\tenable debug mode\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "\tIf no search filter is specified, then the dn <userattr>=user,basedn\n\twill be used (same as specifying a search filter of '<userattr>=',\n\tbut quicker as as there is no need to search for the user DN)\n\n");
        fprintf(stderr, "\tIf you need to bind as a user to perform searches then use the\n\t-D binddn -w bindpasswd or -D binddn -W secretfile options\n\n");
        exit(EXIT_FAILURE);
    }
    /* On Windows ldap_start_tls_s is available starting from Windows XP,
     * so we need to bind at run-time with the function entry point
     */
#if _SQUID_WINDOWS_
    if (use_tls) {

        HMODULE WLDAP32Handle;

        WLDAP32Handle = GetModuleHandle("wldap32");
        if ((Win32_ldap_start_tls_s = (PFldap_start_tls_s) GetProcAddress(WLDAP32Handle, LDAP_START_TLS_S)) == NULL) {
            fprintf(stderr, PROGRAM_NAME ": ERROR: TLS (-Z) not supported on this platform.\n");
            exit(EXIT_FAILURE);
        }
    }
#endif

    while (fgets(buf, sizeof(buf), stdin) != nullptr) {
        user = strtok(buf, " \r\n");
        passwd = strtok(nullptr, "\r\n");

        if (!user) {
            SEND_ERR(HLP_MSG("Missing username"));
            continue;
        }
        if (!passwd || !passwd[0]) {
            SEND_ERR(HLP_MSG("Missing password"));
            continue;
        }
        rfc1738_unescape(user);
        rfc1738_unescape(passwd);
        if (!validUsername(user)) {
            SEND_ERR(HLP_MSG("Invalid username"));
            continue;
        }
        tryagain = (ld != nullptr);
recover:
        if (ld == nullptr && persistent)
            ld = open_ldap_connection(ldapServer, port);
        if (checkLDAP(ld, user, passwd, ldapServer, port) != 0) {
            const auto e = squid_ldap_errno(ld);
            if (tryagain && e != LDAP_INVALID_CREDENTIALS) {
                tryagain = 0;
                ldap_unbind(ld);
                ld = nullptr;
                goto recover;
            }
            if (LDAP_SECURITY_ERROR(e))
                SEND_ERR(ldap_err2string(e));
            else
                SEND_BH(ldap_err2string(e));
        } else {
            SEND_OK("");
        }
        if (ld && (squid_ldap_errno(ld) != LDAP_SUCCESS && squid_ldap_errno(ld) != LDAP_INVALID_CREDENTIALS)) {
            ldap_unbind(ld);
            ld = nullptr;
        }
    }
    if (ld)
        ldap_unbind(ld);
    return EXIT_SUCCESS;
}

static int
ldap_escape_value(char *escaped, int size, const char *src)
{
    int n = 0;
    while (size > 4 && *src) {
        switch (*src) {
        case '*':
        case '(':
        case ')':
        case '\\':
            n += 3;
            size -= 3;
            if (size > 0) {
                *escaped = '\\';
                ++escaped;
                snprintf(escaped, 3, "%02x", (unsigned char) *src);
                ++src;
                escaped += 2;
            }
            break;
        default:
            *escaped = *src;
            ++escaped;
            ++src;
            ++n;
            --size;
        }
    }
    *escaped = '\0';
    return n;
}

/* Check the userid & password.
 * Return 0 on success, 1 on failure
 */
static int
checkLDAP(LDAP * persistent_ld, const char *userid, const char *password, const char *ldapServer, int port)
{
    char dn[1024];
    int ret = 0;
    LDAP *bind_ld = nullptr;

    if (!*password) {
        /* LDAP can't bind with a blank password. Seen as "anonymous"
         * and always granted access
         */
        debug("Blank password given\n");
        return 1;
    }
    if (searchfilter) {
        char filter[16384];
        char escaped_login[1024];
        LDAPMessage *res = nullptr;
        LDAPMessage *entry;
        char *searchattr[] = {(char *)LDAP_NO_ATTRS, nullptr};
        char *userdn;
        int rc;
        LDAP *search_ld = persistent_ld;

        if (!search_ld)
            search_ld = open_ldap_connection(ldapServer, port);

        ldap_escape_value(escaped_login, sizeof(escaped_login), userid);
        if (binddn) {
            rc = ldap_simple_bind_s(search_ld, binddn, bindpasswd);
            if (rc != LDAP_SUCCESS) {
                fprintf(stderr, PROGRAM_NAME ": WARNING, could not bind to binddn '%s'\n", ldap_err2string(rc));
                ret = 1;
                goto search_done;
            }
        }
        snprintf(filter, sizeof(filter), searchfilter, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login);
        debug("user filter '%s', searchbase '%s'\n", filter, basedn);
        rc = ldap_search_s(search_ld, basedn, searchscope, filter, searchattr, 1, &res);
        if (rc != LDAP_SUCCESS) {
            if (noreferrals && rc == LDAP_PARTIAL_RESULTS) {
                /* Everything is fine. This is expected when referrals
                 * are disabled.
                 */
                debug("noreferrals && rc == LDAP_PARTIAL_RESULTS\n");
            } else {
                fprintf(stderr, PROGRAM_NAME ": WARNING, LDAP search error '%s'\n", ldap_err2string(rc));
#if defined(NETSCAPE_SSL)
                if (sslpath && ((rc == LDAP_SERVER_DOWN) || (rc == LDAP_CONNECT_ERROR))) {
                    int sslerr = PORT_GetError();
                    fprintf(stderr, PROGRAM_NAME ": WARNING, SSL error %d (%s)\n", sslerr, ldapssl_err2string(sslerr));
                }
#endif
                ret = 1;
                goto search_done;
            }
        }
        entry = ldap_first_entry(search_ld, res);
        if (!entry) {
            debug("Ldap search returned nothing\n");
            ret = 1;
            goto search_done;
        }
        userdn = ldap_get_dn(search_ld, entry);
        if (!userdn) {
            fprintf(stderr, PROGRAM_NAME ": ERROR, could not get user DN for '%s'\n", userid);
            ret = 1;
            goto search_done;
        }
        snprintf(dn, sizeof(dn), "%s", userdn);
        squid_ldap_memfree(userdn);

        if (ret == 0 && (!binddn || !bind_once || passwdattr)) {
            /* Reuse the search connection for comparing the user password attribute */
            bind_ld = search_ld;
            search_ld = nullptr;
        }
search_done:
        if (res) {
            ldap_msgfree(res);
            res = nullptr;
        }
        if (search_ld && search_ld != persistent_ld) {
            ldap_unbind(search_ld);
            search_ld = nullptr;
        }
        if (ret != 0)
            return ret;
    } else {
        snprintf(dn, sizeof(dn), "%s=%s,%s", userattr, userid, basedn);
    }

    debug("attempting to authenticate user '%s'\n", dn);
    if (!bind_ld && !bind_once)
        bind_ld = persistent_ld;
    if (!bind_ld)
        bind_ld = open_ldap_connection(ldapServer, port);
    if (passwdattr) {
        if (ldap_compare_s(bind_ld, dn, passwdattr, password) != LDAP_COMPARE_TRUE) {
            ret = 1;
        }
    } else if (ldap_simple_bind_s(bind_ld, dn, password) != LDAP_SUCCESS)
        ret = 1;
    if (bind_ld != persistent_ld) {
        ldap_unbind(bind_ld);
        bind_ld = nullptr;
    }
    return ret;
}

int
readSecret(const char *filename)
{
    char buf[BUFSIZ];
    char *e = nullptr;
    FILE *f;
    char *passwd = nullptr;

    if (!(f = fopen(filename, "r"))) {
        fprintf(stderr, PROGRAM_NAME " ERROR: Can not read secret file %s\n", filename);
        return 1;
    }
    if (!fgets(buf, sizeof(buf) - 1, f)) {
        fprintf(stderr, PROGRAM_NAME " ERROR: Secret file %s is empty\n", filename);
        fclose(f);
        return 1;
    }
    /* strip whitespaces on end */
    if ((e = strrchr(buf, '\n')))
        *e = 0;
    if ((e = strrchr(buf, '\r')))
        *e = 0;

    passwd = (char *) calloc(sizeof(char), strlen(buf) + 1);
    if (!passwd) {
        fprintf(stderr, PROGRAM_NAME " ERROR: can not allocate memory\n");
        exit(EXIT_FAILURE);
    }
    strcpy(passwd, buf);
    bindpasswd = passwd;

    fclose(f);

    return 0;
}


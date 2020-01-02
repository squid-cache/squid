/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Flavio Pescuma, MARA Systems AB <flavio@marasystems.com>
 */

#include "squid.h"
#include "util.h"

#define LDAP_DEPRECATED 1

#include "auth/digest/LDAP/ldap_backend.h"

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

#endif
#define PROGRAM_NAME "digest_pw_auth(LDAP_backend)"

/* Globals */

static LDAP *ld = NULL;
static const char *passattr = NULL;
static char *ldapServer = NULL;
static const char *userbasedn = NULL;
static const char *userdnattr = NULL;
static const char *usersearchfilter = NULL;
static const char *binddn = NULL;
static const char *bindpasswd = NULL;
static const char *delimiter = ":";
static const char *frealm = "";
static int encrpass = 0;
static int searchscope = LDAP_SCOPE_SUBTREE;
static int persistent = 0;
static int noreferrals = 0;
static int port = LDAP_PORT;
static int strip_nt_domain = 0;
static int aliasderef = LDAP_DEREF_NEVER;
#if defined(NETSCAPE_SSL)
static char *sslpath = NULL;
static int sslinit = 0;
#endif
static int connect_timeout = 0;
static int timelimit = LDAP_NO_LIMIT;

#ifdef LDAP_VERSION3
/* Added for TLS support and version 3 */
static int use_tls = 0;
static int version = -1;
#endif

static void ldapconnect(void);
static int readSecret(const char *filename);

/* Yuck.. we need to glue to different versions of the API */

#if defined(LDAP_API_VERSION) && LDAP_API_VERSION > 1823
static void
squid_ldap_set_aliasderef(int deref)
{
    ldap_set_option(ld, LDAP_OPT_DEREF, &deref);
}
static void
squid_ldap_set_referrals(int referrals)
{
    int *value = static_cast<int*>(referrals ? LDAP_OPT_ON :LDAP_OPT_OFF);
    ldap_set_option(ld, LDAP_OPT_REFERRALS, value);
}
static void
squid_ldap_set_timelimit(int aTimeLimit)
{
    ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &aTimeLimit);
}
static void
squid_ldap_set_connect_timeout(int aTimeLimit)
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

#else
static int
squid_ldap_errno(LDAP * ld)
{
    return ld->ld_errno;
}
static void
squid_ldap_set_aliasderef(int deref)
{
    ld->ld_deref = deref;
}
static void
squid_ldap_set_referrals(int referrals)
{
    if (referrals)
        ld->ld_options |= ~LDAP_OPT_REFERRALS;
    else
        ld->ld_options &= ~LDAP_OPT_REFERRALS;
}
static void
squid_ldap_set_timelimit(int aTimeLimit)
{
    ld->ld_timelimit = aTimeLimit;
}
static void
squid_ldap_set_connect_timeout(int aTimeLimit)
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
                snprintf(escaped, 3, "%02x", (int) *src);
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

static char *
getpassword(char *login, char *realm)
{
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    char **values = NULL;
    char **value = NULL;
    char *password = NULL;
    int retry = 0;
    char filter[8192];
    char searchbase[8192];
    int rc = -1;
    if (ld) {
        if (usersearchfilter) {
            char escaped_login[1024];
            snprintf(searchbase, sizeof(searchbase), "%s", userbasedn);
            ldap_escape_value(escaped_login, sizeof(escaped_login), login);
            snprintf(filter, sizeof(filter), usersearchfilter, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login, escaped_login);

retrysrch:
            debug("user filter '%s', searchbase '%s'\n", filter, searchbase);

            rc = ldap_search_s(ld, searchbase, searchscope, filter, NULL, 0, &res);
            if (rc != LDAP_SUCCESS) {
                if (noreferrals && rc == LDAP_PARTIAL_RESULTS) {
                    /* Everything is fine. This is expected when referrals
                     * are disabled.
                     */
                    rc = LDAP_SUCCESS;
                } else {
                    fprintf(stderr, PROGRAM_NAME " WARNING, LDAP search error '%s'\n", ldap_err2string(rc));
#if defined(NETSCAPE_SSL)
                    if (sslpath && ((rc == LDAP_SERVER_DOWN) || (rc == LDAP_CONNECT_ERROR))) {
                        int sslerr = PORT_GetError();
                        fprintf(stderr, PROGRAM_NAME ": WARNING, SSL error %d (%s)\n", sslerr, ldapssl_err2string(sslerr));
                    }
#endif
                    fprintf(stderr, PROGRAM_NAME " WARNING, LDAP search error, trying to recover'%s'\n", ldap_err2string(rc));
                    ldap_msgfree(res);
                    /* try to connect to the LDAP server agin, maybe my persisten conexion failed. */
                    if (!retry) {
                        ++retry;
                        ldap_unbind(ld);
                        ld = NULL;
                        ldapconnect();
                        goto retrysrch;
                    }
                    return NULL;

                }
            }
        } else if (userdnattr) {
            snprintf(filter,8192,"%s=%s",userdnattr,login);

retrydnattr:
            debug("searchbase '%s'\n", userbasedn);
            rc = ldap_search_s(ld, userbasedn, searchscope, filter, NULL, 0, &res);
        }
        if (rc == LDAP_SUCCESS) {
            entry = ldap_first_entry(ld, res);
            if (entry)
                values = ldap_get_values(ld, entry, passattr);
            else {
                ldap_msgfree(res);
                return NULL;
            }
            if (!values) {
                debug("No attribute value found\n");
                ldap_msgfree(res);
                return NULL;
            }
            value = values;
            while (*value) {
                if (encrpass && *delimiter ) {
                    const char *t = strtok(*value, delimiter);
                    if (t && strcmp(t, realm) == 0) {
                        password = strtok(NULL, delimiter);
                        break;
                    }
                } else {
                    password = *value;
                    break;
                }
                ++value;
            }
            debug("password: %s\n", password);
            if (password)
                password = xstrdup(password);
            ldap_value_free(values);
            ldap_msgfree(res);
            return password;
        } else {
            fprintf(stderr, PROGRAM_NAME " WARNING, LDAP error '%s'\n", ldap_err2string(rc));
            /* try to connect to the LDAP server agin, maybe my persisten conexion failed. */
            if (!retry) {
                ++retry;
                ldap_unbind(ld);
                ld = NULL;
                ldapconnect();
                goto retrydnattr;
            }
            return NULL;
        }
    }
    return NULL;
}

static void
ldapconnect(void)
{
    int rc;

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

    if (ld == NULL) {
#if HAS_URI_SUPPORT
        if (strstr(ldapServer, "://") != NULL) {
            rc = ldap_initialize(&ld, ldapServer);
            if (rc != LDAP_SUCCESS) {
                fprintf(stderr, "\nUnable to connect to LDAPURI:%s\n", ldapServer);
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
                if ((ld = ldap_init(ldapServer, port)) == NULL) {
                    fprintf(stderr, "\nUnable to connect to LDAP server:%s port:%d\n", ldapServer, port);
                }
        if (connect_timeout)
            squid_ldap_set_connect_timeout(connect_timeout);

#ifdef LDAP_VERSION3
        if (version == -1) {
            version = LDAP_VERSION2;
        }
        if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
                != LDAP_SUCCESS) {
            fprintf(stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
                    version);
            ldap_unbind(ld);
            ld = NULL;
        }
        if (use_tls) {
#ifdef LDAP_OPT_X_TLS
            if (version != LDAP_VERSION3) {
                fprintf(stderr, "TLS requires LDAP version 3\n");
                exit(EXIT_FAILURE);
            } else if (ldap_start_tls_s(ld, NULL, NULL) != LDAP_SUCCESS) {
                fprintf(stderr, "Could not Activate TLS connection\n");
                exit(EXIT_FAILURE);
            }
#else
            fprintf(stderr, "TLS not supported with your LDAP library\n");
            ldap_unbind(ld);
            ld = NULL;
#endif
        }
#endif
        squid_ldap_set_timelimit(timelimit);
        squid_ldap_set_referrals(!noreferrals);
        squid_ldap_set_aliasderef(aliasderef);
        if (binddn && bindpasswd && *binddn && *bindpasswd) {
            rc = ldap_simple_bind_s(ld, binddn, bindpasswd);
            if (rc != LDAP_SUCCESS) {
                fprintf(stderr, PROGRAM_NAME " WARNING, could not bind to binddn '%s'\n", ldap_err2string(rc));
                ldap_unbind(ld);
                ld = NULL;
            }
        }
        debug("Connected OK\n");
    }
}
int
LDAPArguments(int argc, char **argv)
{
    setbuf(stdout, NULL);

    while (argc > 1 && argv[1][0] == '-') {
        const char *value = "";
        char option = argv[1][1];
        switch (option) {
        case 'P':
        case 'R':
        case 'z':
        case 'Z':
        case 'g':
        case 'e':
        case 'S':
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
            return 1;
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
        case 'A':
            passattr = value;
            break;
        case 'e':
            encrpass = 1;
            break;
        case 'l':
            delimiter = value;
            break;
        case 'r':
            frealm = value;
            break;
        case 'b':
            userbasedn = value;
            break;
        case 'F':
            usersearchfilter = value;
            break;
        case 'u':
            userdnattr = value;
            break;
        case 's':
            if (strcmp(value, "base") == 0)
                searchscope = LDAP_SCOPE_BASE;
            else if (strcmp(value, "one") == 0)
                searchscope = LDAP_SCOPE_ONELEVEL;
            else if (strcmp(value, "sub") == 0)
                searchscope = LDAP_SCOPE_SUBTREE;
            else {
                fprintf(stderr, PROGRAM_NAME " ERROR: Unknown search scope '%s'\n", value);
                return 1;
            }
            break;
        case 'S':
#if defined(NETSCAPE_SSL)
            sslpath = value;
            if (port == LDAP_PORT)
                port = LDAPS_PORT;
#else
            fprintf(stderr, PROGRAM_NAME " ERROR: -E unsupported with this LDAP library\n");
            return 1;
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
                fprintf(stderr, PROGRAM_NAME " ERROR: Unknown alias dereference method '%s'\n", value);
                return 1;
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
                return 1;
            }
            break;
        case 'Z':
            if (version == LDAP_VERSION2) {
                fprintf(stderr, "TLS (-Z) is incompatible with version %d\n",
                        version);
                return 1;
            }
            version = LDAP_VERSION3;
            use_tls = 1;
            break;
#endif
        case 'd':
            debug_enabled = 1;
            break;
        case 'E':
            strip_nt_domain = 1;
            break;
        default:
            fprintf(stderr, PROGRAM_NAME " ERROR: Unknown command line option '%c'\n", option);
            return 1;
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
        ldapServer = (char *) "localhost";

    if (!userbasedn || !passattr || (!*delimiter && !*frealm)) {
        fprintf(stderr, "Usage: " PROGRAM_NAME " -b basedn -F filter [options] ldap_server_name\n\n");
        fprintf(stderr, "\t-A password attribute(REQUIRED)\t\tUser attribute that contains the password\n");
        fprintf(stderr, "\t-l password realm delimiter(REQUIRED)\tCharacter(s) that divides the password attribute\n\t\t\t\t\t\tin realm and password tokens, default ':' realm:password, could be\n\t\t\t\t\t\tempty string if the password is alone in the password attribute\n");
        fprintf(stderr, "\t-r filtered realm\t\t\tonly honor Squid requests for this realm. Mandatory if the password is alone in\n\t\t\t\t\t\tthe password attribute, acting as the implicit realm\n");
        fprintf(stderr, "\t-b basedn (REQUIRED)\t\t\tbase dn under where to search for users\n");
        fprintf(stderr, "\t-e Encrypted passwords(REQUIRED)\tPassword are stored encrypted using HHA1\n");
        fprintf(stderr, "\t-F filter\t\t\t\tuser search filter pattern. %%s = login\n");
        fprintf(stderr, "\t-u attribute\t\t\t\tattribute to use in combination with the basedn to create the user DN\n");
        fprintf(stderr, "\t-s base|one|sub\t\t\t\tsearch scope\n");
        fprintf(stderr, "\t-D binddn\t\t\t\tDN to bind as to perform searches\n");
        fprintf(stderr, "\t-w bindpasswd\t\t\t\tpassword for binddn\n");
        fprintf(stderr, "\t-W secretfile\t\t\t\tread password for binddn from file secretfile\n");
#if HAS_URI_SUPPORT
        fprintf(stderr, "\t-H URI\t\t\t\t\tLDAPURI (defaults to ldap://localhost)\n");
#endif
        fprintf(stderr, "\t-h server\t\t\t\tLDAP server (defaults to localhost)\n");
        fprintf(stderr, "\t-p port\t\t\t\t\tLDAP server port (defaults to %d)\n", LDAP_PORT);
        fprintf(stderr, "\t-P\t\t\t\t\tpersistent LDAP connection\n");
#if defined(NETSCAPE_SSL)
        fprintf(stderr, "\t-E sslcertpath\t\t\t\tenable LDAP over SSL\n");
#endif
        fprintf(stderr, "\t-c timeout\t\t\t\tconnect timeout\n");
        fprintf(stderr, "\t-t timelimit\t\t\t\tsearch time limit\n");
        fprintf(stderr, "\t-R\t\t\t\t\tdo not follow referrals\n");
        fprintf(stderr, "\t-a never|always|search|find\t\twhen to dereference aliases\n");
#ifdef LDAP_VERSION3
        fprintf(stderr, "\t-v 2|3\t\t\t\t\tLDAP version\n");
        fprintf(stderr, "\t-Z\t\t\t\t\tTLS encrypt the LDAP connection, requires\n\t\t\t\tLDAP version 3\n");
#endif
        fprintf(stderr, "\t-S\t\t\t\t\tStrip NT domain from usernames\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "\tIf you need to bind as a user to perform searches then use the\n\t-D binddn -w bindpasswd or -D binddn -W secretfile options\n\n");
        return -1;
    }
    return 0;
}
static int
readSecret(const char *filename)
{
    char buf[BUFSIZ];
    char *e = 0;
    FILE *f;

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

    bindpasswd = xstrdup(buf);
    if (!bindpasswd) {
        fprintf(stderr, PROGRAM_NAME " ERROR: can not allocate memory\n");
    }
    fclose(f);

    return 0;
}

void
LDAPHHA1(RequestData * requestData)
{
    char *password = NULL;
    ldapconnect();

    // use the -l delimiter to find realm, or
    // only honor the -r specified realm
    const bool lookup = (!*frealm && *delimiter) ||
                        (*frealm && strcmp(requestData->realm, frealm) == 0);

    if (lookup)
        password = getpassword(requestData->user, requestData->realm);

    if (password != NULL) {
        if (encrpass)
            xstrncpy(requestData->HHA1, password, sizeof(requestData->HHA1));
        else {
            HASH HA1;
            DigestCalcHA1("md5", requestData->user, requestData->realm, password, NULL, NULL, HA1, requestData->HHA1);
        }
        free(password);
    } else {
        requestData->error = -1;
    }

}


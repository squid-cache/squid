/*
 * squid_ldap_auth: authentication via ldap for squid proxy server
 * 
 * Maintainer: Henrik Nordstrom <hno@squid-cache.org>
 *
 * Author: Glen Newton 
 * glen.newton@nrc.ca
 * Advanced Services 
 * CISTI
 * National Research Council
 * 
 * Usage: squid_ldap_auth -b basedn [-s searchscope]
 *                        [-f searchfilter] [-D binddn -w bindpasswd]
 *                        [-u attr] [-h host] [-p port] [-P] [-R] [ldap_server_name[:port]] ...
 * 
 * Dependencies: You need to get the OpenLDAP libraries
 * from http://www.openldap.org
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
 * 2001-12-12: Michael Cunningham <m.cunningham@xpedite.com>
               - Added TLS support and partial ldap version 3 support. 
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lber.h>
#include <ldap.h>

/* Change this to your search base */
static char *basedn;
static char *searchfilter = NULL;
static char *binddn = NULL;
static char *bindpasswd = NULL;
static char *userattr = "uid";
static int searchscope = LDAP_SCOPE_SUBTREE;
static int persistent = 0;
static int noreferrals = 0;
static int aliasderef = LDAP_DEREF_NEVER;

/* Added for TLS support and version 3 */
static int use_tls = 0;
static int version = -1;

static int checkLDAP(LDAP * ld, char *userid, char *password);

/* Yuck.. we need to glue to different versions of the API */

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
    int *value = referrals ? LDAP_OPT_ON : LDAP_OPT_OFF;
    ldap_set_option(ld, LDAP_OPT_REFERRALS, value);
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
squid_ldap_memfree(char *p)
{
    free(p);
}
#endif

int
main(int argc, char **argv)
{
    char buf[256];
    char *user, *passwd;
    char *ldapServer = NULL;
    LDAP *ld = NULL;
    int tryagain;
    int port = LDAP_PORT;

    setbuf(stdout, NULL);

    while (argc > 1 && argv[1][0] == '-') {
	char *value = "";
	char option = argv[1][1];
	switch (option) {
	case 'P':
	case 'R':
	case 'z':
	    break;
	default:
	    if (strlen(argv[1]) > 2 || argc <= 2) {
		value = argv[1] + 2;
	    } else {
		value = argv[2];
		argv++;
		argc--;
	    }
	    break;
	}
	argv++;
	argc--;
	switch (option) {
	case 'h':
	    if (ldapServer) {
		int len = strlen(ldapServer) + 1 + strlen(value) + 1;
		char *newhost = malloc(len);
		snprintf(newhost, len, "%s %s", ldapServer, value);
		free(ldapServer);
		ldapServer = newhost;
	    } else {
		ldapServer = strdup(value);
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
	case 's':
	    if (strcmp(value, "base") == 0)
		searchscope = LDAP_SCOPE_BASE;
	    else if (strcmp(value, "one") == 0)
		searchscope = LDAP_SCOPE_ONELEVEL;
	    else if (strcmp(value, "sub") == 0)
		searchscope = LDAP_SCOPE_SUBTREE;
	    else {
		fprintf(stderr, "squid_ldap_auth: ERROR: Unknown search scope '%s'\n", value);
		exit(1);
	    }
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
		fprintf(stderr, "squid_ldap_auth: ERROR: Unknown alias dereference method '%s'\n", value);
		exit(1);
	    }
	    break;
	case 'D':
	    binddn = value;
	    break;
	case 'w':
	    bindpasswd = value;
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
	case 'v':
	    switch( atoi(value) ) {
	    case 2:
		version = LDAP_VERSION2;
		break;
	    case 3:
		version = LDAP_VERSION3;
		break;
	    default:
		fprintf( stderr, "Protocol version should be 2 or 3\n");
		exit(1);
	    }
	    break;
	case 'Z':
	    if ( version == LDAP_VERSION2 ) {
		fprintf( stderr, "TLS (-Z) is incompatible with version %d\n",
			version);
		exit(1);
	    }
	    version = LDAP_VERSION3;
	    use_tls = 1;
	    break;
	default:
	    fprintf(stderr, "squid_ldap_auth: ERROR: Unknown command line option '%c'\n", option);
	    exit(1);
	}
    }

    while (argc > 1 && argv[1][0] == '-') {
	char *value = argv[1];
	if (ldapServer) {
	    int len = strlen(ldapServer) + 1 + strlen(value) + 1;
	    char *newhost = malloc(len);
	    snprintf(newhost, len, "%s %s", ldapServer, value);
	    free(ldapServer);
	    ldapServer = newhost;
	} else {
	    ldapServer = strdup(value);
	}
	argc--;
	argv++;
    }
    if (!ldapServer)
	ldapServer = "localhost";

    if (!basedn) {
	fprintf(stderr, "Usage: squid_ldap_auth -b basedn [options] [ldap_server_name[:port]]...\n\n");
	fprintf(stderr, "\t-b basedn (REQUIRED)\tbase dn under which to search\n");
	fprintf(stderr, "\t-f filter\t\tsearch filter to locate user DN\n");
	fprintf(stderr, "\t-u userattr\t\tusername DN attribute\n");
	fprintf(stderr, "\t-s base|one|sub\t\tsearch scope\n");
	fprintf(stderr, "\t-D binddn\t\tDN to bind as to perform searches\n");
	fprintf(stderr, "\t-w bindpasswd\t\tpassword for binddn\n");
	fprintf(stderr, "\t-h server\t\tLDAP server (defaults to localhost)\n");
	fprintf(stderr, "\t-p port\t\t\tLDAP server port\n");
	fprintf(stderr, "\t-P\t\t\tpersistent LDAP connection\n");
	fprintf(stderr, "\t-R\t\t\tdo not follow referrals\n");
	fprintf(stderr, "\t-a never|always|search|find\n\t\t\t\twhen to dereference aliases\n");
	fprintf(stderr, "\t-v 1|2\t\t\tLDAP version\n");
	fprintf(stderr, "\t-Z\t\t\tTLS encrypt the LDAP connection, requires LDAP version 3\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\tIf no search filter is specified, then the dn <userattr>=user,basedn\n\twill be used (same as specifying a search filter of '<userattr>=',\n\tbut quicker as as there is no need to search for the user DN)\n\n");
	fprintf(stderr, "\tIf you need to bind as a user to perform searches then use the\n\t-D binddn -w bindpasswd options\n\n");
	exit(1);
    }
    while (fgets(buf, 256, stdin) != NULL) {
	user = strtok(buf, " \r\n");
	passwd = strtok(NULL, "\r\n");

	if (!user || !passwd || !passwd[0]) {
	    printf("ERR\n");
	    continue;
	}
	tryagain = 1;
      recover:
	if (ld == NULL) {
	    if ((ld = ldap_init(ldapServer, port)) == NULL) {
		fprintf(stderr, "\nUnable to connect to LDAP server:%s port:%d\n",
		    ldapServer, port);
		exit(1);
	    }

        if (version == -1 ) {
                version = LDAP_VERSION2;
        }

        if( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version )
                != LDAP_OPT_SUCCESS )
        {
                fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
                        version );
                exit(1);
        }

        if ( use_tls && ( version == LDAP_VERSION3 ) && ( ldap_start_tls_s( ld, NULL, NULL ) == LDAP_SUCCESS )) {
                fprintf( stderr, "Could not Activate TLS connection\n");
                exit(1);
        }

	    squid_ldap_set_referrals(ld, !noreferrals);
	    squid_ldap_set_aliasderef(ld, aliasderef);
	}
	if (checkLDAP(ld, user, passwd) != 0) {
	    if (tryagain && squid_ldap_errno(ld) != LDAP_INVALID_CREDENTIALS) {
		tryagain = 0;
		ldap_unbind(ld);
		ld = NULL;
		goto recover;
	    }
	    printf("ERR\n");
	} else {
	    printf("OK\n");
	}
	if (!persistent || (squid_ldap_errno(ld) != LDAP_SUCCESS && squid_ldap_errno(ld) != LDAP_INVALID_CREDENTIALS)) {
	    ldap_unbind(ld);
	    ld = NULL;
	}
    }
    if (ld)
	ldap_unbind(ld);
    return 0;
}

static int
checkLDAP(LDAP * ld, char *userid, char *password)
{
    char dn[256];

    if (!*password) {
	/* LDAP can't bind with a blank password. Seen as "anonymous"
	 * and always granted access
	 */
	return 1;
    }
    if (searchfilter) {
	char filter[256];
	LDAPMessage *res = NULL;
	LDAPMessage *entry;
	char *searchattr[] =
	{NULL};
	char *userdn;
	int rc;

	if (binddn) {
	    rc = ldap_simple_bind_s(ld, binddn, bindpasswd);
	    if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "squid_ldap_auth: WARNING, could not bind to binddn '%s'\n", ldap_err2string(rc));
		return 1;
	    }
	}
	snprintf(filter, sizeof(filter), searchfilter, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid, userid);
	if (ldap_search_s(ld, basedn, searchscope, filter, searchattr, 1, &res) != LDAP_SUCCESS) {
	    int rc = ldap_result2error(ld, res, 0);
	    if (noreferrals && rc == LDAP_PARTIAL_RESULTS) {
		/* Everything is fine. This is expected when referrals
		 * are disabled.
		 */
	    } else {
		fprintf(stderr, "squid_ldap_auth: WARNING, LDAP search error '%s'\n", ldap_err2string(rc));
	    }
	}
	entry = ldap_first_entry(ld, res);
	if (!entry) {
	    ldap_msgfree(res);
	    return 1;
	}
	userdn = ldap_get_dn(ld, entry);
	if (!userdn) {
	    fprintf(stderr, "squid_ldap_auth: ERROR, could not get user DN for '%s'\n", userid);
	    ldap_msgfree(res);
	    return 1;
	}
	snprintf(dn, sizeof(dn), "%s", userdn);
	free(userdn);
	ldap_msgfree(res);
    } else {
	snprintf(dn, sizeof(dn), "%s=%s,%s", userattr, userid, basedn);
    }

    if (ldap_simple_bind_s(ld, dn, password) != LDAP_SUCCESS)
	return 1;

    return 0;
}

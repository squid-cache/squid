/*
 * squid_ldap_match: lookup group membership in LDAP
 * 
 * Author: Flavio Pescuma <flavio@marasystems.com>
 *         MARA Systems AB, Sweden <http://www.marasystems.com>
 *
 * URL: http://marasystems.com/download/LDAP_Group/
 *
 * Based on squid_ldap_auth by Glen Newton
 * 
 * Dependencies: You need to get the OpenLDAP libraries
 * from http://www.openldap.org
 *
 * If you want to make a TLS enabled connection you will also need the
 * OpenSSL libraries linked into openldap. See http://www.openssl.org/
 * 
 * License: squid_ldap_match is free software; you can redistribute it 
 * and/or modify it under the terms of the GNU General Public License 
 * as published by the Free Software Foundation; either version 2, 
 * or (at your option) any later version.
 *
 * Changes:
 * Version 2.4
 * 2002-09-06: Henrik Nordstrom <hno@marasystems.com>
 * 		Many bugfixes in connection management
 * 		-g option added, and added support
 * 		for multiple groups. Prior versions
 * 		only supported one group and an optional
 * 		group base RDN
 * Version 2.3
 * 2002-09-04: Henrik Nordstrom <hno@marasystems.com>
 *              Minor cleanups
 * Version 2.2
 * 2002-09-04: Henrik Nordstrom <hno@marasystems.com>
 *              Merged changes from squid_ldap_auth.c
 *              - TLS support
 *              - -p option to specify port
 *              Documented the % codes to use in -f
 * Version 2.1
 * 2002-08-21: Henrik Nordstrom <hno@marasystems.com>
 *              Support groups or usernames having spaces
 * Version 2.0
 * 2002-01-22: Henrik Nordstrom <hno@marasystems.com>
 *              Added optional third query argument for search RDN
 * 2002-01-22: Henrik Nordstrom <hno@marasystems.com>
 *              Removed unused options, and fully changed name
 *              to squid_ldap_match.
 * Version 1.0
 * 2001-07-17: Flavio Pescuma <flavio@marasystems.com>
 *              Using the main function from squid_ldap_auth
 *              wrote squid_ldap_match. This program replaces 
 *              the %a and %v (ldapfilter.conf) from the filter 
 *              template supplied with -f with the two arguments 
 *              sent by squid. Returns OK if the ldap_search 
 *              using the composed filter succeeds.
 *
 * OLD Changes: (from squid_ldap_auth.c)
 * 2001-12-12: Michael Cunningham <m.cunningham@xpedite.com>
 *             - Added TLS support and partial ldap version 3 support. 
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
#include <ctype.h>
#include <lber.h>
#include <ldap_cdefs.h>
#include <ldap.h>

/* Change this to your search base */
static char *basedn;
static char *searchfilter = NULL;
static char *binddn = NULL;
static char *bindpasswd = NULL;
static int searchscope = LDAP_SCOPE_SUBTREE;
static int persistent = 0;
static int noreferrals = 0;
static int debug = 0;
static int aliasderef = LDAP_DEREF_NEVER;

/* Added for TLS support and version 3 */
static int use_tls = 0;
static int version = -1;

static int searchLDAP(LDAP * ld, char *group, char *user, char *grouprdn);

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

#if UNUSED
static void 
squid_ldap_memfree(char *p)
{
    ldap_memfree(p);
}

#endif
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
#if UNUSED
static void 
squid_ldap_memfree(char *p)
{
    free(p);
}

#endif
#endif

static char *
strwordtok(char *buf, char **t)
{
    unsigned char *word = NULL;
    unsigned char *p = (unsigned char *) buf;
    unsigned char *d;
    unsigned char ch;
    int quoted = 0;
    if (!p)
	p = (unsigned char *) *t;
    if (!p)
	goto error;
    while (*p && isspace(*p))
	p++;
    if (!*p)
	goto error;
    word = d = p;
    while ((ch = *p)) {
	switch (ch) {
	case '\\':
	    p++;
	    *d++ = ch = *p;
	    if (ch)
		p++;
	    break;
	case '"':
	    quoted = !quoted;
	    p++;
	default:
	    if (!quoted && isspace(*p)) {
		p++;
		goto done;
	    }
	    *d++ = *p++;
	    break;
	}
    }
  done:
    *d++ = '\0';
  error:
    *t = (char *) p;
    return (char *) word;
}

int
main(int argc, char **argv)
{
    char buf[256];
    char *user, *group, *grouprdn = NULL;
    char *ldapServer = NULL;
    LDAP *ld = NULL;
    int tryagain, rc;
    int port = LDAP_PORT;
    int use_grouprdn = 0;

    setbuf(stdout, NULL);

    while (argc > 1 && argv[1][0] == '-') {
	char *value = "";
	char option = argv[1][1];
	switch (option) {
	case 'P':
	case 'R':
	case 'z':
	case 'Z':
	case 'g':
	    break;
	default:
	    if (strlen(argv[1]) > 2) {
		value = argv[1] + 2;
	    } else if (argc > 2) {
		value = argv[2];
		argv++;
		argc--;
	    } else
		value = "";
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
	case 's':
	    if (strcmp(value, "base") == 0)
		searchscope = LDAP_SCOPE_BASE;
	    else if (strcmp(value, "one") == 0)
		searchscope = LDAP_SCOPE_ONELEVEL;
	    else if (strcmp(value, "sub") == 0)
		searchscope = LDAP_SCOPE_SUBTREE;
	    else {
		fprintf(stderr, "squid_ldap_match: ERROR: Unknown search scope '%s'\n", value);
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
		fprintf(stderr, "squid_ldap_match: ERROR: Unknown alias dereference method '%s'\n", value);
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
	    switch (atoi(value)) {
	    case 2:
		version = LDAP_VERSION2;
		break;
	    case 3:
		version = LDAP_VERSION3;
		break;
	    default:
		fprintf(stderr, "Protocol version should be 2 or 3\n");
		exit(1);
	    }
	    break;
	case 'Z':
	    if (version == LDAP_VERSION2) {
		fprintf(stderr, "TLS (-Z) is incompatible with version %d\n",
		    version);
		exit(1);
	    }
	    version = LDAP_VERSION3;
	    use_tls = 1;
	    break;
	case 'd':
	    debug = 1;
	    break;
	case 'g':
	    use_grouprdn = 1;
	    break;
	default:
	    fprintf(stderr, "squid_ldap_match: ERROR: Unknown command line option '%c'\n", option);
	    exit(1);
	}
    }

    while (argc > 1) {
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

    if (!basedn || !searchfilter) {
	fprintf(stderr, "Usage: squid_ldap_match -f basedn -f filter [options] ldap_server_name\n\n");
	fprintf(stderr, "\t-b basedn (REQUIRED)\tbase dn under where to search\n");
	fprintf(stderr, "\t-f filter (REQUIRED)\tsearch filter pattern. %%v = user, %%a = group\n");
	fprintf(stderr, "\t-s base|one|sub\t\tsearch scope\n");
	fprintf(stderr, "\t-D binddn\t\tDN to bind as to perform searches\n");
	fprintf(stderr, "\t-w bindpasswd\t\tpassword for binddn\n");
	fprintf(stderr, "\t-h server\t\tLDAP server (defaults to localhost)\n");
	fprintf(stderr, "\t-p port\t\t\tLDAP server port (defaults to %d)\n", LDAP_PORT);
	fprintf(stderr, "\t-P\t\t\tpersistent LDAP connection\n");
	fprintf(stderr, "\t-R\t\t\tdo not follow referrals\n");
	fprintf(stderr, "\t-a never|always|search|find\n\t\t\t\twhen to dereference aliases\n");
	fprintf(stderr, "\t-v 1|2\t\t\tLDAP version\n");
	fprintf(stderr, "\t-Z\t\t\tTLS encrypt the LDAP connection, requires LDAP version 3\n");
	fprintf(stderr, "\t-g\t\t\tfirst query parameter is additional groups base RDN for this query\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\tIf you need to bind as a user to perform searches then use the\n\t-D binddn -w bindpasswd options\n\n");
	exit(1);
    }
    while (fgets(buf, 256, stdin) != NULL) {
	char *t;
	int found = 0;
	user = strwordtok(buf, &t);
	if (use_grouprdn)
		grouprdn = strwordtok(NULL, &t);

	tryagain = 1;
	while (!found && user && (group = strwordtok(NULL, &t)) != NULL) {

	  recover:
	    if (ld == NULL) {
		if ((ld = ldap_init(ldapServer, port)) == NULL) {
		    fprintf(stderr, "\nUnable to connect to LDAP server:%s port:%d\n",
			ldapServer, port);
		    break;
		}
		if (version == -1) {
		    version = LDAP_VERSION2;
		}
		if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
		    != LDAP_OPT_SUCCESS) {
		    fprintf(stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
			version);
		    ldap_unbind(ld);
		    ld = NULL;
		    break;
		}
		if (use_tls && (version == LDAP_VERSION3) && (ldap_start_tls_s(ld, NULL, NULL) == LDAP_SUCCESS)) {
		    fprintf(stderr, "Could not Activate TLS connection\n");
		    ldap_unbind(ld);
		    ld = NULL;
		    break;
		}
		squid_ldap_set_referrals(ld, !noreferrals);
		squid_ldap_set_aliasderef(ld, aliasderef);
	    }
	    rc = ldap_simple_bind_s(ld, binddn, bindpasswd);
	    if (rc != LDAP_SUCCESS) {
		fprintf(stderr, "squid_ldap_match: WARNING, could not bind to binddn '%s'\n", ldap_err2string(rc));
		ldap_unbind(ld);
		ld = NULL;
		break;
	    }
	    if (debug)
		printf("Binding OK\n");
	    if (searchLDAP(ld, group, user, grouprdn) == 0) {
		found = 1;
		break;
	    } else {
		if (tryagain) {
		    tryagain = 0;
		    ldap_unbind(ld);
		    ld = NULL;
		    goto recover;
		}
	    }
	}
	if (found)
	    printf("OK\n");
	else
	    printf("ERR\n");

	if (ld != NULL) {
	    if (!persistent || (squid_ldap_errno(ld) != LDAP_SUCCESS && squid_ldap_errno(ld) != LDAP_INVALID_CREDENTIALS)) {
		ldap_unbind(ld);
		ld = NULL;
	    }
	}
    }
    if (ld)
	ldap_unbind(ld);
    return 0;
}

static int
searchLDAP(LDAP * ld, char *group, char *member, char *grouprdn)
{
    char filter[256];
    static char searchbase[256];
    LDAPMessage *res = NULL;
    LDAPMessage *entry;

    if (grouprdn)
	snprintf(searchbase, sizeof(searchbase), "%s,%s", grouprdn, basedn);
    else
	snprintf(searchbase, sizeof(searchbase), "%s", basedn);

    ldap_build_filter(filter, sizeof(filter), searchfilter, NULL, NULL, group, member, NULL);
    if (debug)
	printf("filter %s\n", filter);


    if (ldap_search_s(ld, searchbase, searchscope, filter, NULL, 1, &res) != LDAP_SUCCESS) {
	int rc = ldap_result2error(ld, res, 0);
	if (noreferrals && rc == LDAP_PARTIAL_RESULTS) {
	    /* Everything is fine. This is expected when referrals
	     * are disabled.
	     */
	} else {
	    fprintf(stderr, "squid_ldap_match: WARNING, LDAP search error '%s'\n", ldap_err2string(rc));
	}
	ldap_msgfree(res);
	return 1;
    }
    entry = ldap_first_entry(ld, res);
    if (!entry) {
	ldap_msgfree(res);
	return 1;
    }
    ldap_msgfree(res);
    return 0;
}

/*
 * 
 * squid_ldap_auth: authentication via ldap for squid proxy server
 * 
 * Author: Glen Newton 
 * glen.newton@nrc.ca
 * Advanced Services 
 * CISTI
 * National Research Council
 * 
 * Usage: squid_ldap_auth [-b basedn] [-s searchscope] [-f searchfilter] <ldap_server_name>
 * 
 * Dependencies: You need to get the OpenLDAP libraries
 * from http://www.openldap.org
 * 
 * License: squid_ldap_auth is free software; you can redistribute it 
 * and/or modify it under the terms of the GNU General Public License 
 * as published by the Free Software Foundation; either version 2, 
 * or (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lber.h>
#include <ldap_cdefs.h>
#include <ldap.h>

/* Change this to your search base */
static char *basedn = "ou=people,o=nrc.ca";
static char *searchfilter = NULL;
static int searchscope = LDAP_SCOPE_SUBTREE;

int checkLDAP(LDAP * ld, char *userid, char *password);

int
main(int argc, char **argv)
{
    char buf[256];
    char *user, *passwd, *p;
    char *ldapServer;
    LDAP *ld;

    setbuf(stdout, NULL);

    while (argc > 2 && argv[1][0] == '-') {
	char *value;
	char option = argv[1][1];
	if (strlen(argv[1]) > 2) {
	    value = argv[1]+2;
	} else {
	    value = argv[2];
	    argv++;
	    argc--;
	}
	argv++;
	argc--;
	switch(option) {
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
		    fprintf(stderr, "squid_ldap_auth: ERROR: Unknown search scope '%s'\n", value);
		    exit(1);
		}
		break;
	default:
		fprintf(stderr, "squid_ldap_auth: ERROR: Unknown command line option '%c'\n", option);
		exit(1);
	}
    }
	
    if (argc != 2) {
	fprintf(stderr, "Usage: squid_ldap_auth [-b basedn] [-s searchscope] [-f searchfilter] ldap_server_name\n");
	exit(1);
    }
    ldapServer = (char *) argv[1];

    while (fgets(buf, 256, stdin) != NULL) {
	/* You can put this ldap connect outside the loop, but i didn't want to 
	 * have the connection open too much. If you have a site which will 
	 * be doing >1 authentication per second, you should move this (and the 
	 * below ldap_unbind()) outside the loop. 
	 */
	if ((ld = ldap_init(ldapServer, LDAP_PORT)) == NULL) {
	    fprintf(stderr, "\nUnable to connect to LDAP server:%s port:%d\n",
		ldapServer, LDAP_PORT);
	    exit(1);
	}
	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */

	if ((user = strtok(buf, " ")) == NULL) {
	    printf("ERR\n");
	    continue;
	}
	if ((passwd = strtok(NULL, "")) == NULL) {
	    printf("ERR\n");
	    continue;
	}
	if (checkLDAP(ld, user, passwd) != 0) {
	    printf("ERR\n");
	    continue;
	} else {
	    printf("OK\n");
	}
	ldap_unbind(ld);
    }
    return 0;
}

int
checkLDAP(LDAP * ld, char *userid, char *password)
{
    char dn[256];
    int result = 1;

    if (searchfilter) {
	char filter[256];
	LDAPMessage *res = NULL;
	LDAPMessage *entry;
	char *searchattr[] = {NULL};
	char *userdn;

	snprintf(filter, sizeof(filter), "%s%s", searchfilter, userid);
	if (ldap_search_s(ld, basedn, searchscope, filter, searchattr, 1, &res) != LDAP_SUCCESS)
	    return 1;
	entry = ldap_first_entry(ld, res);
	if (!entry) {
	    ldap_msgfree(res);
	    return 1;
	}
	userdn = ldap_get_dn(ld, entry);
	if (!userdn) {
	    ldap_msgfree(res);
	    return 1;
	}
	snprintf(dn, sizeof(dn), "%s", userdn);
	free(userdn);
	ldap_msgfree(res);
    } else {
	snprintf(dn, sizeof(dn), "uid=%s, %s", userid, basedn);
    }

    if (ldap_simple_bind_s(ld, dn, password) == LDAP_SUCCESS)
	result = 0;

    return result;
}

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
 * Usage: squid_ldap_auth <ldap_server_name>
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
#include <lber.h>
#include <ldap_cdefs.h>
#include <ldap.h>

/* Change this to your search base */
#define SEARCHBASE "ou=people,o=nrc.ca"

int checkLDAP(LDAP * ld, char *userid, char *password);

int
main(int argc, char **argv)
{
    char buf[256];
    char *user, *passwd, *p;
    char *ldapServer;
    LDAP *ld;
    LDAPMessage *result, *e;

    setbuf(stdout, NULL);

    if (argc != 2) {
	fprintf(stderr, "Usage: squid_ldap_auth ldap_server_name\n");
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
}



int
checkLDAP(LDAP * ld, char *userid, char *password)
{
    char str[256];

    /*sprintf(str,"uid=[%s][%s], %s",userid, password, SEARCHBASE); */
    sprintf(str, "uid=%s, %s", userid, SEARCHBASE);

    if (ldap_simple_bind_s(ld, str, password) != LDAP_SUCCESS) {
	/*fprintf(stderr, "\nUnable to bind\n"); */
	return 33;
    }
    return 0;
}

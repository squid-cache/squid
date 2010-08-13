/* squid_edir_iplookup - Copyright (C) 2009, 2010 Chad E. Naugle
 *
 ********************************************************************************
 *
 *  This file is part of squid_edir_iplookup.
 *
 *  squid_edir_iplookup is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  squid_edir_iplookup is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with squid_edir_iplookup.  If not, see <http://www.gnu.org/licenses/>.
 *
 ********************************************************************************
 *
 * iplookup.h --
 *
 * ldap_t data struct typedef and related functions.
 *
 */

#ifndef _HAVE_IPLOOKUP_H
#define _HAVE_IPLOOKUP_H
#ifndef _HAVE_MAIN_H
#include "main.h"
#endif
#include <ctype.h>
#define LDAP_DEPRECATED 1	/* Set flag for enabling classic ldap functions */
#include <lber.h>
#include <ldap.h>

/* compile options */
#define USE_LDAP_INIT
#ifndef NETSCAPE_SSL
# define NETSCAPE_SSL
#endif

/* define LDAP_AUTH_TLS */
#ifdef NETSCAPE_SSL
# ifndef LDAP_AUTH_TLS
#  define LDAP_AUTH_TLS		((ber_tag_t) 0xb3U)
# endif
#endif

/* status flags */
#define LDAP_INIT_S		0x0001
#define LDAP_OPEN_S		0x0002
#define LDAP_BIND_S		0x0004
#define LDAP_SEARCH_S		0x0008		/* We got data */
#define LDAP_VAL_S		0x0010		/* Data has been copied to l->val */
#define LDAP_CLOSE_S		0x0020
#define LDAP_SSL_S		0x0040
#define LDAP_TLS_S		0x0080
#define LDAP_IPV4_S		0x0100		/* Search IP is IPv4 */
#define LDAP_IPV6_S		0x0200		/* Search IP is IPv6 */

/* ldap_t struct typedef */
typedef struct {
    LDAP *lp;
    LDAPMessage *lm;
    struct berval **val;
    char basedn[MAXLEN];
    char host[MAXLEN];
    char dn[MAXLEN];
    char passwd[MAXLEN];
    char search_filter[MAXLEN];			/* search_group gets appended here by GroupLDAP */
    char search_ip[MAXLEN];			/* Could be IPv4 or IPv6, set by ConvertIP */
    char userid[MAXLEN];				/* Resulting userid */
    unsigned int status;
    unsigned int port;
    unsigned long type;				/* Type of bind */
    int ver;
    int scope;
    int err;					/* LDAP error code */
    time_t idle_time;
    int num_ent;					/* Number of entry's found via search */
    int num_val;					/* Number of value's found via getval */
} ldap_t;

/* iplookup.c - Functions */
void InitLDAP(ldap_t *);
int OpenLDAP(ldap_t *, char *, unsigned int);
int CloseLDAP(ldap_t *);
int SetVerLDAP(ldap_t *, int);
int BindLDAP(ldap_t *, char *, char *, unsigned int);
int ConvertIP(ldap_t *, char *);
int SearchFilterLDAP(ldap_t *, char *);
int SearchLDAP(ldap_t *, int, char *, char **);
int GetValLDAP(ldap_t *, char *);
int SearchIPLDAP(ldap_t *, char *);
#endif

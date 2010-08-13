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
 * config.h --
 *
 * Runtime default configuration.
 *
 */

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

/* Default program name */
#define DEFAULT_PROGRAM_NAME	"ext_edirectory_userip_acl"

/* Hostname or IP address of LDAP server, default is IPv4 localhost (127.0.0.1) */
/* #define DEFAULT_LDAP_HOST */

/* Should be 389 or 636 for SSL, but you can change it here */
/* #define DEFAULT_LDAP_PORT */

/* Default LDAP protocol version, 1, 2, or 3 -- 3 for TLS/SSL is defaulted */
/* #define DEFAULT_LDAP_VERSION */

/* Base DN to search from, Ie. o=TREE */
/* #define DEFAULT_BASE_DN */

/* Bind DN to perform searches, Base DN will be appended, or you can specify it here */
/* #define DEFAULT_BIND_DN */

/* Binding password to perform searches */
/* #define DEFAULT_BIND_PASS */

/* 0 - base, 1 - one level, 2 - subtree */
/* #define DEFAULT_SEARCH_SCOPE 2 */

/* Base search filter.  Ie. (&(objectClass=Person)(networkAddress=*)) */
/* #define DEFAULT_SEARCH_FILTER "(&(objectClass=User)(networkAddress=*))" */

/* Default maximum length of all generic array variables */
#define DEFAULT_MAXLEN		1024

/* Default to IPv4 enabled? */
#define DEFAULT_USE_IPV4

/* Default to IPv6 enabled? (Enable both for IPv4-in-IPv6) */
/* #define DEFAULT_USE_IPV6 */

/* Default to REQUIRE a groupMembership? */
/* #define DEFAULT_GROUP_REQUIRED */

/* Default to TLS enabled? */
#define DEFAULT_USE_TLS

/* Default to debugging output? (ie. No -d required) */
/* #define DEFAULT_DEBUG */

#endif

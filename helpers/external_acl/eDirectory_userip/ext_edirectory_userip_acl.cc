/* ext_edirectory_userip_acl - Copyright (C) 2009, 2010 Chad E. Naugle
 *
 ********************************************************************************
 *
 *  This file is part of ext_edirectory_userip_acl.
 *
 *  ext_edirectory_userip_acl is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  ext_edirectory_userip_acl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with squid_edir_iplookup.  If not, see <http://www.gnu.org/licenses/>.
 *
 ********************************************************************************
 *
 * ext_edirectory_userip_acl.c -- Rev 2010-09-22
 *
 */

/* Squid-3.X includes */
#include "config.h"
#include "helpers/defines.h"
#include "rfc1738.h"
#include "util.h"

#define EDUI_PROGRAM_NAME		"ext_edirectory_userip_acl"
#define EDUI_PROGRAM_VERSION		"2.0"

/* System includes */
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#define LDAP_DEPRECATED 1       /* Set flag for enabling classic ldap functions */
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HELPER_INPUT_BUFFER
#define EDUI_MAXLEN		HELPER_INPUT_BUFFER
#else
#define EDUI_MAXLEN		8196
#endif

/* ldap compile options */
#define USE_LDAP_INIT
#ifndef NETSCAPE_SSL
# define NETSCAPE_SSL
#endif

/* define LDAP_AUTH_TLS */
#ifdef NETSCAPE_SSL
# ifndef LDAP_AUTH_TLS
#  define LDAP_AUTH_TLS         ((ber_tag_t) 0xb3U)
# endif
#endif

/* conf_t - status flags */
#define EDUI_MODE_INIT		0x01
#define EDUI_MODE_DEBUG		0x02				/* Replace with Squid's debug system */
#define EDUI_MODE_TLS		0x04
#define EDUI_MODE_IPV4		0x08
#define EDUI_MODE_IPV6		0x10
#define EDUI_MODE_GROUP		0x20				/* Group is REQUIRED */
#define EDUI_MODE_PERSIST	0x40				/* Persistent LDAP connections */
#define EDUI_MODE_KILL		0x80

/* conf_t - Program configuration struct typedef */
typedef struct {
    char program[EDUI_MAXLEN];
    char basedn[EDUI_MAXLEN];
    char host[EDUI_MAXLEN];
    char attrib[EDUI_MAXLEN];
    char dn[EDUI_MAXLEN];
    char passwd[EDUI_MAXLEN];
    char search_filter[EDUI_MAXLEN];				/* Base search_filter that gets copied to edui_ldap_t */
    int ver;
    int scope;
    int port;
    time_t persist_timeout;
    unsigned int mode;
} edui_conf_t;

/* edui_ldap_t - status flags */
#define LDAP_INIT_S             0x0001
#define LDAP_OPEN_S             0x0002
#define LDAP_BIND_S             0x0004
#define LDAP_SEARCH_S           0x0008          /* We got data */
#define LDAP_VAL_S              0x0010          /* Data has been copied to l->val */
#define LDAP_CLOSE_S            0x0020
#define LDAP_PERSIST_S          0x0040          /* Persistent connection */
#define LDAP_IDLE_S             0x0080          /* Connection is idle */
#define LDAP_SSL_S              0x0100
#define LDAP_TLS_S              0x0200
#define LDAP_IPV4_S             0x0400          /* Search IP is IPv4 */
#define LDAP_IPV6_S             0x0800          /* Search IP is IPv6 */

/* edui_ldap_t - Meaningful error codes */
#define LDAP_ERR_NULL           -1              /* Null edui_ldap_t pointer */
#define LDAP_ERR_POINTER        -2              /* Null l->lp pointer */
#define LDAP_ERR_PARAM          -3              /* Null or Missing parameters */
#define LDAP_ERR_INIT           -4              /* Not initalized */
#define LDAP_ERR_OPEN           -5              /* Not open */
#define LDAP_ERR_CONNECT        -6              /* Unable to connect */
#define LDAP_ERR_BIND           -7              /* Not bound */
#define LDAP_ERR_SEARCHED       -8              /* Already Searched */
#define LDAP_ERR_NOT_SEARCHED   -9              /* Not searching */
#define LDAP_ERR_INVALID        -10             /* Invalid parameter */
#define LDAP_ERR_OOB            -11             /* Out of bounds value */
#define LDAP_ERR_PERSIST        -12             /* Persistent mode is not active */
#define LDAP_ERR_DATA           -13             /* Required data missing */
#define LDAP_ERR_NOTFOUND       -14             /* Item not found */
#define LDAP_ERR_OTHER          -15             /* Other Generic Error condition */
#define LDAP_ERR_FAILED         -16             /* Operation failed */
#define LDAP_ERR_SUCCESS        -17             /* Operation successful */

/* edui_ldap_t - struct typedef */
typedef struct {
    LDAP *lp;
    LDAPMessage *lm;
    struct berval **val;
    char basedn[EDUI_MAXLEN];
    char host[EDUI_MAXLEN];
    char dn[EDUI_MAXLEN];
    char passwd[EDUI_MAXLEN];
    char search_filter[EDUI_MAXLEN];                 	/* search_group gets appended here by GroupLDAP */
    char search_ip[EDUI_MAXLEN];             	        /* Could be IPv4 or IPv6, set by ConvertIP */
    char userid[EDUI_MAXLEN];                                /* Resulting userid */
    unsigned int status;
    unsigned int port;
    unsigned long type;         	                /* Type of bind */
    int ver;
    int scope;
    int err;						/* LDAP error code */
    time_t idle_time;
    int num_ent;                                        /* Number of entry's found via search */
    int num_val;                                        /* Number of value's found via getval */
} edui_ldap_t;

/* Global function prototypes */
/* DISABLED BELOW IN FAVOR OF SQUID debug() */
//void local_debug(const char *, const char *,...);
//void local_debugx(const char *,...);
void local_printfx(const char *,...);
int SplitString(char *, size_t, char, char *, size_t);
static void DisplayVersion();
static void DisplayUsage();
static void InitConf();
static void DisplayConf();
static void InitLDAP(edui_ldap_t *);
int OpenLDAP(edui_ldap_t *, char *, unsigned int);
int CloseLDAP(edui_ldap_t *);
int SetVerLDAP(edui_ldap_t *, int);
int BindLDAP(edui_ldap_t *, char *, char *, unsigned int);
int ConvertIP(edui_ldap_t *, char *);
int ResetLDAP(edui_ldap_t *);
int SearchFilterLDAP(edui_ldap_t *, char *);
int SearchLDAP(edui_ldap_t *, int, char *, char **);
int GetValLDAP(edui_ldap_t *, char *);
int SearchIPLDAP(edui_ldap_t *, char *);
const char *ErrLDAP(int);
void SigTrap(int);

/* Global variables */
const char *search_attrib[] = { "cn", "uid", "networkAddress", "groupMembership", NULL };
edui_conf_t edui_conf;
edui_ldap_t edui_ldap;
time_t edui_now;
time_t edui_elap;

/* local_debug() -
 *
 * Print formatted message of func() to stderr if EDUI_MODE_DEBUG is set.
 *
 */
/*
void local_debug(const char *func, const char *msg,...)
{
    char prog[EDUI_MAXLEN], dbuf[EDUI_MAXLEN], cbuf[EDUI_MAXLEN], bbuf[EDUI_MAXLEN];
    size_t sz, x;
    va_list ap;
    if (!(edui_conf.mode & EDUI_MODE_DEBUG))
        return;

    if (edui_conf.program[0] == '\0')
        xstrncpy(prog, EDUI_PROGRAM_NAME, strlen(EDUI_PROGRAM_NAME));
    else
        xstrncpy(prog, edui_conf.program, strlen(edui_conf.program));
    if ((func == NULL) || (msg == NULL) || (strlen(prog) > 256)) {
        snprintf(dbuf, sizeof(dbuf), "%s: local_debug() EPIC FAILURE.\n", prog);
        fputs(dbuf, stderr);
        return;
    }
    sz = sizeof(dbuf);
    memset(cbuf, '\0', strlen(cbuf));
    xstrncpy(cbuf, prog, strlen(prog));
    strncat(cbuf, ": [DB] ", 7);
    strncat(cbuf, func, strlen(func));
    strncat(cbuf, "() - ", 5);
    va_start(ap, msg);
    x = vsnprintf(dbuf, sz, msg, ap);
    va_end(ap);
    if (x > 0) {
        strncat(cbuf, dbuf, x);
        fputs(cbuf, stderr);
        memset(dbuf, '\0', strlen(dbuf));
    } else {
        snprintf(bbuf, sz, "%s: local_debug(%s) FAILURE: %zd\n", prog, dbuf, x);
        fputs(bbuf, stderr);
    }
}
*/
/* local_debugx() -
 *
 * Print formatted message to stderr if EDUI_MODE_DEBUG is set, without preformatting.
 *
 */
/*
void local_debugx(const char *msg,...)
{
    char prog[EDUI_MAXLEN], dbuf[EDUI_MAXLEN], bbuf[EDUI_MAXLEN];
    size_t sz, x;
    va_list ap;
    if (!(edui_conf.mode & EDUI_MODE_DEBUG))
        return;

    if (edui_conf.program[0] == '\0')
        xstrncpy(prog, EDUI_PROGRAM_NAME, strlen(EDUI_PROGRAM_NAME));
    else
        xstrncpy(prog, edui_conf.program, strlen(edui_conf.program));
    if ((msg == NULL) || (strlen(prog) > 256)) {
        snprintf(dbuf, sizeof(dbuf), "%s: local_debugx() EPIC FAILURE.\n", prog);
        fputs(dbuf, stderr);
        return;
    }
    sz = sizeof(dbuf);
    va_start(ap, msg);
    x = vsnprintf(dbuf, sz, msg, ap);
    va_end(ap);
    if (x > 0) {
        fputs(dbuf, stderr);
        memset(dbuf, '\0', strlen(dbuf));
    } else {
        snprintf(bbuf, sz, "%s: local_debugx(%s) FAILURE: %zd\n", prog, dbuf, x);
        fputs(bbuf, stderr);
    }
}
*/

/* local_printfx() -
 *
 * Print formatted message to stderr AND stdout, without preformatting.
 *
 */
void local_printfx(const char *msg,...)
{
    char prog[EDUI_MAXLEN], dbuf[EDUI_MAXLEN];
    size_t sz, x;
    va_list ap;

    if (edui_conf.program[0] == '\0')
        xstrncpy(prog, EDUI_PROGRAM_NAME, strlen(EDUI_PROGRAM_NAME));
    else
        xstrncpy(prog, edui_conf.program, strlen(edui_conf.program));

    if ((msg == NULL) || (strlen(prog) > 256)) {
        /* FAIL */
/*
        snprintf(dbuf, sizeof(dbuf), "%s: local_printfx() EPIC FAILURE.\n", prog);
        fputs(dbuf, stderr);
*/
        debug("local_printfx() EPIC FAIL.\n");
        return;
    }
    sz = sizeof(dbuf);
    va_start(ap, msg);
    x = vsnprintf(dbuf, sz, msg, ap);
    va_end(ap);
    if (x > 0) {
        dbuf[x] = '\0';
        x++;
        fputs(dbuf, stdout);
        memset(dbuf, '\0', strlen(dbuf));
    } else {
        /* FAIL */
/*
        snprintf(bbuf, sz, "%s: local_printfx(%s) FAILURE: %zd\n", prog, dbuf, x);
        fputs(bbuf, stderr);
*/
        debug("local_printfx() FAILURE: %zd\n", x);
    }

    /* stdout needs to be flushed for it to work with Squid */
    fflush(stdout);
}

/*
 * SplitString() - <string> <string-size> <char> <split-object> <obj-size>
 *
 * Breaks down string, splitting out element <char> into <split-object>, and removing it from string.
 * Will not exceed size tolerances.
 *
 * NOTE:  We could have used a strchr() pointer, but then '\0' would break it.
 *       (Which DOES commonly exist in IP Addressing)
 *
 */
int SplitString(char *input, size_t insz, char c, char *obj, size_t objsz)
{
    size_t i, j;
    int swi;
    char buf[EDUI_MAXLEN];
    if ((input == NULL) || (obj == NULL) || (insz <= 0) || (objsz <= 0)) return -1;

    /* Copy input, and clear */
    memset(buf, '\0', sizeof(buf));
    memcpy(buf, input, insz);
    memset(input, '\0', insz);
    memset(obj, '\0', objsz);
    j = 0;                /* obj position */
    swi = 0;              /* found data yet ? */

    /* Scan for data, and copy */
    for (i = 0; i < insz; i++) {
        /* Scan input for first non-space character */
        if (buf[i] != c) {
            if (swi == 0) {
                swi++;          /* Data found, begin copying. */
                obj[j] = buf[i];
                j++;
            } else if (swi == 1) {
                obj[j] = buf[i];
                j++;
            } else
                break;          /* end of data */
        } else {
            /* Found a character c */
            if (swi == 1)
                swi++;
            else if (swi == 2)
                break;          /* end of data */
        }
    }
    obj[j] = '\0';        /* Terminate, i = point of split */

    j = 0;                /* Position of input */
    for (; i < insz; i++) {
        /*      Commented out for BINARY MODE, ie. May have '\0' as legit data *
            if (buf[i] == '\0')
              break;
        */
        input[j] = buf[i];
        j++;
    }
    /* Should be correctly split back into input, and
     * split object in obj.  memset() at next call will
     * clear array data.
     */
    i = strlen(input);
    j = strlen(obj);

    return j;
}

/* Displays version information */
static void DisplayVersion()
{
    local_printfx("Squid eDirectory IP Lookup Helper %s.  Copyright (C) 2009, 2010 Chad E. Naugle\n", EDUI_PROGRAM_VERSION);
}

/* Displays program usage information */
static void DisplayUsage()
{
    DisplayVersion();
    local_printfx("\n");
    local_printfx("Usage: %s\n", edui_conf.program);
    local_printfx("		-H <host> -p <port> [-Z] [-P] [-v 3] -b <basedn> -s <scope>\n");
    local_printfx("		-D <binddn> -W <bindpass> -F <search-filter> [-G] \n\n");
    local_printfx("	-d	    : Debug Mode.\n");
    local_printfx("	-4	    : Force Addresses to be in IPv4 (127.0.0.1 format).\n");
    local_printfx("	-6	    : Force Addresses to be in IPv6 (::1 format).\n");
    local_printfx("	-H <host>   : Specify hostname/ip of server.\n");
    local_printfx("	-p <port>   : Specify port number. (Range 1-65535)\n");
    local_printfx("	-Z	    : Enable TLS security.\n");
    local_printfx("	-P	    : Use persistent connections.\n");
    local_printfx("	-t <sec>    : Timeout factor for persistent connections.  (Default is 60 sec, set to 0 for never timeout)\n");
    local_printfx("	-v <1,2,3>  : Set LDAP version to 1, 2, or 3.\n");
    local_printfx("	-b <base>   : Specify Base DN. (ie. \"o=ORG\")\n");
    local_printfx("	-s <scope>  : Specify LDAP Search Scope (base, one, sub; defaults to 'one').\n");
    local_printfx("	-D <dn>     : Specify Binding DN. (ie. cn=squid,o=ORG)\n");
    local_printfx("	-W <pass>   : Specify Binding password.\n");
    local_printfx("	-u <attrib> : Set userid attribute (Defaults to \"cn\").\n");
    local_printfx("	-F <filter> : Specify LDAP search filter. (ie. \"(objectClass=User)\")\n");
    local_printfx("	-G 	    : Specify if LDAP search group is required. (ie. \"groupMembership=\")\n");
    local_printfx("	-V	    : Display version & exit.\n");
    local_printfx("	-h	    : This screen & exit.\n");
    local_printfx("\n");
}

/* Initalizes program's configuration paremeters */
static void InitConf()
{
    memset(edui_conf.program, '\0', sizeof(edui_conf.program));
    memset(edui_conf.basedn, '\0', sizeof(edui_conf.basedn));
    memset(edui_conf.host, '\0', sizeof(edui_conf.host));
    memset(edui_conf.attrib, '\0', sizeof(edui_conf.attrib));
    memset(edui_conf.dn, '\0', sizeof(edui_conf.dn));
    memset(edui_conf.passwd, '\0', sizeof(edui_conf.passwd));
    memset(edui_conf.search_filter, '\0', sizeof(edui_conf.search_filter));
    edui_conf.scope = -1;
    edui_conf.ver = -1;
    edui_conf.port = -1;
    edui_conf.persist_timeout = -1;
    edui_conf.mode = 0;
    edui_conf.mode |= EDUI_MODE_INIT;

    /* Set defaults from compile-time-options */
#ifdef EDUI_BASE_DN
    xstrncpy(edui_conf.basedn, EDUI_BASE_DN, sizeof(edui_conf.basedn));
#endif
#ifdef EDUI_DEFAULT_HOST
    xstrncpy(edui_conf.host, EDUI_DEFAULT_HOST, sizeof(edui_conf.host));
#endif
#ifdef EDUI_BIND_DN
    xstrncpy(edui_conf.dn, EDUI_BIND_DN, sizeof(edui_conf.dn));
#endif
#ifdef EDUI_BIND_PASS
    xstrncpy(edui_conf.passwd, EDUI_BIND_PASS, sizeof(edui_conf.passwd));
#endif
#ifdef EDUI_USER_ATTRIB
    xstrncpy(edui_conf.attrib, EDUI_USER_ATTRIB, sizeof(edui_conf.attrib));
#endif
#ifdef EDUI_SEARCH_FILTER
    xstrncpy(edui_conf.search_filter, EDUI_SEARCH_FILTER, sizeof(edui_conf.search_filter));
#endif
#ifdef EDUI_SEARCH_SCOPE
    if (!strcmp(EDUI_SEARCH_SCOPE, "base"))
        edui_conf.scope = 0;
    else if (!strcmp(EDUI_SEARCH_SCOPE, "one"))
        edui_conf.scope = 1;
    else if (!strcmp(EDUI_SEARCH_SCOPE, "sub"))
        edui_conf.scope = 2;
    else
        edui_conf.scope = 1;
#endif
#ifdef EDUI_LDAP_VERSION
    edui_conf.ver = EDUI_LDAP_VERSION;
#endif
#ifdef EDUI_DEFAULT_PORT
    edui_conf.port = EDUI_DEFAULT_PORT;
#endif
#ifdef EDUI_FORCE_IPV4
    edui_conf.mode |= EDUI_MODE_IPV4;
#endif
#ifdef EDUI_FORCE_IPV6
    edui_conf.mode |= EDUI_MODE_IPV6;
#endif
#ifdef EDUI_USE_TLS
    edui_conf.mode |= EDUI_MODE_TLS;
#endif
#ifdef EDUI_USE_PERSIST
    edui_conf.mode |= EDUI_MODE_PERSIST;
#endif
#ifdef EDUI_PERSIST_TIMEOUT
    edui_conf.persist_timeout = EDUI_PERSIST_TIMEOUT;
#endif
#ifdef EDUI_GROUP_REQUIRED
    edui_conf.mode |= EDUI_MODE_GROUP;
#endif
#ifdef EDUI_DEBUG
    edui_conf.mode |= EDUI_MODE_DEBUG;
#endif
}

/* Displays running configuration */
static void DisplayConf()
{
    if (!(edui_conf.mode & EDUI_MODE_DEBUG))
        return;
    DisplayVersion();
    local_printfx("\n");
    local_printfx("Configuration:\n");
    local_printfx("	EDUI_MAXLEN: %zd\n", EDUI_MAXLEN);
    if (edui_conf.mode & EDUI_MODE_DEBUG)
        local_printfx("	Debug mode: ON\n");
    else
        local_printfx("	Debug mode: OFF\n");
    if (edui_conf.mode & EDUI_MODE_IPV4)
        local_printfx("	Address format: IPv4 (127.0.0.1)\n");
    else if (edui_conf.mode & EDUI_MODE_IPV6)
        local_printfx("	Address format: IPv6 (::1)\n");
    else
        local_printfx("	Address format: Not enforced.\n");
    if (edui_conf.host[0] != '\0')
        local_printfx("	Hostname: %s\n", edui_conf.host);
    else
        local_printfx("	Hostname: localhost\n");
    if (edui_conf.port > 0)
        local_printfx("	Port: %d\n", edui_conf.port);
    else
        local_printfx("	Port: %d\n", LDAP_PORT);
    if (edui_conf.mode & EDUI_MODE_TLS)
        local_printfx("	TLS mode: ON\n");
    else
        local_printfx("	TLS mode: OFF\n");
    if (edui_conf.mode & EDUI_MODE_PERSIST) {
        local_printfx("	Persistent mode: ON\n");
        if (edui_conf.persist_timeout > 0)
            local_printfx("	Persistent mode idle timeout: %d\n", edui_conf.persist_timeout);
        else
            local_printfx("	Persistent mode idle timeout: OFF\n");
    } else
        local_printfx("	Persistent mode: OFF\n");
    local_printfx("	LDAP Version: %d\n", edui_conf.ver);
    if (edui_conf.basedn[0] != '\0')
        local_printfx("	Base DN: %s\n", edui_conf.basedn);
    else
        local_printfx("	Base DN: None\n");
    if (edui_conf.dn[0] != '\0')
        local_printfx("	Binding DN: %s\n", edui_conf.dn);
    else
        local_printfx("	Binding DN: Anonymous\n");
    if (edui_conf.passwd[0] != '\0')
        local_printfx("	Binding Password: %s\n", edui_conf.passwd);
    else
        local_printfx("	Binding Password: None\n");
    switch (edui_conf.scope) {
    case 0:
        local_printfx("	Search Scope: base\n");
        break;
    case 1:
        local_printfx("	Search Scope: one level\n");
        break;
    case 2:
        local_printfx("	Search Scope: subtree\n");
        break;
    default:
        local_printfx("	Search Scope: base\n");
        break;
    }
    if (edui_conf.attrib[0] != '\0')
        local_printfx("	Search Attribute: %s\n", edui_conf.attrib);
    else
        local_printfx("	Search Attribute: cn\n");
    if (edui_conf.search_filter[0] != '\0')
        local_printfx("	Search Filter: %s\n", edui_conf.search_filter);
    else
        local_printfx("	Search Filter: (&(objectClass=User)(networkAddress=*))\n");
    if (edui_conf.mode & EDUI_MODE_GROUP)
        local_printfx("	Search Group Required: Yes\n");
    else
        local_printfx("	Search Group Required: No\n");
    local_printfx("\n");
}

/* InitLDAP() - <edui_ldap_t>
 *
 * Initalize LDAP structure for use, zeroing out all variables.
 *
 */
static void InitLDAP(edui_ldap_t *l)
{
    if (l == NULL) return;			/* Duh! */

    l->lp = NULL;
    if (l->lm != NULL)
        ldap_msgfree(l->lm);
    if (l->val != NULL)
        ldap_value_free_len(l->val);
    l->lm = NULL;
    l->val = NULL;
    memset(l->basedn, '\0', sizeof(l->basedn));
    memset(l->host, '\0', sizeof(l->host));
    memset(l->dn, '\0', sizeof(l->dn));
    memset(l->passwd, '\0', sizeof(l->passwd));
    memset(l->search_filter, '\0', sizeof(l->search_filter));
    memset(l->search_ip, '\0', sizeof(l->search_ip));
    memset(l->userid, '\0', sizeof(l->userid));
    l->status = 0;
    l->status |= LDAP_INIT_S;
    l->port = 0;
    l->scope = -1;
    l->type = 0;
    l->err = -1;					/* Set error to LDAP_SUCCESS by default */
    l->ver = 0;
    l->idle_time = 0;
    l->num_ent = 0;				/* Number of entries in l->lm */
    l->num_val = 0;				/* Number of entries in l->val */

    /* Set default settings from conf */
    if (edui_conf.basedn[0] != '\0')
        xstrncpy(l->basedn, edui_conf.basedn, sizeof(l->basedn));
    if (edui_conf.host[0] != '\0')
        xstrncpy(l->host, edui_conf.host, sizeof(l->host));
    if (edui_conf.port != 0)
        l->port = edui_conf.port;
    if (edui_conf.dn[0] != '\0')
        xstrncpy(l->dn, edui_conf.dn, sizeof(l->dn));
    if (edui_conf.passwd[0] != '\0')
        xstrncpy(l->passwd, edui_conf.passwd, sizeof(l->passwd));
    if (edui_conf.search_filter[0] != '\0')
        xstrncpy(l->search_filter, edui_conf.search_filter, sizeof(l->search_filter));
    if (!(edui_conf.scope < 0))
        l->scope = edui_conf.scope;
//    * We Dont Need Bit-Status updates in gerneal debugging. *
//    debug("New status = %u\n", l->status);
}

/* OpenLDAP() - <edui_ldap_t> <host> <port>
 *
 * Build LDAP struct with hostname and port, and ready it for binding.
 *
 */
int OpenLDAP(edui_ldap_t *l, char *h, unsigned int p)
{
    if ((l == NULL) || (h == NULL)) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized, or might be in use */
    if (l->status & LDAP_OPEN_S) return LDAP_ERR_OPEN;		/* Already open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */

    xstrncpy(l->host, h, sizeof(l->host));
    if (p > 0)
        l->port = p;
    else
        l->port = LDAP_PORT;				/* Default is port 389 */

#ifdef NETSCAPE_SSL
    if (l->port == LDAPS_PORT)
        l->status |= (LDAP_SSL_S | LDAP_TLS_S);		/* SSL Port: 636 */
#endif

#ifdef USE_LDAP_INIT
    l->lp = ldap_init(l->host, l->port);
#else
    l->lp = ldap_open(l->host, l->port);
#endif
    if (l->lp == NULL) {
        l->err = LDAP_CONNECT_ERROR;
        return LDAP_ERR_CONNECT;				/* Unable to connect */
    } else {
        /* set status */
//    l->status &= ~(LDAP_INIT_S);
        l->status |= LDAP_OPEN_S;
        l->err = LDAP_SUCCESS;
        return LDAP_ERR_SUCCESS;
    }
}

/* CloseLDAP() - <edui_ldap_t>
 *
 * Close LDAP connection, and clean up data structure.
 *
 */
int CloseLDAP(edui_ldap_t *l)
{
    int s;
    if (l == NULL) return LDAP_ERR_NULL;
    if (l->lp == NULL) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Connection not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Connection not open */

    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    if (l->val != NULL) {
        ldap_value_free_len(l->val);
        l->val = NULL;
    }

    /* okay, so it's open, close it - No need to check other criteria */
    s = ldap_unbind(l->lp);
    if (s == LDAP_SUCCESS) {
        l->status = LDAP_INIT_S;
//        * We Dont Need Bit-Status updates in gerneal debugging. *
//        debug("New status = %u\n", l->status);
        l->idle_time = 0;
        l->err = s;							/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;							/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/* SetVerLDAP() - <edui_ldap_t> <version>
 *
 * Set LDAP version number for connection to <version> of 1, 2, or 3
 *
 */
int SetVerLDAP(edui_ldap_t *l, int v)
{
    int x;
    if (l == NULL) return LDAP_ERR_NULL;
    if ((v > 3) || (v < 1)) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Not open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */

    /* set version */
    x = ldap_set_option(l->lp, LDAP_OPT_PROTOCOL_VERSION, &v);
    if (x == LDAP_SUCCESS) {
        l->ver = v;
        l->err = x;							/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = x;							/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/* BindLDAP() - <edui_ldap_t> <use-dn> <use-password> <type>
 *
 * Bind LDAP connection (Open) using optional dn and password, of <type>
 *
 */
int BindLDAP(edui_ldap_t *l, char *dn, char *pw, unsigned int t)
{
    int s;
    if (l == NULL) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Not open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */
    if (l->lp == NULL) return LDAP_ERR_POINTER;			/* Error */

    /* Copy details - dn and pw CAN be NULL for anonymous and/or TLS */
    if (dn != NULL) {
        if ((l->basedn[0] != '\0') && (strstr(dn, l->basedn) == NULL)) {
            /* We got a basedn, but it's not part of dn */
            xstrncpy(l->dn, dn, sizeof(l->dn));
            strncat(l->dn, ",", 1);
            strncat(l->dn, l->basedn, strlen(l->basedn));
        } else
            xstrncpy(l->dn, dn, sizeof(l->dn));
    }
    if (pw != NULL)
        xstrncpy(l->passwd, pw, sizeof(l->passwd));

    /* Type ? */
    switch (t) {
    case LDAP_AUTH_NONE:
        l->type = t;
        break;
    case LDAP_AUTH_SIMPLE:
        l->type = t;
        break;
    case LDAP_AUTH_SASL:
        l->type = t;
        break;
#ifdef LDAP_AUTH_KRBV4
    case LDAP_AUTH_KRBV4:
        l->type = t;
        break;
#endif
#ifdef LDAP_AUTH_KRBV41
    case LDAP_AUTH_KRBV41:
        l->type = t;
        break;
#endif
#ifdef LDAP_AUTH_KRBV42
    case LDAP_AUTH_KRBV42:
        l->type = t;
        break;
#endif
#ifdef LDAP_AUTH_TLS
    case LDAP_AUTH_TLS:					/* Added for chicken switch to TLS-enabled without using SSL */
        l->type = t;
        break;
#endif
    default:
        l->type = LDAP_AUTH_NONE;
        break;						/* Default to anonymous bind */
    }

    /* Bind */
#if defined(LDAP_AUTH_TLS) && defined(NETSCAPE_SSL) && HAVE_LDAP_START_TLS_S
    if (l->type == LDAP_AUTH_TLS)
        s = ldap_start_tls_s(l->lp, NULL, NULL);
    else
#endif
        s = ldap_bind_s(l->lp, l->dn, l->passwd, l->type);
    if (s == LDAP_SUCCESS) {
        l->status |= LDAP_BIND_S;				/* Success */
        l->err = s;						/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;						/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/*
 * ConvertIP() - <edui_ldap_t> <ip>
 *
 * Take an IPv4 address in dot-decimal or IPv6 notation, and convert to 2-digit HEX stored in l->search_ip
 * This is the networkAddress that we search LDAP for.
 *
 * PENDING -- CHANGE OVER TO inet*_pton
 *
 */
int ConvertIP(edui_ldap_t *l, char *ip)
{
    char bufa[EDUI_MAXLEN], bufb[EDUI_MAXLEN], obj[EDUI_MAXLEN];
    char hexc[4], *p;
    void *y, *z;
    size_t s;
    long x;
    int i, j, t, swi;								/* IPv6 "::" cut over toggle */
    if (l == NULL) return LDAP_ERR_NULL;
    if (ip == NULL) return LDAP_ERR_PARAM;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */

    y = memchr((void *)ip, ':', EDUI_MAXLEN);
    z = memchr((void *)ip, '.', EDUI_MAXLEN);
    if ((y != NULL) && (z != NULL)) {
        y = NULL;
        z = NULL;
        return LDAP_ERR_INVALID;
    }
    if ((y != NULL) && (edui_conf.mode & EDUI_MODE_IPV4)) {
        /* IPv4 Mode forced */
        return LDAP_ERR_INVALID;
    } else if (y != NULL) {
        /* Set IPv6 mode */
// Taboo debug() call.
        debug("Setting IPv6 Mode.\n");
        if (l->status & LDAP_IPV4_S)
            l->status &= ~(LDAP_IPV4_S);
        if (!(l->status & LDAP_IPV6_S))
            l->status |= (LDAP_IPV6_S);
        y = NULL;
    }
    if ((z != NULL) && (edui_conf.mode & EDUI_MODE_IPV6)) {
        /* IPv6 Mode forced */
        return LDAP_ERR_INVALID;
    } else if (z != NULL) {
// Taboo debug() call.
        debug("Setting IPv4 Mode.\n");
        /* Set IPv4 mode */
        if (l->status & LDAP_IPV6_S)
            l->status &= ~(LDAP_IPV6_S);
        if (!(l->status & LDAP_IPV4_S))
            l->status |= (LDAP_IPV4_S);
        z = NULL;
    }
    s = strlen(ip);
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(obj, '\0', sizeof(obj));
    /* SplitString() will zero out bufa & obj at each call */
    memset(l->search_ip, '\0', sizeof(l->search_ip));
    xstrncpy(bufa, ip, sizeof(bufa));						/* To avoid segfaults, use bufa instead of ip */
    swi = 0;
    if (l->status & LDAP_IPV6_S) {
        /* Search for :: in string */
        if ((bufa[0] == ':') && (bufa[1] == ':')) {
            /* bufa starts with a ::, so just copy and clear */
            xstrncpy(bufb, bufa, sizeof(bufa));
            memset(bufa, '\0', strlen(bufa));
            swi++;								/* Indicates that there is a bufb */
        } else if ((bufa[0] == ':') && (bufa[1] != ':')) {
            /* bufa starts with a :, a typo so just fill in a ':', cat and clear */
            bufb[0] = ':';
            strncat(bufb, bufa, strlen(bufa));
            memset(bufa, '\0', strlen(bufa));
            swi++;								/* Indicates that there is a bufb */
        } else {
            p = strstr(bufa, "::");
            if (p != NULL) {
                /* Found it, break bufa down and split into bufb here */
                memset(bufb, '\0', strlen(bufb));
                i = strlen(p);
                memcpy(bufb, p, i);
                *p = '\0';
                bufb[i] = '\0';
                swi++;								/* Indicates that there is a bufb */
            }
        }
    }
    s = strlen(bufa);
    if (s < 1)
        s = strlen(bufb);
    while (s > 0) {
        if ((l->status & LDAP_IPV4_S) && (swi == 0)) {
            /* Break down IPv4 address  */
            t = SplitString(bufa, s, '.', obj, sizeof(obj));
            if (t > 0) {
                errno = 0;
                x = strtol(obj, (char **)NULL, 10);
                if (((x < 0) || (x > 255)) || ((errno != 0) && (x == 0)) || ((obj[0] != '0') && (x == 0)))
                    return LDAP_ERR_OOB;						/* Out of bounds -- Invalid address */
                memset(hexc, '\0', sizeof(hexc));
                int hlen = snprintf(hexc, sizeof(hexc), "%.2X", (int)x);
                strncat(l->search_ip, hexc, hlen);
            } else
                break;								/* reached end of octet */
        } else if (l->status & LDAP_IPV6_S) {
            /* Break down IPv6 address */
            if (swi > 1)
                t = SplitString(bufb, s, ':', obj, sizeof(obj));		/* After "::" */
            else
                t = SplitString(bufa, s, ':', obj, sizeof(obj));		/* Before "::" */
            /* Convert octet by size (t) - and fill 0's */
            switch (t) {							/* IPv6 is already in HEX, copy contents */
            case 4:
                hexc[0] = (char) toupper((int)obj[0]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[1]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                hexc[0] = (char) toupper((int)obj[2]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[3]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                break;
            case 3:
                hexc[0] = '0';
                hexc[1] = (char) toupper((int)obj[0]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                hexc[0] = (char) toupper((int)obj[1]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[2]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                break;
            case 2:
                strncat(l->search_ip, "00", 2);
                hexc[0] = (char) toupper((int)obj[0]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[1]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                break;
            case 1:
                strncat(l->search_ip, "00", 2);
                hexc[0] = '0';
                hexc[1] = (char) toupper((int)obj[0]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, 2);
                break;
            default:
                if (t > 4)
                    return LDAP_ERR_OOB;
                break;
            }
            /* Code to pad the address with 0's between a '::' */
            if ((strlen(bufa) == 0) && (swi == 1)) {
                /* We are *AT* the split, pad in some 0000 */
                t = strlen(bufb);
                /* How many ':' exist in bufb ? */
                j = 0;
                for (i = 0; i < t; i++) {
                    if (bufb[i] == ':')
                        j++;
                }
                j--;								/* Preceeding "::" doesn't count */
                t = 8 - (strlen(l->search_ip) / 4) - j;			/* Remainder */
                if (t > 0) {
                    for (i = 0; i < t; i++)
                        strncat(l->search_ip, "0000", 4);
                }
            }
        }
        if ((bufa[0] == '\0') && (swi > 0)) {
            s = strlen(bufb);
            swi++;
        } else
            s = strlen(bufa);
    }
    s = strlen(l->search_ip);

    /* CHECK sizes of address, truncate or pad */
    /* if "::" is at end of ip, then pad another block or two */
    while ((l->status & LDAP_IPV6_S) && (s < 32)) {
        strncat(l->search_ip, "0000", 4);
        s = strlen(l->search_ip);
    }
    if ((l->status & LDAP_IPV6_S) && (s > 32)) {
        /* Too long, truncate */
        l->search_ip[32] = '\0';
        s = strlen(l->search_ip);
    }
    /* If at end of ip, and its not long enough, then pad another block or two */
    while ((l->status & LDAP_IPV4_S) && (s < 8)) {
        strncat(l->search_ip, "00", 2);
        s = strlen(l->search_ip);
    }
    if ((l->status & LDAP_IPV4_S) && (s > 8)) {
        /* Too long, truncate */
        l->search_ip[8] = '\0';
        s = strlen(l->search_ip);
    }

    /* Completed, s is length of address in HEX */
    return s;
}

/* ResetLDAP() - <edui_ldap_t>
 *
 * Resets LDAP connection for next search query.
 *
 */
int ResetLDAP(edui_ldap_t *l)
{
    if (l == NULL) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;                 /* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;                 /* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;                 /* Not bound */
    if (!(l->status & LDAP_PERSIST_S)) return LDAP_ERR_PERSIST;           /* Not persistent */

    /* Cleanup data struct */
//    debug("Resetting LDAP connection for next query. (status = %u)\n", l->status);
    if (l->status & LDAP_VAL_S)
        l->status &= ~(LDAP_VAL_S);
    if (l->status & LDAP_SEARCH_S)
        l->status &= ~(LDAP_SEARCH_S);
    if (l->status & LDAP_IPV4_S)
        l->status &= ~(LDAP_IPV4_S);
    if (l->status & LDAP_IPV6_S)
        l->status &= ~(LDAP_IPV6_S);
    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    if (l->val != NULL) {
        ldap_value_free_len(l->val);
        l->val = NULL;
    }
    memset(l->search_ip, '\0', sizeof(l->search_ip));
    memset(l->search_filter, '\0', strlen(l->search_filter));
    xstrncpy(l->search_filter, edui_conf.search_filter, sizeof(l->search_filter));
    memset(l->userid, '\0', strlen(l->userid));
    if (!(l->status & LDAP_IDLE_S))
        l->status |= LDAP_IDLE_S;                                           /* Set idle mode */
    l->num_ent = 0;
    l->num_val = 0;
//    debug("New status = %u\n", l->status);
    l->err = LDAP_SUCCESS;
    return LDAP_ERR_SUCCESS;
}

/*
 * SearchFilterLDAP() - <edui_ldap_t> <IP> <group>
 *
 * Build LDAP Search Filter string and copy to l->search_filter
 *
 */
int SearchFilterLDAP(edui_ldap_t *l, char *group)
{
    size_t i, j, s;
    int swi;
    char bufa[EDUI_MAXLEN], bufb[EDUI_MAXLEN], bufc[EDUI_MAXLEN], bufd[EDUI_MAXLEN], bufg[EDUI_MAXLEN];
    if (l == NULL) return LDAP_ERR_NULL;
//  if (group == NULL) return LDAP_ERR_PARAM;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not Bound */
    if (l->search_ip[0] == '\0') return LDAP_ERR_DATA;				/* Search IP is required */

    /* Zero out if not already */
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(bufc, '\0', sizeof(bufc));
    memset(bufd, '\0', sizeof(bufd));
    memset(bufg, '\0', sizeof(bufg));

//  debug("Building... (Adding '\\' to IP...) - search_ip: %s\n", l->search_ip);
    s = strlen(l->search_ip);
    bufc[0] = '\134';
    swi = 0;
    j = 1;
    for (i = 0; i < s; i++) {
        if (swi == 2) {
            bufc[j] = '\134';
            j++;
            bufc[j] = l->search_ip[i];
            j++;
            swi = 1;
        } else {
            bufc[j] = l->search_ip[i];
            j++;
            swi++;
        }
    }
    if (group == NULL) {
        /* No groupMembership= to add, yay! */
        xstrncpy(bufa, "(&", 2);
        strncat(bufa, edui_conf.search_filter, strlen(edui_conf.search_filter));
        /* networkAddress */
        snprintf(bufb, sizeof(bufb), "(|(networkAddress=1\\23%s)", bufc);
        if (l->status & LDAP_IPV4_S) {
            int ln = snprintf(bufd, sizeof(bufd), "(networkAddress=8\\23\\00\\00%s)(networkAddress=9\\23\\00\\00%s))", \
                              bufc, bufc);
            strncat(bufb, bufd, ln);
        } else if (l->status & LDAP_IPV6_S) {
            int ln = snprintf(bufd, sizeof(bufd), "(networkAddress=10\\23\\00\\00%s)(networkAddress=11\\23\\00\\00%s))", \
                              bufc, bufc);
            strncat(bufb, bufd, ln);
        } else
            strncat(bufb, ")", 1);
        strncat(bufa, bufb, strlen(bufb));
        strncat(bufa, ")", 1);
    } else {
        /* Needs groupMembership= to add... */
        xstrncpy(bufa, "(&(&", 4);
        strncat(bufa, edui_conf.search_filter, strlen(edui_conf.search_filter));
        /* groupMembership -- NOTE: Squid *MUST* provide "cn=" from squid.conf */
        snprintf(bufg, sizeof(bufg), "(groupMembership=%s", group);
        if ((l->basedn[0] != '\0') && (strstr(group, l->basedn) == NULL)) {
            strncat(bufg, ",", 1);
            strncat(bufg, l->basedn, strlen(l->basedn));
        }
        strncat(bufg, ")", 1);
        strncat(bufa, bufg, strlen(bufg));
        /* networkAddress */
        snprintf(bufb, sizeof(bufb), "(|(networkAddress=1\\23%s)", bufc);
        if (l->status & LDAP_IPV4_S) {
            int ln = snprintf(bufd, sizeof(bufd), "(networkAddress=8\\23\\00\\00%s)(networkAddress=9\\23\\00\\00%s))", \
                              bufc, bufc);
            strncat(bufb, bufd, ln);
        } else if (l->status & LDAP_IPV6_S) {
            int ln = snprintf(bufd, sizeof(bufd), "(networkAddress=10\\23\\00\\00%s)(networkAddress=11\\23\\00\\00%s))", \
                              bufc, bufc);
            strncat(bufb, bufd, ln);
        } else
            strncat(bufb, ")", 1);
        strncat(bufa, bufb, strlen(bufb));
        strncat(bufa, "))", 2);
    }
    s = strlen(bufa);
    xstrncpy(l->search_filter, bufa, s);
    return s;
}

/*
 * SearchLDAP() - <edui_ldap_t> <scope> <filter> <attrib>
 *
 * Initate LDAP query, under <scope> levels, filtering matches with <filter> and optionally <attrib>
 * <attrib> will generally be networkAddress ...
 *
 */
int SearchLDAP(edui_ldap_t *l, int scope, char *filter, char **attrs)
{
    int s;
    char ft[EDUI_MAXLEN];
    if (l == NULL) return LDAP_ERR_NULL;
    if ((scope < 0) || (filter == NULL)) return LDAP_ERR_PARAM;		/* If attrs is NULL, then all attrs will return */
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */
    if (l->status & LDAP_SEARCH_S) return LDAP_ERR_SEARCHED;		/* Already searching */
    if (l->basedn[0] == '\0') return LDAP_ERR_DATA;			/* We require a basedn */
    if (l->lm != NULL)
        ldap_msgfree(l->lm);						/* Make sure l->lm is empty */

    if (filter == NULL)							/* if filter is NULL, then return ALL networkAddress */
        xstrncpy(ft, "(&(objectClass=User)(networkAddress=*))", sizeof(ft));
    else
        xstrncpy(ft, filter, sizeof(ft));

    /* We have a binded connection, with a free l->lm, so let's get this done */
    switch (scope) {
    case 0:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_BASE, ft, attrs, 0, &(l->lm));
        break;
    case 1:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_ONELEVEL, ft, attrs, 0, &(l->lm));
        break;
    case 2:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_SUBTREE, ft, attrs, 0, &(l->lm));
        break;
    default:
        /* Only search ONE by default */
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_ONELEVEL, ft, attrs, 0, &(l->lm));
        break;
    }
    if (s == LDAP_SUCCESS) {
        l->status |= (LDAP_SEARCH_S);					/* Mark as searched */
        l->err = s;
        l->idle_time = 0;							/* Connection in use, reset idle timer */
        l->num_ent = ldap_count_entries(l->lp, l->lm);			/* Counted */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;
        l->num_ent = (-1);
        return LDAP_ERR_FAILED;
    }
}

/*
 * GetValLDAP() - <edui_ldap_t> <search-attr>
 *
 * Scan LDAP and look for search-attr, then return results in l->val
 *
 */
int GetValLDAP(edui_ldap_t *l, char *attr)
{
    ber_len_t x;
    /*
      ber_len_t i, j;
      int c;
    */
    LDAPMessage *ent;
    if (l == NULL) return LDAP_ERR_NULL;
    if (attr == NULL) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */
    if (!(l->status & LDAP_SEARCH_S)) return LDAP_ERR_NOT_SEARCHED;	/* Not searched */
    if (l->num_ent <= 0) return LDAP_ERR_DATA;				/* No entries found */
    if (l->val != NULL)
        ldap_value_free_len(l->val);					/* Clear data before populating */
    l->num_val = 0;
    if (l->status & LDAP_VAL_S)
        l->status &= ~(LDAP_VAL_S);						/* Clear VAL bit */

    /* Sift through entries -- Look for matches */
    for (ent = ldap_first_entry(l->lp, l->lm); ent != NULL; ent = ldap_next_entry(l->lp, ent)) {
        l->val = ldap_get_values_len(l->lp, ent, attr);
        if (l->val != NULL) {
            x = ldap_count_values_len(l->val);				/* We got x values ... */
            l->num_val = x;
            if (x > 0) {
                /* Display all values */
                /* DEBUGGING ONLY *
                	for (i = 0; i < x; i++) {
                	  local_debug("GetValLDAP", "value[%zd]: \"%s\"\n", i, l->val[i]->bv_val);
                	  local_debug("GetValLDAP", "value[%zd]: ", i);
                	  for (j = 0; j < (l->val[i]->bv_len); j++) {
                	    c = (int) l->val[i]->bv_val[j];
                	    if (c < 0)
                	      c = c + 256;
                	    local_debugx("%.2X", c);
                	  }
                	  local_debugx("\n");
                	}
                */
                /*	CRASHES?!?!
                	if (ent != NULL)
                	  ldap_msgfree(ent);
                */
                if (l->lm != NULL) {
                    ldap_msgfree(l->lm);
                    l->lm = NULL;
                }
                l->num_ent = 0;
                l->status &= ~(LDAP_SEARCH_S);
                l->status |= LDAP_VAL_S;
                l->err = LDAP_SUCCESS;
                return LDAP_ERR_SUCCESS;					/* Found it */
            }
        }
        /* Attr not found, continue */
    }
    /* No entries found using attr */
    if (l->val != NULL)
        ldap_value_free_len(l->val);
    /*
      if (ent != NULL)
        ldap_msgfree(ent);
    */
    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    l->num_ent = 0;
    l->num_val = 0;
    l->err = LDAP_NO_SUCH_OBJECT;
    l->status &= ~(LDAP_SEARCH_S);
    return LDAP_ERR_NOTFOUND;						/* Not found */
}

/*
 * SearchIPLDAP() - <edui_ldap_t> <result-uid>
 *
 * Scan LDAP and get all networkAddress Values, and see if they match l->search_ip
 * Actual IP matching routine for eDirectory
 *
 */
int SearchIPLDAP(edui_ldap_t *l, char *uid)
{
    ber_len_t i, x;
    ber_len_t j, k;
    ber_len_t y, z;
    int c;
    char bufa[EDUI_MAXLEN], bufb[EDUI_MAXLEN], hexc[4];
    LDAPMessage *ent;
    struct berval **ber;
    if (l == NULL) return LDAP_ERR_NULL;
    if (uid == NULL) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;				/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;				/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;				/* Not bound */
    if (!(l->status & LDAP_SEARCH_S)) return LDAP_ERR_NOT_SEARCHED;			/* Not searched */
    if (l->num_ent <= 0) return LDAP_ERR_DATA;						/* No entries found */
    if (l->val != NULL)
        ldap_value_free_len(l->val);							/* Clear data before populating */
    l->num_val = 0;
    if (l->status & LDAP_VAL_S)
        l->status &= ~(LDAP_VAL_S);							/* Clear VAL bit */
    if (edui_conf.attrib[0] == '\0')
        xstrncpy(edui_conf.attrib, "cn", sizeof(edui_conf.attrib));		/* Make sure edui_conf.attrib is set */

    /* Sift through entries */
    for (ent = ldap_first_entry(l->lp, l->lm); ent != NULL; ent = ldap_next_entry(l->lp, ent)) {
        l->val = ldap_get_values_len(l->lp, ent, "networkAddress");
        ber = ldap_get_values_len(l->lp, ent, edui_conf.attrib);			/* edui_conf.attrib is the <userid> mapping */
        if (l->val != NULL) {
            x = ldap_count_values_len(l->val);						/* We got x values ... */
            l->num_val = x;
            if (x > 0) {
                /* Display all values */
                for (i = 0; i < x; i++) {
                    j = l->val[i]->bv_len;
                    memcpy(bufa, l->val[i]->bv_val, j);
                    z = SplitString(bufa, j, '#', bufb, sizeof(bufb));
                    /* DEBUGGING ONLY *
                    	  local_debug("SearchIPLDAP", "value[%zd]: SplitString(", i);
                    	  for (k = 0; k < z; k++) {
                    	    c = (int) bufb[k];
                    	    if (c < 0)
                    	      c = c + 256;
                    	    local_debugx("%.2X", c);
                    	  }
                    	  local_debugx(", ");
                    	  for (k = 0; k < (j - z - 1); k++) {
                    	    c = (int) bufa[k];
                    	    if (c < 0)
                    	      c = c + 256;
                    	    local_debugx("%.2X", c);
                    	  }
                    	  local_debugx("): %zd\n", z);
                    */
                    z = j - z - 1;
                    j = atoi(bufb);
                    switch (j) {
                    case 0:							/* IPX address (We don't support these right now) */
                        break;
                    case 1:							/* IPv4 address (eDirectory 8.7 and below) */
                        /* bufa is the address, just compare it */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 0; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            int hlen = snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 0)
                                xstrncpy(bufb, hexc, hlen);
                            else
                                strncat(bufb, hexc, hlen);
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (memcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                xstrncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 8:							/* IPv4 (UDP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            int hlen = snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                xstrncpy(bufb, hexc, hlen);
                            else
                                strncat(bufb, hexc, hlen);
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (memcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                xstrncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 9:							/* IPv4 (TCP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            int hlen = snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                xstrncpy(bufb, hexc, hlen);
                            else
                                strncat(bufb, hexc, hlen);
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (memcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                xstrncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 10:							/* IPv6 (UDP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv6 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            int hlen = snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                xstrncpy(bufb, hexc, hlen);
                            else
                                strncat(bufb, hexc, hlen);
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (memcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                xstrncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 11:							/* IPv6 (TCP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv6 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            int hlen = snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                xstrncpy(bufb, hexc, hlen);
                            else
                                strncat(bufb, hexc, hlen);
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (memcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                xstrncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We gout our userid */
                        }
                        /* Not matched, continue */
                        break;
                    default:							/* Other, unsupported */
                        break;
                    }
                }
                if (ber != NULL) {
                    ldap_value_free_len(ber);
                    ber = NULL;
                }
            }
            ldap_value_free_len(l->val);
            l->val = NULL;
        }
        if (ber != NULL) {
            ldap_value_free_len(ber);
            ber = NULL;
        }
        /* Attr not found, continue */
    }
    /* No entries found using given attr */
    if (l->val != NULL) {
        ldap_value_free_len(l->val);
        l->val = NULL;
    }
    if (ber != NULL) {
        ldap_value_free_len(ber);
        ber = NULL;
    }
    if (ent != NULL) {
        ldap_msgfree(ent);
        ent = NULL;
    }
    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    l->num_ent = 0;
    l->num_val = 0;
    l->err = LDAP_NO_SUCH_OBJECT;
    l->status &= ~(LDAP_SEARCH_S);
    return LDAP_ERR_NOTFOUND;						/* Not found ... Sorry :) */
}

const char *ErrLDAP(int e)
{
    switch (e) {
    case LDAP_ERR_NULL:
        return "Null pointer provided";
    case LDAP_ERR_POINTER:
        return "Null LDAP pointer";
    case LDAP_ERR_PARAM:
        return "Null or Missing paremeter(s)";
    case LDAP_ERR_INIT:
        return "LDAP data not initalized";
    case LDAP_ERR_OPEN:
        return "LDAP connection is not active";
    case LDAP_ERR_CONNECT:
        return "Unable to connect to LDAP host";
    case LDAP_ERR_BIND:
        return "LDAP connection is not bound";
    case LDAP_ERR_SEARCHED:
        return "LDAP connection has already been searched";
    case LDAP_ERR_NOT_SEARCHED:
        return "LDAP connection has not been searched";
    case LDAP_ERR_INVALID:
        return "Invalid paremeters";
    case LDAP_ERR_OOB:
        return "Paremeter is out of bounds";
    case LDAP_ERR_PERSIST:
        return "Persistent mode is not active";
    case LDAP_ERR_DATA:
        return "Required data has not been found";
    case LDAP_ERR_NOTFOUND:
        return "Item or object has not been found";
    case LDAP_ERR_OTHER:
        return "An unknown error has occured";
    case LDAP_ERR_FAILED:
        return "Operation has failed";
    case LDAP_ERR_SUCCESS:
        return "Operation is successful";
    default:
        return "An unknown error has occured";
    }
}

/* Signal Trap routine */
void SigTrap(int s)
{
    if (!(edui_conf.mode & EDUI_MODE_KILL))
        edui_conf.mode |= EDUI_MODE_KILL;

    /* Clean Up */
    if (edui_ldap.status & LDAP_OPEN_S)
        CloseLDAP(&edui_ldap);

    debug("Terminating, Signal: %d\n", s);
    exit(0);
}

/* main() - function */
int main(int argc, char **argv)
{
    char bufa[EDUI_MAXLEN], bufb[EDUI_MAXLEN], *p = NULL;
    char bufc[EDUI_MAXLEN];
    char sfmod[EDUI_MAXLEN];
    int x;
    size_t i, j, s, k;
    time_t t;
    struct sigaction sv;

    /* Init */
    k = (size_t) argc;
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(bufc, '\0', sizeof(bufc));
    memset(sfmod, '\0', sizeof(sfmod));
    InitConf();
    xstrncpy(edui_conf.program, argv[0], sizeof(edui_conf.program));
    edui_now = -1;
    t = -1;
//    debug("InitConf() done.\n");

    /* Scan args */
    if (k > 1) {
        for (i = 1; i < k; i++) {
            /* Classic / novelty usage schemes */
            if (!strcmp(argv[i], "--help")) {
                DisplayUsage();
                return 1;
            } else if (!strcmp(argv[i], "--usage")) {
                DisplayUsage();
                return 1;
            } else if (!strcmp(argv[i], "--version")) {
                DisplayVersion();
                return 1;
            } else if (argv[i][0] == '-') {
                s = strlen(argv[i]);
                for (j = 1; j < s; j++) {
                    switch (argv[i][j]) {
                    case 'h':
                        DisplayUsage();
                        return 1;
                    case 'V':
                        DisplayVersion();
                        return 1;
                    case 'd':
                        if (!(edui_conf.mode & EDUI_MODE_DEBUG))
                            edui_conf.mode |= EDUI_MODE_DEBUG;		/* Don't set mode more than once */
                        debug_enabled = 1;				/* Squid-3 Debug Mode */
                        break;
                    case '4':
                        if (!(edui_conf.mode & EDUI_MODE_IPV4) || !(edui_conf.mode & EDUI_MODE_IPV6))
                            edui_conf.mode |= EDUI_MODE_IPV4;			/* Don't set mode more than once */
                        break;
                    case '6':
                        if (!(edui_conf.mode & EDUI_MODE_IPV4) || !(edui_conf.mode & EDUI_MODE_IPV6))
                            edui_conf.mode |= EDUI_MODE_IPV6;			/* Don't set mode more than once */
                        break;
                    case 'Z':
                        if (!(edui_conf.mode & EDUI_MODE_TLS))
                            edui_conf.mode |= EDUI_MODE_TLS;			/* Don't set mode more than once */
                        break;
                    case 'P':
                        if (!(edui_conf.mode & EDUI_MODE_PERSIST))
                            edui_conf.mode |= EDUI_MODE_PERSIST;			/* Don't set mode more than once */
                        break;
                    case 'v':
                        i++;
                        if (argv[i] != NULL) {
                            edui_conf.ver = atoi(argv[i]);
                            if (edui_conf.ver < 1)
                                edui_conf.ver = 1;
                            else if (edui_conf.ver > 3)
                                edui_conf.ver = 3;
                        } else {
                            local_printfx("No parameters given for 'v'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 't':
                        i++;
                        if (argv[i] != NULL) {
                            edui_conf.persist_timeout = atoi(argv[i]);
                            if (edui_conf.persist_timeout < 0)
                                edui_conf.persist_timeout = 0;
                        } else {
                            local_printfx("No parameters given for 't'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'b':
                        i++;					/* Set Base DN */
                        if (argv[i] != NULL)
                            xstrncpy(edui_conf.basedn, argv[i], sizeof(edui_conf.basedn));
                        else {
                            local_printfx("No parameters given for 'b'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'H':
                        i++;					/* Set Hostname */
                        if (argv[i] != NULL)
                            xstrncpy(edui_conf.host, argv[i], sizeof(edui_conf.host));
                        else {
                            local_printfx("No parameters given for 'H'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'p':
                        i++;					/* Set port */
                        if (argv[i] != NULL)
                            edui_conf.port = atoi(argv[i]);
                        else {
                            local_printfx("No parameters given for 'p'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'D':
                        i++;					/* Set Bind DN */
                        if (argv[i] != NULL)
                            xstrncpy(edui_conf.dn, argv[i], sizeof(edui_conf.dn));
                        else {
                            local_printfx("No parameters given for 'D'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'W':
                        i++;					/* Set Bind PWD */
                        if (argv[i] != NULL)
                            xstrncpy(edui_conf.passwd, argv[i], sizeof(edui_conf.passwd));
                        else {
                            local_printfx("No parameters given for 'W'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'F':
                        i++;					/* Set Search Filter */
                        if (argv[i] != NULL)
                            xstrncpy(edui_conf.search_filter, argv[i], sizeof(edui_conf.search_filter));
                        else {
                            local_printfx("No parameters given for 'F'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'G':
                        if (!(edui_conf.mode & EDUI_MODE_GROUP))
                            edui_conf.mode |= EDUI_MODE_GROUP;		/* Don't set mode more than once */
                        break;
                    case 's':
                        i++;					/* Set Scope Level */
                        if (argv[i] != NULL) {
                            if (!strncmp(argv[i], "base", 4))
                                edui_conf.scope = 0;
                            else if (!strncmp(argv[i], "one", 4))
                                edui_conf.scope = 1;
                            else if (!strncmp(argv[i], "sub", 4))
                                edui_conf.scope = 2;
                            else
                                edui_conf.scope = 1;			/* Default is 'one' */
                        } else {
                            local_printfx("No parameters given for 's'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'u':
                        i++;						/* Set Search Attribute */
                        if (argv[i] != NULL) {
			    xstrncpy(edui_conf.attrib, argv[i], sizeof(edui_conf.attrib));
                        } else {
                            local_printfx("No parameters given for 'u'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case '-':					/* We got a second '-' ... ignore */
                        break;
                    default:
                        local_printfx("Invalid parameter - '%c'.\n", argv[i][j]);
                        break;
                    }
                }
            } else {
                /* Incorrect parameter, display usage */
                DisplayUsage();
                return 1;
            }
        }
    }

    /* Set predefined required paremeters if none are given, localhost:LDAP_PORT, etc */
    if (edui_conf.host[0] == '\0')				/* Default to localhost */
        xstrncpy(edui_conf.host, "localhost", sizeof(edui_conf.host));
    if (edui_conf.port < 0)
        edui_conf.port = LDAP_PORT;				/* Default: LDAP_PORT */
    if ((edui_conf.mode & EDUI_MODE_IPV4) && (edui_conf.mode & EDUI_MODE_IPV6))
        edui_conf.mode &= ~(EDUI_MODE_IPV6);			/* Default to IPv4 */
    if (edui_conf.ver < 0)
        edui_conf.ver = 2;
    if (!(edui_conf.mode & EDUI_MODE_TLS))
        edui_conf.mode |= EDUI_MODE_TLS;			/* eDirectory requires TLS mode */
    if ((edui_conf.mode & EDUI_MODE_TLS) && (edui_conf.ver < 3))
        edui_conf.ver = 3;					/* TLS requires version 3 */
    if (edui_conf.persist_timeout < 0)
        edui_conf.persist_timeout = 600;			/* Default: 600 seconds (10 minutes) */
    if (edui_conf.scope < 0)
        edui_conf.scope = 1;					/* Default: one */
    if (edui_conf.search_filter[0] == '\0')
        xstrncpy(edui_conf.search_filter, "(&(objectclass=User)(networkAddress=*))", sizeof(edui_conf.search_filter));
    if (edui_conf.attrib[0] == '\0')
        xstrncpy(edui_conf.attrib, "cn", sizeof(edui_conf.attrib));
    if (edui_conf.basedn[0] == '\0') {
        local_printfx("FATAL: No '-b' option provided (Base DN).\n");
        DisplayUsage();
        return 1;
    }
    debug("Configuration done.\n");

    DisplayConf();
    /* Done with arguments */

    /* Trap the following signals */
    sigemptyset(&sv.sa_mask);
    sv.sa_handler = SigTrap;
    sigaction(SIGTERM, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGHUP, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGABRT, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGINT, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGSEGV, &sv, NULL);
//    debug("Signals trapped.\n");

    /* Set elap timer */
    time(&edui_now);
    t = edui_now;

    /* Main loop -- Waits for stdin input before action */
    while (fgets(bufa, sizeof(bufa), stdin) != NULL) {
        if (edui_conf.mode & EDUI_MODE_KILL)
            break;
        time(&edui_now);
        if (t < edui_now) {
            /* Elapse seconds */
            edui_elap = edui_now - t;
//      debug("while() -> %d seconds elapsed.\n", edui_elap);
            t = edui_now;
        } else
            edui_elap = 0;
        k = strlen(bufa);
        /* *** Extended DEBUGGING ONLY ***
            local_debug("main", "while() -> bufa[%zd]: %s", k, bufa);
            local_debug("main", "while() -> bufa[%zd]: ");
            for (i = 0; i < k; i++)
              local_debugx("%.2X", bufa[i]);
            local_debugx("\n");
        */
        /* Check for CRLF */
        p = strchr(bufa, '\n');
        if (p != NULL)
            *p = '\0';
        p = strchr(bufa, '\r');
        if (p != NULL)
            *p = '\0';
        p = strchr(bufa, ' ');

        /* No space given, but group string is required --> ERR */
        if ((edui_conf.mode & EDUI_MODE_GROUP) && (p == NULL)) {
            debug("while() -> Search group is missing. (required)\n");
            local_printfx("ERR (Search Group Required)\n");
            continue;
        }
        x = 0;

        /* Open LDAP connection */
        if (!(edui_ldap.status & LDAP_INIT_S)) {
            InitLDAP(&edui_ldap);
            debug("InitLDAP() -> %s\n", ErrLDAP(LDAP_ERR_SUCCESS));
            if (edui_conf.mode & EDUI_MODE_PERSIST)					/* Setup persistant mode */
                edui_ldap.status |= LDAP_PERSIST_S;
        }
        if ((edui_ldap.status & LDAP_IDLE_S) && (edui_elap > 0)) {
            edui_ldap.idle_time = edui_ldap.idle_time + edui_elap;
        }
        if ((edui_ldap.status & LDAP_PERSIST_S) && (edui_ldap.status & LDAP_IDLE_S) && (edui_ldap.idle_time > edui_conf.persist_timeout)) {
            debug("while() -> Connection timed out after %d seconds\n", (int)(edui_ldap.idle_time));
            x = CloseLDAP(&edui_ldap);
            debug("CloseLDAP(-) -> %s\n", ErrLDAP(x));
        }
        edui_ldap.err = -1;
        if (!(edui_ldap.status & LDAP_OPEN_S)) {
            x = OpenLDAP(&edui_ldap, edui_conf.host, edui_conf.port);
            if (x != LDAP_ERR_SUCCESS) {
                /* Failed to connect */
                debug("OpenLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
            } else {
                debug("OpenLDAP(-, %s, %d) -> %s\n", edui_conf.host, edui_conf.port, ErrLDAP(x));
                x = SetVerLDAP(&edui_ldap, edui_conf.ver);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Failed to set version */
                    debug("SetVerLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
                } else
                    debug("SetVerLDAP(-, %d) -> %s\n", edui_conf.ver, ErrLDAP(x));
            }
        }
        edui_ldap.err = -1;
        if (!(edui_ldap.status & LDAP_BIND_S) && (edui_conf.mode & EDUI_MODE_TLS)) {
            /* TLS binding */
            x = BindLDAP(&edui_ldap, edui_conf.dn, edui_conf.passwd, LDAP_AUTH_TLS);
            if (x != LDAP_ERR_SUCCESS) {
                /* Unable to bind */
                debug("BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		local_printfx("ERR (BindLDAP: %s - %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		continue;
            } else
                debug("BindLDAP(-, %s, %s, (LDAP_AUTH_TLS)) -> %s\n", edui_conf.dn, edui_conf.passwd, ErrLDAP(x));
        } else if (!(edui_ldap.status & LDAP_BIND_S)) {
            if (edui_conf.dn[0] != '\0') {
                /* Simple binding - using dn / passwd for authorization */
                x = BindLDAP(&edui_ldap, edui_conf.dn, edui_conf.passwd, LDAP_AUTH_SIMPLE);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Unable to bind */
                    debug("BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		    local_printfx("ERR (BindLDAP: %s - %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		    continue;
                } else
                    debug("BindLDAP(-, %s, %s, (LDAP_AUTH_SIMPLE)) -> %s\n", edui_conf.dn, edui_conf.passwd, ErrLDAP(x));
            } else {
                /* Anonymous binding */
                x = BindLDAP(&edui_ldap, edui_conf.dn, edui_conf.passwd, LDAP_AUTH_NONE);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Unable to bind */
                    debug("BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		    local_printfx("ERR (BindLDAP: %s - %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
		    continue;
                } else
                    debug("BindLDAP(-, -, -, (LDAP_AUTH_NONE)) -> %s\n", ErrLDAP(x));
            }
        }
        edui_ldap.err = -1;
        if (edui_ldap.status & LDAP_PERSIST_S) {
            x = ResetLDAP(&edui_ldap);
            if (x != LDAP_ERR_SUCCESS) {
                /* Unable to reset */
                debug("ResetLDAP() -> %s\n", ErrLDAP(x));
            } else
                debug("ResetLDAP() -> %s\n", ErrLDAP(x));
        }
        if (x != LDAP_ERR_SUCCESS) {
            /* Everything failed --> ERR */
            debug("while() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
            CloseLDAP(&edui_ldap);
            local_printfx("ERR (General Failure: %s)\n", ErrLDAP(x));
            continue;
        }
        edui_ldap.err = -1;
        /* If we got a group string, split it */
        if (p != NULL) {
            /* Split string */
//            debug("SplitString(%s, %zd, ' ', %s, %zd)\n", bufa, strlen(bufa), bufb, sizeof(bufb));
            i = SplitString(bufa, strlen(bufa), ' ', bufb, sizeof(bufb));
            if (i > 0) {
                debug("SplitString(%s, %s) done.  Result: %zd\n", bufa, bufb, i);
                /* Got a group to match against */
                x = ConvertIP(&edui_ldap, bufb);
                if (x < 0) {
                    debug("ConvertIP() -> %s\n", ErrLDAP(x));
                    local_printfx("ERR (ConvertIP: %s)\n", ErrLDAP(x));
                } else {
                    edui_ldap.err = -1;
                    debug("ConvertIP(-, %s) -> Result[%d]: %s\n", bufb, x, edui_ldap.search_ip);
                    x = SearchFilterLDAP(&edui_ldap, bufa);
                    if (x < 0) {
                        debug("SearchFilterLDAP() -> %s\n", ErrLDAP(x));
                        local_printfx("ERR (SearchFilterLDAP: %s)\n", ErrLDAP(x));
                    } else {
                        /* Do Search */
                        edui_ldap.err = -1;
                        debug("SearchFilterLDAP(-, %s) -> Length: %u\n", bufa, x);
                        x = SearchLDAP(&edui_ldap, edui_ldap.scope, edui_ldap.search_filter, (char **) &search_attrib);
                        if (x != LDAP_ERR_SUCCESS) {
                            debug("SearchLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
                            local_printfx("ERR (SearchLDAP: %s)\n", ErrLDAP(x));
                        } else {
                            edui_ldap.err = -1;
                            debug("SearchLDAP(-, %d, %s, -) -> %s\n", edui_conf.scope, edui_ldap.search_filter, ErrLDAP(x));
                            x = SearchIPLDAP(&edui_ldap, bufc);
                            if (x != LDAP_ERR_SUCCESS) {
                                debug("SearchIPLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
                                local_printfx("ERR (SearchIPLDAP: %s)\n", ErrLDAP(x));
                            } else {
                                debug("SearchIPLDAP(-, %s) -> %s\n", bufc, ErrLDAP(x));
                                local_printfx("OK user=%s\n", bufc);			/* Got userid --> OK user=<userid> */
                            }
                        }
                        /* Clear for next query */
                        memset(bufc, '\0', strlen(bufc));
                    }
                }
            } else {
                debug("SplitString() -> Error: %Zu\n", i);
                local_printfx("ERR (SplitString Error %d)\n", i);
            }
        } else {
            /* No group to match against, only an IP */
            x = ConvertIP(&edui_ldap, bufa);
            if (x < 0) {
                debug("ConvertIP() -> %s\n", ErrLDAP(x));
                local_printfx("ERR (ConvertIP: %s)\n", ErrLDAP(x));
            } else {
                debug("ConvertIP(-, %s) -> Result[%d]: %s\n", bufa, x, edui_ldap.search_ip);
                /* Do search */
                x = SearchFilterLDAP(&edui_ldap, NULL);
                if (x < 0) {
                    debug("SearchFilterLDAP() -> %s\n", ErrLDAP(x));
                    local_printfx("ERR (SearchFilterLDAP: %s)\n", ErrLDAP(x));
                } else {
                    edui_ldap.err = -1;
                    debug("SearchFilterLDAP(-, NULL) -> Length: %u\n", x);
                    x = SearchLDAP(&edui_ldap, edui_ldap.scope, edui_ldap.search_filter, (char **) &search_attrib);
                    if (x != LDAP_ERR_SUCCESS) {
                        debug("SearchLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(x));
                        local_printfx("ERR (SearchLDAP: %s)\n", ErrLDAP(x));
                    } else {
                        edui_ldap.err = -1;
                        debug("SearchLDAP(-, %d, %s, -) -> %s\n", edui_conf.scope, edui_ldap.search_filter, ErrLDAP(x));
                        x = SearchIPLDAP(&edui_ldap, bufc);
                        if (x != LDAP_ERR_SUCCESS) {
                            debug("SearchIPLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(edui_ldap.err));
                            local_printfx("ERR (SearchIPLDAP: %s)\n", ErrLDAP(x));
                        } else {
                            debug("SearchIPLDAP(-, %s) -> %s\n", bufc, ErrLDAP(x));
                            local_printfx("OK user=%s\n", bufc);				/* Got a userid --> OK user=<userid> */
                        }
                    }
                }
                /* Clear for next query */
                memset(bufc, '\0', strlen(bufc));
            }
        }

        /* Clear buffer and close for next data, if not persistent */
        edui_ldap.err = -1;
        memset(bufa, '\0', strlen(bufa));
        if (!(edui_ldap.status & LDAP_PERSIST_S)) {
            x = CloseLDAP(&edui_ldap);
            debug("CloseLDAP(-) -> %s\n", ErrLDAP(x));
        }
    }

    debug("Terminating.\n");
    exit(1);
}


/*
 * $Id: cachemgr.cc,v 1.63 1997/10/25 17:22:34 wessels Exp $
 *
 * DEBUG: section 0     CGI Cache Manager
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "config.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>	/* needs sys/time.h above it */
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_LIBC_H
#include <libc.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "util.h"
#include "snprintf.h"

#define MAX_ENTRIES 10000

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#if 0
#define LF 10
#define CR 13
#endif

typedef enum {
    INFO,
    CACHED,
    SERVER,
    CLIENTS,
    LOG,
    PARAM,
    STATS_I,
    STATS_F,
    STATS_D,
    STATS_R,
    STATS_O,
    STATS_VM,
    STATS_U,
    STATS_IO,
    STATS_HDRS,
    STATS_FDS,
    STATS_NETDB,
    SHUTDOWN,
    REFRESH,
    PCONN,
#ifdef REMOVE_OBJECT
    REMOVE,
#endif
    MAXOP
} op_t;

static const char *const op_cmds[] =
{
    "info",
    "squid.conf",
    "server_list",
    "client_list",
    "log",
    "config",
    "ipcache",
    "fqdncache",
    "dns",
    "redirector",
    "objects",
    "vm_objects",
    "utilization",
    "io",
    "reply_headers",
    "filedescriptors",
    "netdb",
    "shutdown",
    "refresh",
    "pconn",
#ifdef REMOVE_OBJECT
    "remove",
#endif
    "unknown"
};

static const char *const op_cmds_descr[] =
{
    "Cache Information",
    "Cache Configuration File",
    "Cache Server List",
    "Cache Client List",
    "Cache Log",
    "Cache Parameters",
    "IP Cache Contents",
    "FQDN Cache Contents",
    "DNS Server Statistics",
    "Redirector Statistics",
    "Objects",
    "VM Objects",
    "Utilization",
    "I/O",
    "HTTP Reply Headers",
    "Filedescriptor Usage",
    "Network Probe Database",
    "Shutdown Cache",
    "Refresh Object (URL required)",
    "Persistant Connection Statistics",
#ifdef REMOVE_OBJECT
    "Remove Object (URL required)",
#endif
    "Unknown Operation"
};

static int hasTables = FALSE;

static const char *script_name = "/cgi-bin/cachemgr.cgi";
static const char *const w_space = " \t\n\r";
static const char *progname = NULL;
static time_t now;
static struct in_addr no_addr;

static char x2c(char *);
static int client_comm_connect(int sock, char *dest_host, u_short dest_port);
static void print_trailer(void);
static void noargs_html(char *, int, char *, char *);
static void unescape_url(char *);
static void plustospace(char *);
static void parse_object(char *);
static char *describeTimeSince(time_t then);

static void
print_trailer(void)
{
    static char tbuf[128];
    struct tm *gmt;

    gmt = gmtime(&now);
    strftime(tbuf, 128, "%A, %d-%b-%y %H:%M:%S GMT", gmt);

    printf("<HR>\n");
    printf("<ADDRESS>\n");
    printf("Generated %s, by %s/%s@%s\n",
	tbuf, progname, SQUID_VERSION, getfullhostname());
    printf("</ADDRESS></BODY></HTML>\n");
}


static void
print_option(op_t current_opt, op_t opt_nr)
{
    printf("<OPTION%sVALUE=\"%s\">%s\n",
	current_opt == opt_nr ? " SELECTED " : " ",
	op_cmds[opt_nr],
	op_cmds_descr[opt_nr]);
}


static void
noargs_html(char *host, int port, char *url, char *password)
{
    op_t op = INFO;

    printf("\r\n\r\n");
    printf("<HTML><HEAD><TITLE>Cache Manager Interface</TITLE></HEAD>\n");
    printf("<BODY><H1>Cache Manager Interface</H1>\n");
    printf("<P>This is a WWW interface to the instrumentation interface\n");
    printf("for the Squid object cache.</P>\n");
    printf("<HR>\n");
    printf("<PRE>\n");
    printf("<FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);
    printf("<STRONG>Cache Host:</STRONG><INPUT NAME=\"host\" ");
    printf("SIZE=30 VALUE=\"%s\"><BR>\n", host);
    printf("<STRONG>Cache Port:</STRONG><INPUT NAME=\"port\" ");
    printf("SIZE=30 VALUE=\"%d\"><BR>\n", port);
    printf("<STRONG>Password  :</STRONG><INPUT TYPE=\"password\" ");
    printf("NAME=\"password\" SIZE=30 VALUE=\"%s\"><BR>\n", password);
    printf("<STRONG>URL       :</STRONG><INPUT NAME=\"url\" ");
    printf("SIZE=30 VALUE=\"%s\"><BR>\n", url);
    printf("<STRONG>Operation :</STRONG>");
    printf("<SELECT NAME=\"operation\">\n");
    print_option(op, INFO);
    print_option(op, CACHED);
    print_option(op, PARAM);
#ifdef MENU_SHOW_LOG
    print_option(op, LOG);
#endif
    print_option(op, STATS_U);
    print_option(op, STATS_IO);
    print_option(op, STATS_HDRS);
    print_option(op, STATS_FDS);
    print_option(op, STATS_NETDB);
    print_option(op, STATS_O);
    print_option(op, STATS_VM);
    print_option(op, SERVER);
    print_option(op, CLIENTS);
    print_option(op, STATS_I);
    print_option(op, STATS_F);
    print_option(op, STATS_D);
    print_option(op, STATS_R);
    print_option(op, SHUTDOWN);
    print_option(op, REFRESH);
    print_option(op, PCONN);
#ifdef REMOVE_OBJECT
    print_option(op, REMOVE);
#endif
    printf("</SELECT><BR>\n");
    printf("<HR>\n");
    printf("<INPUT TYPE=\"submit\"> <INPUT TYPE=\"reset\">\n");
    printf("</FORM></PRE>\n");
    print_trailer();
}

#if 0
/* A utility function from the NCSA httpd cgi-src utils.c */
char *
makeword(char *line, char stop)
{
    int x = 0, y;
    char *word = xmalloc(sizeof(char) * (strlen(line) + 1));

    for (x = 0; ((line[x]) && (line[x] != stop)); x++)
	word[x] = line[x];

    word[x] = '\0';
    if (line[x])
	++x;
    y = 0;

    while ((line[y++] = line[x++]) != '\0');
    return word;
}

/* A utility function from the NCSA httpd cgi-src utils.c */
char *
fmakeword(FILE * f, char stop, int *cl)
{
    int wsize = 102400;
    char *word = NULL;
    int ll = 0;

    word = xmalloc(sizeof(char) * (wsize + 1));
    for (;;) {
	word[ll] = (char) fgetc(f);
	if (ll == wsize) {
	    word[ll + 1] = '\0';
	    wsize += 102400;
	    word = realloc(word, sizeof(char) * (wsize + 1));
	}
	--(*cl);
	if ((word[ll] == stop) || (feof(f)) || (!(*cl))) {
	    if (word[ll] != stop)
		ll++;
	    word[ll] = '\0';
	    return word;
	}
	++ll;
    }
    /* NOTREACHED */
}
#endif

/* A utility function from the NCSA httpd cgi-src utils.c */
static char
x2c(char *what)
{
    char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
    return (digit);
}

/* A utility function from the NCSA httpd cgi-src utils.c */
static void
unescape_url(char *url)
{
    int x, y;

    for (x = 0, y = 0; url[y]; ++x, ++y) {
	if ((url[x] = url[y]) == '%') {
	    url[x] = x2c(&url[y + 1]);
	    y += 2;
	}
    }
    url[x] = '\0';
}

/* A utility function from the NCSA httpd cgi-src utils.c */
static void
plustospace(char *str)
{
    int x;

    for (x = 0; str[x]; x++)
	if (str[x] == '+')
	    str[x] = ' ';
}

#define ONE_SECOND (1)
#define ONE_MINUTE (ONE_SECOND*60)
#define ONE_HOUR (ONE_MINUTE*60)
#define ONE_DAY (ONE_HOUR*24)
#define ONE_WEEK (ONE_DAY*7)
#define ONE_MONTH (ONE_DAY*30)
#define ONE_YEAR (ONE_DAY*365)

static char *
describeTimeSince(time_t then)
{
    time_t delta = now - then;
    static char buf[128];
    static char buf2[128];
    const char *fmt = "%s ago";
    buf[0] = '\0';
    if (delta < 0) {
	delta = (-delta);
	fmt = "in %s";
    }
    if (then < 0)
	return "NEVER";
    if (delta < ONE_MINUTE)
	snprintf(buf, 128, "%ds", (int) (delta / ONE_SECOND));
    else if (delta < ONE_HOUR)
	snprintf(buf, 128, "%dm", (int) (delta / ONE_MINUTE));
    else if (delta < ONE_DAY)
	snprintf(buf, 128, "%dh", (int) (delta / ONE_HOUR));
    else if (delta < ONE_WEEK)
	snprintf(buf, 128, "%dD", (int) (delta / ONE_DAY));
    else if (delta < ONE_MONTH)
	snprintf(buf, 128, "%dW", (int) (delta / ONE_WEEK));
    else if (delta < ONE_YEAR)
	snprintf(buf, 128, "%dM", (int) (delta / ONE_MONTH));
    else
	snprintf(buf, 128, "%dY", (int) (delta / ONE_YEAR));
    snprintf(buf2, 128, fmt, buf);
    return buf2;
}

static void
parse_object(char *string)
{
    char *tbuf = NULL;
    char *store_status = NULL;
    char *mem_status = NULL;
    char *swap_status = NULL;
    char *ping_status = NULL;
    char *lock_count = NULL;
    char *flags = NULL;
    char *last_verified = NULL;
    char *last_use = NULL;
    char *last_modified = NULL;
    char *expires = NULL;
    char *refcount = NULL;
    char *clients = NULL;
    char *size = NULL;
    char *url = NULL;

    tbuf = xstrdup(string);

    if ((store_status = strtok(tbuf, w_space)) == NULL)
	goto parse_obj_done;
    if ((mem_status = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((swap_status = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((ping_status = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((lock_count = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((flags = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((last_verified = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((last_use = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((last_modified = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((expires = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((refcount = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((clients = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((size = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;
    if ((url = strtok(NULL, w_space)) == NULL)
	goto parse_obj_done;

#if !ALL_OBJECTS
    if (!strncmp(url, "cache_object", 12))
	goto parse_obj_done;
    if (!strncmp(url, "POST", 4))
	goto parse_obj_done;
#endif

    printf("<LI><A HREF=\"%s\">%s</A><BR>",
	url, url);
    printf("Verified %s, ", describeTimeSince((time_t) atoi(last_verified + 3)));
    printf("Used %s, ", describeTimeSince((time_t) atoi(last_use + 3)));
    printf("Modified %s, ", describeTimeSince((time_t) atoi(last_modified + 3)));
    printf("Expires %s,<BR>", describeTimeSince((time_t) atoi(expires + 3)));
    printf("%d bytes, %d accesses, %d active clients,<BR>",
	atoi(size),
	atoi(refcount),
	atoi(clients));
    printf("%s, %s, %s, %s,<BR>",
	store_status,
	mem_status,
	swap_status,
	ping_status);
    printf("%d Locks, Flags: %s\n",
	atoi(lock_count),
	flags);

  parse_obj_done:
    xfree(tbuf);
}

int
main(int argc, char *argv[])
{
    static char hostname[256] = "";
    static char operation[256] = "";
    static char password[256] = "";
    static char url[4096] = "";
    static char msg[1024];
    static char buf[4096];
    static char reserve[4096];
    static char s1[255];
    static char s2[255];
    char *buffer = NULL;
    char *time_string = NULL;
    char *agent = NULL;
    char *s = NULL;
    int conn;
    int len;
    int bytesWritten;
    int portnum = CACHE_HTTP_PORT;
    op_t op;
    int p_state;
    int n_loops;
    int cpy_ind;
    int indx;
    int in_list = 0;
    int in_table = 0;
    int d1, d2, d3, d4, d5, d6, d7;
    int single = TRUE;
    float f1;

    safe_inet_addr("255.255.255.255", &no_addr);
    now = time(NULL);
    if ((s = strrchr(argv[0], '/')))
	progname = xstrdup(s + 1);
    else
	progname = xstrdup(argv[0]);
    if ((s = getenv("SCRIPT_NAME")) != NULL) {
	script_name = xstrdup(s);
    }
    strcpy(hostname, CACHEMGR_HOSTNAME);

    /* a POST request */
    if ((s = getenv("REQUEST_METHOD")) && !strcasecmp(s, "POST") &&
	(s = getenv("CONTENT_LENGTH")) && (len = atoi(s)) > 0) {
	buffer = xmalloc(len + 1);
	fread(buffer, len, 1, stdin);
	buffer[len] = '\0';
	/* a GET request */
    } else if ((s = getenv("QUERY_STRING"))) {
	/* convert hostname:portnum to host=hostname&port=portnum */
	if (*s && !strchr(s, '=') && !strchr(s, '&')) {
	    char *p;
	    int len_buff = strlen(s) + sizeof "host=&port=";
	    buffer = xmalloc(len_buff);
	    if ((p = strchr(s, ':')))
		if (p != s) {
		    *p = '\0';
		    snprintf(buffer, len_buff, "host=%s&port=%s", s, p + 1);
		} else {
		    snprintf(buffer, len_buff, "port=%s", p + 1);
	    } else
		snprintf(buffer, len_buff, "host=%s", s);
	} else {
	    buffer = xstrdup(s);
	}
	/* no CGI parameters */
    } else {
	buffer = xstrdup("");
    }

    printf("Content-type: text/html\r\n\r\n");

    for (s = strtok(buffer, "&"); s; s = strtok(0, "&")) {
	char *v;

	plustospace(s);
	unescape_url(s);
	if ((v = strchr(s, '=')) != NULL)
	    *v++ = '\0';
	else
	    v = s;

	if (!strcmp(s, "host")) {
	    xstrncpy(hostname, v, sizeof hostname);
	} else if (!strcmp(s, "operation")) {
	    xstrncpy(operation, v, sizeof operation);
	} else if (!strcmp(s, "password")) {
	    xstrncpy(password, v, sizeof password);
	} else if (!strcmp(s, "url")) {
	    xstrncpy(url, v, sizeof url);
	} else if (!strcmp(s, "port")) {
	    portnum = atoi(v);
	} else {
	    printf("<P><STRONG>Unknown CGI parameter: %s</STRONG></P>\n",
		s);
	    noargs_html(hostname, portnum, url, password);
	    exit(0);
	}
    }
    xfree(buffer);

    if ((agent = getenv("HTTP_USER_AGENT")) != NULL) {
	if (!strncasecmp(agent, "Mozilla", 7) ||
	    !strncasecmp(agent, "OmniWeb/2", 9) ||
	    !strncasecmp(agent, "Netscape", 8)) {
	    hasTables = TRUE;
	}
    }
    /* prints HTML form if no args */
    if (!operation[0] || !strcmp(operation, "empty")) {
	noargs_html(hostname, portnum, url, password);
	exit(0);
    }
    if (hostname[0] == '\0') {
	printf("<H1>ERROR</H1>\n");
	printf("<P><STRONG>You must provide a hostname!\n</STRONG></P><HR>");
	noargs_html(hostname, portnum, url, password);
	exit(0);
    }
    close(0);

    for (op = INFO; op != MAXOP; op = (op_t) (op + 1))
	if (!strcmp(operation, op_cmds[op]) ||
	    !strcmp(operation, op_cmds_descr[op]))
	    break;

    switch (op) {
    case INFO:
    case CACHED:
    case SERVER:
    case CLIENTS:
    case LOG:
    case PARAM:
    case STATS_I:
    case STATS_F:
    case STATS_D:
    case STATS_R:
    case STATS_O:
    case STATS_VM:
    case STATS_U:
    case STATS_IO:
    case STATS_HDRS:
    case STATS_FDS:
    case STATS_NETDB:
    case PCONN:
    case SHUTDOWN:
	snprintf(msg, 1024, "GET cache_object://%s/%s@%s HTTP/1.0\r\n\r\n",
	    hostname, op_cmds[op], password);
	break;
    case REFRESH:
	snprintf(msg, 1024, "GET %s HTTP/1.0\r\nPragma: no-cache\r\nAccept: */*\r\n\r\n", url);
	break;
#ifdef REMOVE_OBJECT
    case REMOVE:
	printf("Remove not yet supported\n");
	exit(0);
	/* NOTREACHED */
#endif
    default:
    case MAXOP:
	printf("Unknown operation: %s\n", operation);
	exit(0);
	/* NOTREACHED */
    }

    time_string = ctime(&now);

    printf("<HTML><HEAD><TITLE>Cache Manager: %s:%s:%d</TITLE></HEAD>\n",
	operation, hostname, portnum);
    printf("<BODY><FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);
    printf("<INPUT TYPE=\"submit\" VALUE=\"Refresh\">\n");
    printf("<SELECT NAME=\"operation\">\n");
    printf("<OPTION VALUE=\"empty\">Empty Form\n");
    print_option(op, INFO);
    print_option(op, CACHED);
    print_option(op, PARAM);
#ifdef MENU_SHOW_LOG
    print_option(op, LOG);
#endif
    print_option(op, STATS_U);
    print_option(op, STATS_IO);
    print_option(op, STATS_HDRS);
    print_option(op, STATS_FDS);
    print_option(op, STATS_NETDB);
    print_option(op, STATS_O);
    print_option(op, STATS_VM);
    print_option(op, SERVER);
    print_option(op, CLIENTS);
    print_option(op, STATS_I);
    print_option(op, STATS_F);
    print_option(op, STATS_D);
    print_option(op, STATS_R);
    print_option(op, PCONN);
    printf("</SELECT>\n");
    printf("<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=\"%s\">\n", hostname);
    printf("<INPUT TYPE=\"hidden\" NAME=\"port\" VALUE=\"%d\">\n", portnum);
    printf("<INPUT TYPE=\"hidden\" NAME=\"password\" VALUE=\"%s\">\n", password);
    printf("<INPUT TYPE=\"hidden\" NAME=\"url\" VALUE=\"%s\">\n", url);
    printf("</FORM>\n");
    printf("<HR>\n");

    printf("<H1>%s:  %s:%d</H1>\n", operation, hostname, portnum);
    printf("<P>dated %s</P>\n", time_string);
    printf("<PRE>\n");

    /* Connect to the server */
    if ((conn = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("client: socket");
	exit(1);
    }
    if (client_comm_connect(conn, hostname, portnum) < 0) {
	printf("Error: connecting to cache mgr: %s:%d\n", hostname, portnum);
	printf("%s</PRE></BODY></HTML>\n", xstrerror());
	exit(1);
    }
    bytesWritten = write(conn, msg, strlen(msg));

    if (bytesWritten < 0) {
	printf("Error: write failed\n");
	exit(1);
    } else if (bytesWritten != (strlen(msg))) {
	printf("Error: write short\n");
	exit(1);
    }
    /* Print header stuff for tables */
    switch (op) {
    case INFO:
    case CACHED:
    case SERVER:
    case CLIENTS:
    case LOG:
    case STATS_I:
    case STATS_F:
    case STATS_D:
    case STATS_R:
    case STATS_O:
    case STATS_VM:
    case STATS_IO:
    case STATS_HDRS:
    case STATS_FDS:
    case STATS_NETDB:
    case SHUTDOWN:
    case REFRESH:
    case PCONN:
	break;
    case PARAM:
	if (hasTables) {
	    printf("<table border=1><tr><td><STRONG>Parameter</STRONG><td><STRONG>Value</STRONG><td><STRONG>Description</STRONG>\n");
	    in_table = 1;
	} else {
	    printf("\n    Parameter   Value   Description\n");
	    printf("-------------- ------- -------------------------------------\n");
	}
	break;
    case STATS_U:
	if (hasTables) {
	    printf("<table border=1><tr><td><STRONG>Protocol</STRONG><td><STRONG>Object Count</STRONG><td><STRONG>Max KB</STRONG><td><STRONG>Current KB</STRONG><td><STRONG>Min KB</STRONG><td><STRONG>Hit Ratio</STRONG><td><STRONG>Transfer KB/sec</STRONG><td><STRONG>Transfer Count</STRONG><td><STRONG>Transfered KB</STRONG></td>\n");
	    in_table = 1;
	} else {
	    printf("Protocol  Object  Maximum   Current   Minimum  Hit  Trans   Transfer Transfered\n");
	    printf("          Count   KB        KB        KB       Rate KB/sec  Count     KB\n");
	    printf("-------- ------- --------- --------- --------- ---- ------ --------- ----------\n");
	}
	break;
    default:
	printf("\n\n<P>\nNot currently implemented.\n");
	exit(1);
    }

    p_state = 0;
    cpy_ind = 0;
    n_loops = 0;		/* Keep track of passes through loop */
    while ((len = read(conn, buf, sizeof(buf))) > 0) {
	n_loops++;
	/* Simple state machine for parsing a {{ } { } ...} style list */
	for (indx = 0; indx < len; indx++) {
	    if (buf[indx] == '{')
		p_state++;
	    else if (buf[indx] == '}')
		if (p_state == 2) {	/* Have an element of the list */
		    single = FALSE;
		    p_state++;
		    reserve[cpy_ind] = '\0';
		    cpy_ind = 0;
		} else if (p_state == 1 && single)	/* Check for single element list */
		    p_state = 3;
		else		/* End of list */
		    p_state = 0;
	    else if ((indx == 0) && (n_loops == 1)) {
		if (op != REFRESH)
		    printf("ERROR:%s\n", buf);	/* Must be an error message, pass it on */
		else
		    printf("Refreshed URL: %s\n", url);
	    } else
		reserve[cpy_ind++] = buf[indx];


	    /* Have an element of the list, so parse reserve[] accordingly */
	    if (p_state == 3) {
		int sn;
		switch (op) {
		case CACHED:
		    p_state = 1;
		    for (s = reserve; *s; s++)
			switch (*s) {
			case '<':
			    printf("&lt;");
			    break;
			case '&':
			    printf("&amp;");
			    break;
			default:
			    putchar(*s);
			    break;
			}
		    break;
		case INFO:
		case SERVER:
		case CLIENTS:
		case LOG:
		case STATS_I:
		case STATS_F:
		case STATS_D:
		case STATS_R:
		case STATS_IO:
		case STATS_HDRS:
		case STATS_FDS:
		case STATS_NETDB:
		case SHUTDOWN:
		case PCONN:
		    p_state = 1;
		    printf("%s", reserve);
		    break;
		case REFRESH:
		    /* throw object away */
		    break;
		case PARAM:
		    p_state = 1;
		    memset(s1, '\0', 255);
		    memset(s2, '\0', 255);
		    d1 = 0;
		    sscanf(reserve, "%s %d \"%[^\"]", s1, &d1, s2);
		    if (hasTables)
			printf("<tr><td><STRONG>%s</STRONG><td ALIGN=\"right\">%d<td>%s\n", s1, d1, s2 + 2);
		    else
			printf("%14s %7d %s\n", s1, d1, s2 + 2);
		    break;
		case STATS_U:
		    p_state = 1;
		    sn = sscanf(reserve, "%s %d %d %d %d %f %d %d %d",
			s1, &d1, &d2, &d3, &d4, &f1, &d5, &d6, &d7);
		    if (sn == 1) {
			if (hasTables)
			    printf("<tr><td align=\"right\"><STRONG>%s</STRONG>\n", s1);
			else
			    printf("%s-Requests\n", s1);
			break;
		    }
		    if (hasTables)
			printf("<tr><td align=\"right\"><STRONG>%s</STRONG><td align=\"right\">%d<td align=\"right\">%d<td align=\"right\">%d<td align=\"right\">%d<td align=\"right\">%4.2f<td align=\"right\">%d<td align=\"right\">%d<td align=\"right\">%d\n",
			    s1, d1, d2, d3, d4, f1, d5, d6, d7);
		    else
			printf("%8s %7d %9d %9d %9d %4.2f %6d %9d %10d\n",
			    s1, d1, d2, d3, d4, f1, d5, d6, d7);
		    break;
		case STATS_O:
		case STATS_VM:
		    if (!in_list) {
			in_list = 1;
			printf("<OL>\n");
		    }
		    parse_object(reserve);
		    p_state = 1;
		    break;
		default:
		    printf("%s\n", "Not currently implemented");
		    exit(1);
		}
	    }
	}
    }

    if (in_list)
	printf("</OL>\n");

    if (in_table)
	printf("</table>\n");

    printf("\n</PRE>\n");
    print_trailer();
    close(conn);
    exit(0);
    /* NOTREACHED */
    return 0;
}

static int
client_comm_connect(int sock, char *dest_host, u_short dest_port)
{
    const struct hostent *hp;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    memset(&to_addr, '\0', sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;

    if ((hp = gethostbyname(dest_host)) != NULL)
	xmemcpy(&to_addr.sin_addr.s_addr, hp->h_addr, hp->h_length);
    else if (safe_inet_addr(dest_host, &to_addr.sin_addr))
	(void) 0;
    else
	return (-1);

    to_addr.sin_port = htons(dest_port);
    return connect(sock, (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
}

/*
 * $Id: cachemgr.cc,v 1.67 1998/02/22 20:40:24 wessels Exp $
 *
 * DEBUG: section 0     CGI Cache Manager
 * AUTHOR: Duane Wessels
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

typedef struct {
    char *hostname;
    int port;
    char *action;
    char *passwd;
} cachemgr_request;

/*
 * static variables
 */
static const char *script_name = "/cgi-bin/cachemgr.cgi";
static const char *const w_space = " \t\n\r";
static const char *progname = NULL;
static time_t now;
static struct in_addr no_addr;

/*
 * Function prototypes
 */
static void print_trailer(void);
static void noargs_html(char *host, int port);
static void error_html(const char *msg);
static cachemgr_request *read_request(void);
static char *read_get_request(void);
static char *read_post_request(void);


static void
print_trailer(void)
{
    printf("<HR>\n");
    printf("<ADDRESS>\n");
    printf("Generated %s, by %s/%s@%s\n",
	mkrfc1123(now), progname, SQUID_VERSION, getfullhostname());
    printf("</ADDRESS></BODY></HTML>\n");
}

static void
noargs_html(char *host, int port)
{
    printf("Content-type: text/html\r\n\r\n");
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
    printf("</SELECT><BR>\n");
    printf("<INPUT TYPE=\"submit\" VALUE=\"Continue...\">\n");
    printf("</FORM></PRE>\n");
    print_trailer();
}

static void
error_html(const char *msg)
{
    printf("Content-type: text/html\r\n\r\n");
    printf("<HTML><HEAD><TITLE>Cache Manager Error</TITLE></HEAD>\n");
    printf("<BODY><H1>Cache Manager Error</H1>\n");
    printf("<P>\n%s</P>\n", msg);
    print_trailer();
}

static char *
menu_url(cachemgr_request * req, char *action)
{
    static char url[1024];
    snprintf(url, 1024, "%s?host=%s&port=%d&operation=%s",
	script_name,
	req->hostname,
	req->port,
	action);
    return url;
}

static const char *
munge_menu_line(const char *buf, cachemgr_request * req)
{
    char *x;
    char *a;
    char *d;
    static char html[1024];
    if (strlen(buf) < 1)
	return buf;
    if (*buf != ' ')
	return buf;
    x = xstrdup(buf);
    if ((a = strtok(x, w_space)) == NULL)
	return buf;
    if ((d = strtok(NULL, "")) == NULL)
	return buf;
    snprintf(html, 1024, "<LI><A HREF=\"%s\">%s</A>\n",
	menu_url(req, a), d);
    return html;
}

static int
read_reply(int s, cachemgr_request * req)
{
    char buf[1024];
    FILE *fp = fdopen(s, "r");
    int state = 0;
    int parse_menu = 0;
    if (0 == strlen(req->action))
	parse_menu = 1;
    else if (0 == strcasecmp(req->action, "menu"))
	parse_menu = 1;
    if (fp == NULL) {
	perror("fdopen");
	return 1;
    }
    printf("Content-Type: text/html\r\n\r\n");
    if (parse_menu) {
	printf("<H2>Cache Manager menu for %s:</H2>", req->hostname);
	printf("<UL>\n");
    } else {
	printf("<P><A HREF=\"%s\">%s</A>\n<HR>\n",
	    menu_url(req, "menu"), "Cache Manager menu");
	printf("<PRE>\n");
    }
    while (fgets(buf, 1024, fp) != NULL) {
	if (1 == state)
	    if (parse_menu)
		fputs(munge_menu_line(buf, req), stdout);
	    else
		fputs(buf, stdout);
	if (0 == strcmp(buf, "\r\n"))
	    state++;
    }
    if (parse_menu)
	printf("</UL>\n");
    else
	printf("</PRE>\n");
    print_trailer();
    close(s);
    return 0;
}

static int
process_request(cachemgr_request * req)
{
    const struct hostent *hp;
    static struct sockaddr_in S;
    int s;
    int l;
    static char buf[1024];
    if (req == NULL) {
	noargs_html(CACHEMGR_HOSTNAME, CACHE_HTTP_PORT);
	return 1;
    }
    if (req->hostname == NULL) {
	req->hostname = xstrdup(CACHEMGR_HOSTNAME);
    }
    if (req->port == 0) {
	req->port = CACHE_HTTP_PORT;
    }
    if (req->action == NULL) {
	req->action = xstrdup("");
    }
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	snprintf(buf, 1024, "socket: %s\n", xstrerror());
	error_html(buf);
	return 1;
    }
    memset(&S, '\0', sizeof(struct sockaddr_in));
    S.sin_family = AF_INET;
    if ((hp = gethostbyname(req->hostname)) != NULL)
	xmemcpy(&S.sin_addr.s_addr, hp->h_addr, hp->h_length);
    else if (safe_inet_addr(req->hostname, &S.sin_addr))
	(void) 0;
    else {
	snprintf(buf, 1024, "Unknown host: %s\n", req->hostname);
	error_html(buf);
	return 1;
    }
    S.sin_port = htons(req->port);
    if (connect(s, (struct sockaddr *) &S, sizeof(struct sockaddr_in)) < 0) {
	snprintf(buf, 1024, "connect: %s\n", xstrerror());
	error_html(buf);
	return 1;
    }
    l = snprintf(buf, 1024,
	"GET cache_object://%s/%s HTTP/1.0\r\n"
	"Accept: */*\r\n"
	"\r\n",
	req->hostname,
	req->action);
    write(s, buf, l);
    return read_reply(s, req);
}

int
main(int argc, char *argv[])
{
    char *s;
    cachemgr_request *req;
    safe_inet_addr("255.255.255.255", &no_addr);
    now = time(NULL);
    if ((s = strrchr(argv[0], '/')))
	progname = xstrdup(s + 1);
    else
	progname = xstrdup(argv[0]);
    if ((s = getenv("SCRIPT_NAME")) != NULL)
	script_name = xstrdup(s);
    req = read_request();
    return process_request(req);
}

static char *
read_post_request(void)
{
    char *s;
    char *buf;
    int len;
    if ((s = getenv("REQUEST_METHOD")) == NULL)
	return NULL;
    if (0 != strcasecmp(s, "POST"))
	return NULL;
    if ((s = getenv("CONTENT_LENGTH")) == NULL)
	return NULL;
    if ((len = atoi(s)) <= 0)
	return NULL;
    buf = xmalloc(len + 1);
    fread(buf, len, 1, stdin);
    buf[len] = '\0';
    return buf;
}

static char *
read_get_request(void)
{
    char *s;
    if ((s = getenv("QUERY_STRING")) == NULL)
	return NULL;
    return xstrdup(s);
}

static cachemgr_request *
read_request(void)
{
    char *buf;
    cachemgr_request *req;
    char *s;
    char *t;
    char *q;
    if ((buf = read_post_request()) != NULL)
	(void) 0;
    else if ((buf = read_get_request()) != NULL)
	(void) 0;
    else
	return NULL;
    if (strlen(buf) == 0)
	return NULL;
    req = xcalloc(1, sizeof(cachemgr_request));
    for (s = strtok(buf, "&"); s != NULL; s = strtok(NULL, "&")) {
	t = xstrdup(s);
	if ((q = strchr(t, '=')) == NULL)
	    continue;
	*q++ = '\0';
	if (0 == strcasecmp(t, "host"))
	    req->hostname = xstrdup(q);
	if (0 == strcasecmp(t, "port"))
	    req->port = atoi(q);
	if (0 == strcasecmp(t, "password"))
	    req->passwd = xstrdup(q);
	if (0 == strcasecmp(t, "operation"))
	    req->action = xstrdup(q);
    }
    return req;
}

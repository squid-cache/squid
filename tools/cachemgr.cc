
/*
 * $Id: cachemgr.cc,v 1.3 2006/09/10 20:08:20 serassio Exp $
 *
 * DEBUG: section 0     CGI Cache Manager
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
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
#elif HAVE_MALLOC_H
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
#if HAVE_FNMATCH_H
extern "C"
{
#include <fnmatch.h>
}

#endif

#include "assert.h"

#include "util.h"
#include "snprintf.h"

#ifndef DEFAULT_CACHEMGR_CONFIG
#define DEFAULT_CACHEMGR_CONFIG "/etc/squid/cachemgr.conf"
#endif

typedef struct
{
    char *server;
    char *hostname;
    int port;
    char *action;
    char *user_name;
    char *passwd;
    char *pub_auth;
}

cachemgr_request;

/*
 * Debugging macros (info goes to error_log on your web server)
 * Note: do not run cache manager with non zero debugging level 
 *       if you do not debug, it may write a lot of [sensitive]
 *       information to your error log.
 */

/* debugging level 0 (disabled) - 3 (max) */
#define DEBUG_LEVEL 0
#define debug(level) if ((level) <= DEBUG_LEVEL && DEBUG_LEVEL > 0)

/*
 * Static variables and constants
 */
static const time_t passwd_ttl = 60 * 60 * 3;	/* in sec */
static const char *script_name = "/cgi-bin/cachemgr.cgi";
static const char *progname = NULL;
static time_t now;

static struct IN_ADDR no_addr;

/*
 * Function prototypes
 */
#define safe_free(str) { if (str) { xfree(str); (str) = NULL; } }
static const char *safe_str(const char *str);
static const char *xstrtok(char **str, char del);
static void print_trailer(void);
static void auth_html(const char *host, int port, const char *user_name);
static void error_html(const char *msg);
static char *menu_url(cachemgr_request * req, const char *action);
static int parse_status_line(const char *sline, const char **statusStr);
static cachemgr_request *read_request(void);
static char *read_get_request(void);
static char *read_post_request(void);

static void make_pub_auth(cachemgr_request * req);
static void decode_pub_auth(cachemgr_request * req);
static void reset_auth(cachemgr_request * req);
static const char *make_auth_header(const cachemgr_request * req);

static int check_target_acl(const char *hostname, int port);

#ifdef _SQUID_MSWIN_
static int s_iInitCount = 0;

int Win32SockInit(void)
{
    int iVersionRequested;
    WSADATA wsaData;
    int err;

    if (s_iInitCount > 0) {
        s_iInitCount++;
        return (0);
    } else if (s_iInitCount < 0)
        return (s_iInitCount);

    /* s_iInitCount == 0. Do the initailization */
    iVersionRequested = MAKEWORD(2, 0);

    err = WSAStartup((WORD) iVersionRequested, &wsaData);

    if (err) {
        s_iInitCount = -1;
        return (s_iInitCount);
    }

    if (LOBYTE(wsaData.wVersion) != 2 ||
            HIBYTE(wsaData.wVersion) != 0) {
        s_iInitCount = -2;
        WSACleanup();
        return (s_iInitCount);
    }

    s_iInitCount++;
    return (s_iInitCount);
}

void Win32SockCleanup(void)
{
    if (--s_iInitCount == 0)
        WSACleanup();

    return;
}

#endif /* ifdef _SQUID_MSWIN_ */

static const char *
safe_str(const char *str)
{
    return str ? str : "";
}

/* relaxed number format */
static int
is_number(const char *str)
{
    return strspn(str, "\t -+01234567890./\n") == strlen(str);
}

static const char *
xstrtok(char **str, char del)
{
    if (*str) {
        char *p = strchr(*str, del);
        char *tok = *str;
        int len;

        if (p) {
            *str = p + 1;
            *p = '\0';
        } else
            *str = NULL;

        /* trim */
        len = strlen(tok);

        while (len && xisspace(tok[len - 1]))
            tok[--len] = '\0';

        while (xisspace(*tok))
            tok++;

        return tok;
    } else
        return "";
}

static void
print_trailer(void)
{
    printf("<HR noshade size=\"1px\">\n");
    printf("<ADDRESS>\n");
    printf("Generated %s, by %s/%s@%s\n",
           mkrfc1123(now), progname, VERSION, getfullhostname());
    printf("</ADDRESS></BODY></HTML>\n");
}

static void
auth_html(const char *host, int port, const char *user_name)
{
    FILE *fp;
    int need_host = 1;

    if (!user_name)
        user_name = "";

    if (!host || !strlen(host))
        host = "";

    printf("Content-Type: text/html\r\n\r\n");

    printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");

    printf("<HTML><HEAD><TITLE>Cache Manager Interface</TITLE>\n");

    printf("<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE></HEAD>\n");

    printf("<BODY><H1>Cache Manager Interface</H1>\n");

    printf("<P>This is a WWW interface to the instrumentation interface\n");

    printf("for the Squid object cache.</P>\n");

    printf("<HR noshade size=\"1px\">\n");

    printf("<FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);

    printf("<TABLE BORDER=\"0\" CELLPADDING=\"10\" CELLSPACING=\"1\">\n");


    fp = fopen("cachemgr.conf", "r");

    if (fp == NULL)
        fp = fopen(DEFAULT_CACHEMGR_CONFIG, "r");

    if (fp != NULL) {
        int servers = 0;
        char config_line[BUFSIZ];

        while (fgets(config_line, BUFSIZ, fp)) {
            char *server, *comment;
            strtok(config_line, "\r\n");

            if (config_line[0] == '#')
                continue;

            if (config_line[0] == '\0')
                continue;

            if ((server = strtok(config_line, " \t")) == NULL)
                continue;

            if (strchr(server, '*') || strchr(server, '[') || strchr(server, '?')) {
                need_host = -1;
                continue;
            }

            comment = strtok(NULL, "");

            if (comment)
                while (*comment == ' ' || *comment == '\t')
                    comment++;

            if (!comment || !*comment)
                comment = server;

            if (!servers) {
                printf("<TR><TH ALIGN=\"left\">Cache Server:</TH><TD><SELECT NAME=\"server\">\n");
            }

            printf("<OPTION VALUE=\"%s\"%s>%s</OPTION>\n", server, (servers || *host) ? "" : " SELECTED", comment);
            servers++;
        }

        if (servers) {
            if (need_host == 1 && !*host)
                need_host = 0;

            if (need_host)
                printf("<OPTION VALUE=\"\"%s>Other</OPTION>\n", (*host) ? " SELECTED" : "");

            printf("</SELECT></TR>\n");
        }

        fclose(fp);
    }

    if (need_host) {
        if (need_host == 1 && !*host)
            host = "localhost";

        printf("<TR><TH ALIGN=\"left\">Cache Host:</TH><TD><INPUT NAME=\"host\" ");

        printf("size=\"30\" VALUE=\"%s\"></TD></TR>\n", host);

        printf("<TR><TH ALIGN=\"left\">Cache Port:</TH><TD><INPUT NAME=\"port\" ");

        printf("size=\"30\" VALUE=\"%d\"></TD></TR>\n", port);
    }

    printf("<TR><TH ALIGN=\"left\">Manager name:</TH><TD><INPUT NAME=\"user_name\" ");

    printf("size=\"30\" VALUE=\"%s\"></TD></TR>\n", user_name);

    printf("<TR><TH ALIGN=\"left\">Password:</TH><TD><INPUT TYPE=\"password\" NAME=\"passwd\" ");

    printf("size=\"30\" VALUE=\"\"></TD></TR>\n");

    printf("</TABLE><BR CLEAR=\"all\">\n");

    printf("<INPUT TYPE=\"submit\" VALUE=\"Continue...\">\n");

    printf("</FORM>\n");

    print_trailer();
}

static void
error_html(const char *msg)
{
    printf("Content-Type: text/html\r\n\r\n");
    printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
    printf("<HTML><HEAD><TITLE>Cache Manager Error</TITLE>\n");
    printf("<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE></HEAD>\n");
    printf("<BODY><H1>Cache Manager Error</H1>\n");
    printf("<P>\n%s</P>\n", msg);
    print_trailer();
}

/* returns http status extracted from status line or -1 on parsing failure */
static int
parse_status_line(const char *sline, const char **statusStr)
{
    const char *sp = strchr(sline, ' ');

    if (statusStr)
        *statusStr = NULL;

    if (strncasecmp(sline, "HTTP/", 5) || !sp)
        return -1;

    while (xisspace(*++sp))

        ;
    if (!xisdigit(*sp))
        return -1;

    if (statusStr)
        *statusStr = sp;

    return atoi(sp);
}

static char *
menu_url(cachemgr_request * req, const char *action)
{
    static char url[1024];
    snprintf(url, sizeof(url), "%s?host=%s&port=%d&user_name=%s&operation=%s&auth=%s",
             script_name,
             req->hostname,
             req->port,
             safe_str(req->user_name),
             action,
             safe_str(req->pub_auth));
    return url;
}

static const char *
munge_menu_line(const char *buf, cachemgr_request * req)
{
    char *x;
    const char *a;
    const char *d;
    const char *p;
    char *a_url;
    char *buf_copy;
    static char html[2 * 1024];

    if (strlen(buf) < 1)
        return buf;

    if (*buf != ' ')
        return buf;

    buf_copy = x = xstrdup(buf);

    a = xstrtok(&x, '\t');

    d = xstrtok(&x, '\t');

    p = xstrtok(&x, '\t');

    a_url = xstrdup(menu_url(req, a));

    /* no reason to give a url for a disabled action */
    if (!strcmp(p, "disabled"))
        snprintf(html, sizeof(html), "<LI type=\"circle\">%s (disabled)<A HREF=\"%s\">.</A>\n", d, a_url);
    else
        /* disable a hidden action (requires a password, but password is not in squid.conf) */
        if (!strcmp(p, "hidden"))
            snprintf(html, sizeof(html), "<LI type=\"circle\">%s (hidden)<A HREF=\"%s\">.</A>\n", d, a_url);
        else
            /* disable link if authentication is required and we have no password */
            if (!strcmp(p, "protected") && !req->passwd)
                snprintf(html, sizeof(html), "<LI type=\"circle\">%s (requires <a href=\"%s\">authentication</a>)<A HREF=\"%s\">.</A>\n",
                         d, menu_url(req, "authenticate"), a_url);
            else
                /* highlight protected but probably available entries */
                if (!strcmp(p, "protected"))
                    snprintf(html, sizeof(html), "<LI type=\"square\"><A HREF=\"%s\"><font color=\"#FF0000\">%s</font></A>\n",
                             a_url, d);

    /* public entry or unknown type of protection */
                else
                    snprintf(html, sizeof(html), "<LI type=\"disk\"><A HREF=\"%s\">%s</A>\n", a_url, d);

    xfree(a_url);

    xfree(buf_copy);

    return html;
}

static const char *
munge_other_line(const char *buf, cachemgr_request * req)
{
    static const char *ttags[] = {"td", "th"};

    static char html[4096];
    static int table_line_num = 0;
    static int next_is_header = 0;
    int is_header = 0;
    const char *ttag;
    char *buf_copy;
    char *x, *p;
    int l = 0;
    /* does it look like a table? */

    if (!strchr(buf, '\t') || *buf == '\t') {
        /* nope, just text */
        snprintf(html, sizeof(html), "%s%s",
                 table_line_num ? "</table>\n<pre>" : "", buf);
        table_line_num = 0;
        return html;
    }

    /* start html table */
    if (!table_line_num) {
        l += snprintf(html + l, sizeof(html) - l, "</pre><table cellpadding=\"2\" cellspacing=\"1\">\n");
        next_is_header = 0;
    }

    /* remove '\n' */
    is_header = (!table_line_num || next_is_header) && !strchr(buf, ':') && !is_number(buf);

    ttag = ttags[is_header];

    /* record starts */
    l += snprintf(html + l, sizeof(html) - l, "<tr>");

    /* substitute '\t' */
    buf_copy = x = xstrdup(buf);

    if ((p = strchr(x, '\n')))
        *p = '\0';

    while (x && strlen(x)) {
        int column_span = 1;
        const char *cell = xstrtok(&x, '\t');

        while (x && *x == '\t') {
            column_span++;
            x++;
        }

        l += snprintf(html + l, sizeof(html) - l, "<%s colspan=\"%d\" align=\"%s\">%s</%s>",
                      ttag, column_span,
                      is_header ? "center" : is_number(cell) ? "right" : "left",
                      cell, ttag);
    }

    xfree(buf_copy);
    /* record ends */
    l += snprintf(html + l, sizeof(html) - l, "</tr>\n");
    next_is_header = is_header && strstr(buf, "\t\t");
    table_line_num++;
    return html;
}

static int
read_reply(int s, cachemgr_request * req)
{
    char buf[4 * 1024];
#ifdef _SQUID_MSWIN_

    int reply;
    char *tmpfile = tempnam(NULL, "tmp0000");
    FILE *fp = fopen(tmpfile, "w+");
#else

    FILE *fp = fdopen(s, "r");
#endif
    /* interpretation states */
    enum {
        isStatusLine, isHeaders, isBodyStart, isBody, isForward, isEof, isForwardEof, isSuccess, isError
    } istate = isStatusLine;
    int parse_menu = 0;
    const char *action = req->action;
    const char *statusStr = NULL;
    int status = -1;

    if (0 == strlen(req->action))
        parse_menu = 1;
    else if (0 == strcasecmp(req->action, "menu"))
        parse_menu = 1;

    if (fp == NULL) {
#ifdef _SQUID_MSWIN_
        perror(tmpfile);
        xfree(tmpfile);
#else

        perror("fdopen");
#endif

        close(s);
        return 1;
    }

#ifdef _SQUID_MSWIN_

    while ((reply=recv(s, buf , sizeof(buf), 0)) > 0)
        fwrite(buf, 1, reply, fp);

    rewind(fp);

#endif

    if (parse_menu)
        action = "menu";

    /* read reply interpreting one line at a time depending on state */
    while (istate < isEof) {
        if (!fgets(buf, sizeof(buf), fp))
            istate = istate == isForward ? isForwardEof : isEof;

        switch (istate) {

        case isStatusLine:
            /* get HTTP status */
            /* uncomment the following if you want to debug headers */
            /* fputs("\r\n\r\n", stdout); */
            status = parse_status_line(buf, &statusStr);
            istate = status == 200 ? isHeaders : isForward;
            /* if cache asks for authentication, we have to reset our info */

            if (status == 401 || status == 407) {
                reset_auth(req);
                status = 403;	/* Forbiden, see comments in case isForward: */
            }

            /* this is a way to pass HTTP status to the Web server */
            if (statusStr)
                printf("Status: %d %s", status, statusStr);	/* statusStr has '\n' */

            break;

        case isHeaders:
            /* forward header field */
            if (!strcmp(buf, "\r\n")) {		/* end of headers */
                fputs("Content-Type: text/html\r\n", stdout);	/* add our type */
                istate = isBodyStart;
            }

            if (strncasecmp(buf, "Content-Type:", 13))	/* filter out their type */
                fputs(buf, stdout);

            break;

        case isBodyStart:
            printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");

            printf("<HTML><HEAD><TITLE>CacheMgr@%s: %s</TITLE>\n",
                   req->hostname, action);

            printf("<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}TABLE{background-color:#333333;border:0pt;padding:0pt}TH,TD{background-color:#ffffff;white-space:nowrap}--></STYLE>\n");

            printf("</HEAD><BODY>\n");

            if (parse_menu) {
                printf("<H2><a href=\"%s\">Cache Manager</a> menu for %s:</H2>",
                       menu_url(req, "authenticate"), req->hostname);
                printf("<UL>\n");
            } else {
                printf("<P><A HREF=\"%s\">%s</A>\n<HR noshade size=\"1px\">\n",
                       menu_url(req, "menu"), "Cache Manager menu");
                printf("<PRE>\n");
            }

            istate = isBody;
            /* yes, fall through, we do not want to loose the first line */

        case isBody:
            /* interpret [and reformat] cache response */

            if (parse_menu)
                fputs(munge_menu_line(buf, req), stdout);
            else
                fputs(munge_other_line(buf, req), stdout);

            break;

        case isForward:
            /* forward: no modifications allowed */
            /*
             * Note: we currently do not know any way to get browser.reply to
             * 401 to .cgi because web server filters out all auth info. Thus we
             * disable authentication headers for now.
             */
            if (!strncasecmp(buf, "WWW-Authenticate:", 17) || !strncasecmp(buf, "Proxy-Authenticate:", 19))

                ;	/* skip */
            else
                fputs(buf, stdout);

            break;

        case isEof:
            /* print trailers */
            if (parse_menu)
                printf("</UL>\n");
            else
                printf("</table></PRE>\n");

            print_trailer();

            istate = isSuccess;

            break;

        case isForwardEof:
            /* indicate that we finished processing an "error" sequence */
            istate = isError;

            break;

        default:
            printf("%s: internal bug: invalid state reached: %d", script_name, istate);

            istate = isError;
        }
    }

    fclose(fp);
#ifdef _SQUID_MSWIN_

    remove(tmpfile);
    xfree(tmpfile);
    close(s);

#endif

    return 0;
}

static int
process_request(cachemgr_request * req)
{

    const struct hostent *hp;

    static struct sockaddr_in S;
    int s;
    int l;

    static char buf[2 * 1024];

    if (req == NULL) {
        auth_html(CACHEMGR_HOSTNAME, CACHE_HTTP_PORT, "");
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

    if (strcmp(req->action, "authenticate") == 0) {
        auth_html(req->hostname, req->port, req->user_name);
        return 0;
    }

    if (!check_target_acl(req->hostname, req->port)) {
        snprintf(buf, 1024, "target %s:%d not allowed in cachemgr.conf\n", req->hostname, req->port);
        error_html(buf);
        return 1;
    }

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(buf, 1024, "socket: %s\n", xstrerror());
        error_html(buf);
        return 1;
    }

    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;

    if ((hp = gethostbyname(req->hostname)) != NULL) {
        assert(hp->h_length >= 0 && (size_t)hp->h_length <= sizeof(S.sin_addr.s_addr));
        xmemcpy(&S.sin_addr.s_addr, hp->h_addr, hp->h_length);
    } else if (safe_inet_addr(req->hostname, &S.sin_addr))
        (void) 0;
    else {
        snprintf(buf, 1024, "Unknown host: %s\n", req->hostname);
        error_html(buf);
        return 1;
    }

    S.sin_port = htons(req->port);

    if (connect(s, (struct sockaddr *) &S, sizeof(S)) < 0) {
        snprintf(buf, 1024, "connect %s:%d: %s\n",
                 inet_ntoa(S.sin_addr),
                 ntohs(S.sin_port),
                 xstrerror());
        error_html(buf);
        return 1;
    }

    l = snprintf(buf, sizeof(buf),
                 "GET cache_object://%s/%s HTTP/1.0\r\n"
                 "Accept: */*\r\n"
                 "%s"			/* Authentication info or nothing */
                 "\r\n",
                 req->hostname,
                 req->action,
                 make_auth_header(req));
    write(s, buf, l);
    debug(1) fprintf(stderr, "wrote request: '%s'\n", buf);
    return read_reply(s, req);
}

int
main(int argc, char *argv[])
{
    char *s;
    cachemgr_request *req;

    safe_inet_addr("255.255.255.255", &no_addr);
    now = time(NULL);
#ifdef _SQUID_MSWIN_

    Win32SockInit();
    atexit(Win32SockCleanup);
    _setmode( _fileno( stdin ), _O_BINARY );
    _setmode( _fileno( stdout ), _O_BINARY );
    _fmode = _O_BINARY;

    if ((s = strrchr(argv[0], '\\')))
#else

    if ((s = strrchr(argv[0], '/')))
#endif

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

    buf = (char *)xmalloc(len + 1);

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

#ifdef _SQUID_MSWIN_

    if (strlen(buf) == 0 || strlen(buf) == 4000)
#else

    if (strlen(buf) == 0)
#endif

        return NULL;

    req = (cachemgr_request *)xcalloc(1, sizeof(cachemgr_request));

    for (s = strtok(buf, "&"); s != NULL; s = strtok(NULL, "&")) {
        t = xstrdup(s);

        if ((q = strchr(t, '=')) == NULL)
            continue;

        *q++ = '\0';

        rfc1738_unescape(t);

        rfc1738_unescape(q);

        if (0 == strcasecmp(t, "server") && strlen(q))
            req->server = xstrdup(q);
        else if (0 == strcasecmp(t, "host") && strlen(q))
            req->hostname = xstrdup(q);
        else if (0 == strcasecmp(t, "port") && strlen(q))
            req->port = atoi(q);
        else if (0 == strcasecmp(t, "user_name") && strlen(q))
            req->user_name = xstrdup(q);
        else if (0 == strcasecmp(t, "passwd") && strlen(q))
            req->passwd = xstrdup(q);
        else if (0 == strcasecmp(t, "auth") && strlen(q))
            req->pub_auth = xstrdup(q), decode_pub_auth(req);
        else if (0 == strcasecmp(t, "operation"))
            req->action = xstrdup(q);
    }

    if (req->server && !req->hostname) {
        char *p;
        req->hostname = strtok(req->server, ":");

        if ((p = strtok(NULL, ":")))
            req->port = atoi(p);
    }

    make_pub_auth(req);
    debug(1) fprintf(stderr, "cmgr: got req: host: '%s' port: %d uname: '%s' passwd: '%s' auth: '%s' oper: '%s'\n",
                     safe_str(req->hostname), req->port, safe_str(req->user_name), safe_str(req->passwd), safe_str(req->pub_auth), safe_str(req->action));
    return req;
}


/* Routines to support authentication */

/*
 * Encodes auth info into a "public" form. 
 * Currently no powerful encryption is used.
 */
static void
make_pub_auth(cachemgr_request * req)
{
    static char buf[1024];
    safe_free(req->pub_auth);
    debug(3) fprintf(stderr, "cmgr: encoding for pub...\n");

    if (!req->passwd || !strlen(req->passwd))
        return;

    /* host | time | user | passwd */
    snprintf(buf, sizeof(buf), "%s|%d|%s|%s",
             req->hostname,
             (int) now,
             req->user_name ? req->user_name : "",
             req->passwd);

    debug(3) fprintf(stderr, "cmgr: pre-encoded for pub: %s\n", buf);

    debug(3) fprintf(stderr, "cmgr: encoded: '%s'\n", base64_encode(buf));

    req->pub_auth = xstrdup(base64_encode(buf));
}

static void
decode_pub_auth(cachemgr_request * req)
{
    char *buf;
    const char *host_name;
    const char *time_str;
    const char *user_name;
    const char *passwd;

    debug(2) fprintf(stderr, "cmgr: decoding pub: '%s'\n", safe_str(req->pub_auth));
    safe_free(req->passwd);

    if (!req->pub_auth || strlen(req->pub_auth) < 4 + strlen(safe_str(req->hostname)))
        return;

    buf = xstrdup(base64_decode(req->pub_auth));

    debug(3) fprintf(stderr, "cmgr: length ok\n");

    /* parse ( a lot of memory leaks, but that is cachemgr style :) */
    if ((host_name = strtok(buf, "|")) == NULL)
        return;

    debug(3) fprintf(stderr, "cmgr: decoded host: '%s'\n", host_name);

    if ((time_str = strtok(NULL, "|")) == NULL)
        return;

    debug(3) fprintf(stderr, "cmgr: decoded time: '%s' (now: %d)\n", time_str, (int) now);

    if ((user_name = strtok(NULL, "|")) == NULL)
        return;

    debug(3) fprintf(stderr, "cmgr: decoded uname: '%s'\n", user_name);

    if ((passwd = strtok(NULL, "|")) == NULL)
        return;

    debug(2) fprintf(stderr, "cmgr: decoded passwd: '%s'\n", passwd);

    /* verify freshness and validity */
    if (atoi(time_str) + passwd_ttl < now)
        return;

    if (strcasecmp(host_name, req->hostname))
        return;

    debug(1) fprintf(stderr, "cmgr: verified auth. info.\n");

    /* ok, accept */
    xfree(req->user_name);

    req->user_name = xstrdup(user_name);

    req->passwd = xstrdup(passwd);

    xfree(buf);
}

static void
reset_auth(cachemgr_request * req)
{
    safe_free(req->passwd);
    safe_free(req->pub_auth);
}

static const char *
make_auth_header(const cachemgr_request * req)
{
    static char buf[1024];
    size_t stringLength = 0;
    const char *str64;

    if (!req->passwd)
        return "";

    snprintf(buf, sizeof(buf), "%s:%s",
             req->user_name ? req->user_name : "",
             req->passwd);

    str64 = base64_encode(buf);

    stringLength += snprintf(buf, sizeof(buf), "Authorization: Basic %s\r\n", str64);

    assert(stringLength < sizeof(buf));

    stringLength += snprintf(&buf[stringLength], sizeof(buf) - stringLength,
                             "Proxy-Authorization: Basic %s\r\n", str64);

    return buf;
}

static int
check_target_acl(const char *hostname, int port)
{
    char config_line[BUFSIZ];
    FILE *fp = NULL;
    int ret = 0;
    fp = fopen("cachemgr.conf", "r");

    if (fp == NULL)
        fp = fopen(DEFAULT_CACHEMGR_CONFIG, "r");

    if (fp == NULL) {
#ifdef CACHEMGR_HOSTNAME_DEFINED

        if (strcmp(hostname, CACHEMGR_HOSTNAME) == 0 && port == CACHE_HTTP_PORT)
            return 1;

#else

        if (strcmp(hostname, "localhost") == 0)
            return 1;

        if (strcmp(hostname, getfullhostname()) == 0)
            return 1;

#endif

        return 0;
    }

    while (fgets(config_line, BUFSIZ, fp)) {
        char *token = NULL;
        strtok(config_line, " \r\n\t");

        if (config_line[0] == '#')
            continue;

        if (config_line[0] == '\0')
            continue;

        if ((token = strtok(config_line, ":")) == NULL)
            continue;

#if HAVE_FNMATCH_H

        if (fnmatch(token, hostname, 0) != 0)
            continue;

#else

        if (strcmp(token, hostname) != 0)
            continue;

#endif

        if ((token = strtok(NULL, ":")) != NULL) {
            int i;

            if (strcmp(token, "*") == 0)

                ;   /* Wildcard port specification */
            else if (strcasecmp(token, "any") == 0)

                ;   /* Wildcard port specification */
            else if (sscanf(token, "%d", &i) != 1)
                continue;

            else if (i != port)
                continue;
        } else if (port != CACHE_HTTP_PORT)
            continue;

        ret = 1;

        break;
    }

    fclose(fp);
    return ret;
}

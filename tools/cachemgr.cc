/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base64.h"
#include "getfullhostname.h"
#include "html_quote.h"
#include "ip/Address.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "time/gadgets.h"
#include "util.h"

#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#if HAVE_UNISTD_H
#include <unistd.h>
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
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
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
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_FNMATCH_H
extern "C" {
#include <fnmatch.h>
}
#endif

#ifndef DEFAULT_CACHEMGR_CONFIG
#define DEFAULT_CACHEMGR_CONFIG "/etc/squid/cachemgr.conf"
#endif

typedef struct {
    char *server;
    char *hostname;
    int port;
    char *action;
    char *user_name;
    char *passwd;
    char *pub_auth;
    char *workers;
    char *processes;
} cachemgr_request;

/*
 * Static variables and constants
 */
static const time_t passwd_ttl = 60 * 60 * 3;   /* in sec */
static const char *script_name = "/cgi-bin/cachemgr.cgi";
static const char *progname = nullptr;
static time_t now;

/*
 * Function prototypes
 */
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

#if _SQUID_WINDOWS_
static int s_iInitCount = 0;

int Win32SockInit(void)
{
    int iVersionRequested;
    WSADATA wsaData;
    int err;

    if (s_iInitCount > 0) {
        ++s_iInitCount;
        return (0);
    } else if (s_iInitCount < 0)
        return (s_iInitCount);

    /* s_iInitCount == 0. Do the initialization */
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

    ++s_iInitCount;
    return (s_iInitCount);
}

void Win32SockCleanup(void)
{
    if (--s_iInitCount == 0)
        WSACleanup();

    return;
}

#endif

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
            *str = nullptr;

        /* trim */
        len = strlen(tok);

        while (len && xisspace(tok[len - 1]))
            tok[--len] = '\0';

        while (xisspace(*tok))
            ++tok;

        return tok;
    } else
        return "";
}

static bool
hostname_check(const char *uri)
{
    static CharacterSet hostChars = CharacterSet("host",".:[]_") +
                                    CharacterSet::ALPHA + CharacterSet::DIGIT;

    const auto limit = strlen(uri);
    for (size_t i = 0; i < limit; i++) {
        if (!hostChars[uri[i]]) {
            return false;
        }
    }
    return true;
}

static void
print_trailer(void)
{
    printf("<HR noshade size=\"1px\">\n");
    printf("<ADDRESS>\n");
    printf("Generated %s, by %s/%s@%s\n",
           Time::FormatRfc1123(now), progname, VERSION, getfullhostname());
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

    fp = fopen("cachemgr.conf", "r");

    if (fp == nullptr)
        fp = fopen(DEFAULT_CACHEMGR_CONFIG, "r");

    if (fp == nullptr)
        printf("X-Error: message=\"Unable to open config %s\"", DEFAULT_CACHEMGR_CONFIG);

    printf("Content-Type: text/html\r\n\r\n");

    printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");

    printf("<HTML><HEAD><TITLE>Cache Manager Interface</TITLE>\n");

    printf("<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n");

    printf("<script type=\"text/javascript\">\n");
    printf("function TS(t, s) {\n");
    printf(" var x = new XMLHttpRequest();\n");
    printf(" x.open('GET', 'http' + s + '://' + t + '/squid-internal-mgr/', true);\n");
    printf(" x.onreadystatechange=function() {\n");
    printf("  if (x.readyState==4) {\n");
    printf("   if ((x.status>=200 && x.status <= 299) || x.status==401) {\n");
    printf("    var v = x.getResponseHeader('Server');\n");
    printf("    if (v.substring(0,6) == 'squid/' || v == 'squid') {\n");
    printf("     var d = document.getElementById('H' + s + 'mgr');\n");
    printf("     if (d.innerHTML == '') d.innerHTML = '<h2>HTTP' + (s=='s'?'S':'') + ' Managed Proxies</h2>';\n");
    printf("     d.innerHTML = d.innerHTML + '<p>Host: <a href=\"http' + s + '://' + t + '/squid-internal-mgr/\">' + t + '</a></p>';\n");
    printf("     var sv = document.getElementById('server');\n");
    printf("     var op = sv.getElementsByTagName('OPTION');\n");
    printf("     for(var i=0; i<op.length; i++) { if (op[i].innerHTML == t) { sv.removeChild(op[i]); i--; }}\n");
    printf("     if (sv.getElementsByTagName('OPTION').length == 0) {\n");
    printf("      document.getElementById('Cmgr').innerHTML = '';\n");
    printf(" }}}}}\n");
    printf(" x.send(null);\n");
    printf("}\n");
    printf("</script>\n");

    printf("</HEAD>\n");

    printf("<BODY><H1>Cache Manager Interface</H1>\n");

    printf("<P>This is a WWW interface to the instrumentation interface\n");

    printf("for the Squid object cache.</P>\n");

    printf("<HR noshade size=\"1px\">\n");

    printf("<div id=\"Hsmgr\"></div>\n");
    printf("<div id=\"Hmgr\"></div>\n");
    printf("<div id=\"Cmgr\">\n");
    printf("<h2>CGI Managed Proxies</h2>\n");
    printf("<FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);

    printf("<TABLE BORDER=\"0\" CELLPADDING=\"10\" CELLSPACING=\"1\">\n");

    if (fp != nullptr) {
        int servers = 0;
        char config_line[BUFSIZ];

        while (fgets(config_line, BUFSIZ, fp)) {
            char *server, *comment;
            if (strtok(config_line, "\r\n") == nullptr)
                continue;

            if (config_line[0] == '#')
                continue;

            if (config_line[0] == '\0')
                continue;

            if ((server = strtok(config_line, " \t")) == nullptr)
                continue;

            if (strchr(server, '*') || strchr(server, '[') || strchr(server, '?')) {
                need_host = -1;
                continue;
            }

            comment = strtok(nullptr, "");

            if (comment)
                while (*comment == ' ' || *comment == '\t')
                    ++comment;

            if (!comment || !*comment)
                comment = server;

            if (!servers)
                printf("<TR><TH ALIGN=\"left\">Cache Server:</TH><TD><SELECT id=\"server\" NAME=\"server\">\n");

            printf("<OPTION VALUE=\"%s\"%s>%s</OPTION>\n", server, (servers || *host) ? "" : " SELECTED", comment);
            ++servers;
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

    printf("size=\"30\" VALUE=\"%s\"></TD></TR>\n", rfc1738_escape(user_name));

    printf("<TR><TH ALIGN=\"left\">Password:</TH><TD><INPUT TYPE=\"password\" NAME=\"passwd\" ");

    printf("size=\"30\" VALUE=\"\"></TD></TR>\n");

    printf("</TABLE><BR CLEAR=\"all\">\n");

    printf("<INPUT TYPE=\"submit\" VALUE=\"Continue...\">\n");

    printf("</FORM></div>\n");

    printf("<script type=\"text/javascript\">\n");
    printf("var s = document.getElementById(\"server\");\n");
    printf("for (var i = 0; i < s.childElementCount; i++) {\n");
    printf(" TS(s.children[i].value, '');\n");
    printf(" TS(s.children[i].value, 's');\n");
    printf("}</script>\n");

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
    printf("<P>\n%s</P>\n", html_quote(msg));
    print_trailer();
}

/* returns http status extracted from status line or -1 on parsing failure */
static int
parse_status_line(const char *sline, const char **statusStr)
{
    const char *sp = strchr(sline, ' ');

    if (statusStr)
        *statusStr = nullptr;

    if (strncasecmp(sline, "HTTP/", 5) || !sp)
        return -1;

    while (xisspace(*++sp));
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
             rfc1738_escape(safe_str(req->user_name)),
             action,
             safe_str(req->pub_auth));
    return url;
}

static void
munge_menu_line(MemBuf &out, const char *buf, cachemgr_request * req)
{
    char *x;
    const char *a;
    const char *d;
    const char *p;
    char *a_url;
    char *buf_copy;

    const auto bufLen = strlen(buf);
    if (bufLen < 1)
        return; // nothing to append

    if (*buf != ' ') {
        out.append(buf, bufLen);
        return;
    }

    buf_copy = x = xstrndup(buf, bufLen+1);

    a = xstrtok(&x, '\t');

    d = xstrtok(&x, '\t');

    p = xstrtok(&x, '\t');

    a_url = xstrdup(menu_url(req, a));

    /* no reason to give a url for a disabled action */
    if (!strcmp(p, "disabled"))
        out.appendf("<LI type=\"circle\">%s (disabled)<A HREF=\"%s\">.</A>\n", d, a_url);
    else
        /* disable a hidden action (requires a password, but password is not in squid.conf) */
        if (!strcmp(p, "hidden"))
            out.appendf("<LI type=\"circle\">%s (hidden)<A HREF=\"%s\">.</A>\n", d, a_url);
        else
            /* disable link if authentication is required and we have no password */
            if (!strcmp(p, "protected") && !req->passwd)
                out.appendf("<LI type=\"circle\">%s (requires <a href=\"%s\">authentication</a>)<A HREF=\"%s\">.</A>\n",
                            d, menu_url(req, "authenticate"), a_url);
            else
                /* highlight protected but probably available entries */
                if (!strcmp(p, "protected"))
                    out.appendf("<LI type=\"square\"><A HREF=\"%s\"><font color=\"#FF0000\">%s</font></A>\n",
                                a_url, d);

    /* public entry or unknown type of protection */
                else
                    out.appendf("<LI type=\"disk\"><A HREF=\"%s\">%s</A>\n", a_url, d);

    xfree(a_url);

    xfree(buf_copy);
}

static void
munge_other_line(MemBuf &out, const char *buf, cachemgr_request *)
{
    static const char *ttags[] = {"td", "th"};

    static int table_line_num = 0;
    static int next_is_header = 0;
    int is_header = 0;
    const char *ttag;
    char *buf_copy;
    char *x, *p;
    /* does it look like a table? */

    if (!strchr(buf, '\t') || *buf == '\t') {
        /* nope, just text */
        if (table_line_num)
            out.append("</table>\n<pre>", 14);
        out.appendf("%s", html_quote(buf));
        table_line_num = 0;
        return;
    }

    /* start html table */
    if (!table_line_num) {
        out.append("</pre><table cellpadding=\"2\" cellspacing=\"1\">\n", 46);
        next_is_header = 0;
    }

    /* remove '\n' */
    is_header = (!table_line_num || next_is_header) && !strchr(buf, ':') && !is_number(buf);

    ttag = ttags[is_header];

    /* record starts */
    out.append("<tr>", 4);

    /* substitute '\t' */
    buf_copy = x = xstrdup(buf);

    if ((p = strchr(x, '\n')))
        *p = '\0';

    while (x && strlen(x)) {
        int column_span = 1;
        const char *cell = xstrtok(&x, '\t');

        while (x && *x == '\t') {
            ++column_span;
            ++x;
        }

        out.appendf("<%s colspan=\"%d\" align=\"%s\">%s</%s>",
                    ttag, column_span,
                    is_header ? "center" : is_number(cell) ? "right" : "left",
                    html_quote(cell), ttag);
    }

    xfree(buf_copy);
    /* record ends */
    out.append("</tr>\n", 6);
    next_is_header = is_header && strstr(buf, "\t\t");
    ++table_line_num;
}

static const char *
munge_action_line(const char *_buf, cachemgr_request * req)
{
    static char html[2 * 1024];
    char *buf = xstrdup(_buf);
    char *x = buf;
    const char *action, *description;
    char *p;

    if ((p = strchr(x, '\n')))
        *p = '\0';
    action = xstrtok(&x, '\t');
    if (!action) {
        xfree(buf);
        return "";
    }
    description = xstrtok(&x, '\t');
    if (!description)
        description = action;
    snprintf(html, sizeof(html), " <a href=\"%s\">%s</a>", menu_url(req, action), description);
    xfree(buf);
    return html;
}

static int
read_reply(int s, cachemgr_request * req)
{
    char buf[4 * 1024];
#if _SQUID_WINDOWS_

    int reply;
    char *tmpfile = tempnam(nullptr, "tmp0000");
    FILE *fp = fopen(tmpfile, "w+");
#else

    FILE *fp = fdopen(s, "r");
#endif
    /* interpretation states */
    enum {
        isStatusLine, isHeaders, isActions, isBodyStart, isBody, isForward, isEof, isForwardEof, isSuccess, isError
    } istate = isStatusLine;
    int parse_menu = 0;
    const char *action = req->action;
    const char *statusStr = nullptr;
    int status = -1;

    if (0 == strlen(req->action))
        parse_menu = 1;
    else if (0 == strcasecmp(req->action, "menu"))
        parse_menu = 1;

    if (fp == nullptr) {
#if _SQUID_WINDOWS_
        perror(tmpfile);
        xfree(tmpfile);
#else

        perror("fdopen");
#endif

        close(s);
        return 1;
    }

#if _SQUID_WINDOWS_

    while ((reply=recv(s, buf, sizeof(buf), 0)) > 0)
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
                status = 403;   /* Forbidden, see comments in case isForward: */
            }

            /* this is a way to pass HTTP status to the Web server */
            if (statusStr)
                printf("Status: %d %s", status, statusStr); /* statusStr has '\n' */

            break;

        case isHeaders:
            /* forward header field */
            if (!strcmp(buf, "\r\n")) {     /* end of headers */
                fputs("Content-Type: text/html\r\n", stdout);   /* add our type */
                istate = isBodyStart;
            }

            if (strncasecmp(buf, "Content-Type:", 13))  /* filter out their type */
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

            istate = isActions;
            [[fallthrough]]; // we do not want to lose the first line

        case isActions:
            if (strncmp(buf, "action:", 7) == 0) {
                fputs(" ", stdout);
                fputs(munge_action_line(buf + 7, req), stdout);
                break;
            }
            if (parse_menu) {
                printf("<UL>\n");
            } else {
                printf("<HR noshade size=\"1px\">\n");
                printf("<PRE>\n");
            }

            istate = isBody;
            [[fallthrough]]; // we do not want to lose the first line

        case isBody:
        {
            /* interpret [and reformat] cache response */
            MemBuf out;
            out.init();
            if (parse_menu)
                munge_menu_line(out, buf, req);
            else
                munge_other_line(out, buf, req);

            fputs(out.buf, stdout);
        }
        break;

        case isForward:
            /* forward: no modifications allowed */
            /*
             * Note: we currently do not know any way to get browser.reply to
             * 401 to .cgi because web server filters out all auth info. Thus we
             * disable authentication headers for now.
             */
            if (!strncasecmp(buf, "WWW-Authenticate:", 17) || !strncasecmp(buf, "Proxy-Authenticate:", 19));    /* skip */
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
#if _SQUID_WINDOWS_

    remove(tmpfile);
    xfree(tmpfile);
    close(s);

#endif

    return 0;
}

static int
process_request(cachemgr_request * req)
{

    char ipbuf[MAX_IPSTRLEN];
    struct addrinfo *AI = nullptr;
    Ip::Address S;
    int s;
    int l;

    static char buf[2 * 1024];

    if (req == nullptr) {
        auth_html(CACHEMGR_HOSTNAME, CACHE_HTTP_PORT, "");
        return 1;
    }

    if (req->hostname == nullptr) {
        req->hostname = xstrdup(CACHEMGR_HOSTNAME);
    }

    if (req->port == 0) {
        req->port = CACHE_HTTP_PORT;
    }

    if (req->action == nullptr) {
        req->action = xstrdup("menu");
    }

    if (strcmp(req->action, "authenticate") == 0) {
        auth_html(req->hostname, req->port, req->user_name);
        return 0;
    }

    if (!check_target_acl(req->hostname, req->port)) {
        snprintf(buf, sizeof(buf), "target %s:%d not allowed in cachemgr.conf\n", req->hostname, req->port);
        error_html(buf);
        return 1;
    }

    S = *gethostbyname(req->hostname);

    if ( !S.isAnyAddr() ) {
        (void) 0;
    } else if ((S = req->hostname))
        (void) 0;
    else {
        if (hostname_check(req->hostname)) {
            snprintf(buf, sizeof(buf), "Unknown Host: %s\n", req->hostname);
            error_html(buf);
            return 1;
        } else {
            snprintf(buf, sizeof(buf), "%s\n", "Invalid Hostname");
            error_html(buf);
            return 1;
        }
    }

    S.port(req->port);

    S.getAddrInfo(AI);

#if USE_IPV6
    if ((s = socket( AI->ai_family, SOCK_STREAM, 0)) < 0) {
#else
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#endif
        int xerrno = errno;
        snprintf(buf, sizeof(buf), "socket: %s\n", xstrerr(xerrno));
        error_html(buf);
        Ip::Address::FreeAddr(AI);
        return 1;
    }

    if (connect(s, AI->ai_addr, AI->ai_addrlen) < 0) {
        int xerrno = errno;
        snprintf(buf, sizeof(buf), "connect %s: %s\n", S.toUrl(ipbuf,MAX_IPSTRLEN), xstrerr(xerrno));
        error_html(buf);
        Ip::Address::FreeAddr(AI);
        close(s);
        return 1;
    }

    Ip::Address::FreeAddr(AI);

    // XXX: missing backward compatibility for old Squid.
    // Squid-3.1 and older do not support http scheme manager requests.
    // Squid-3.2 versions have bugs with https scheme manager requests.
    l = snprintf(buf, sizeof(buf),
                 "GET /squid-internal-mgr/%s%s%s HTTP/1.0\r\n" // HTTP/1.0 because this tool does not support Transfer-Encoding
                 "Host: %s\r\n"
                 "User-Agent: cachemgr.cgi/%s\r\n"
                 "Accept: */*\r\n"
                 "%s"           /* Authentication info or nothing */
                 "\r\n",
                 req->action,
                 req->workers? "?workers=" : (req->processes ? "?processes=" : ""),
                 req->workers? req->workers : (req->processes ? req->processes: ""),
                 req->hostname,
                 VERSION,
                 make_auth_header(req));
    if (write(s, buf, l) < 0) {
        fprintf(stderr,"ERROR: (%d) writing request: '%s'\n", errno, buf);
    } else {
        debug("wrote request: '%s'\n", buf);
    }
    return read_reply(s, req);
}

int
main(int argc, char *argv[])
{
    char *s;
    cachemgr_request *req;

    now = time(nullptr);
#if _SQUID_WINDOWS_

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

    if ((s = getenv("SCRIPT_NAME")) != nullptr)
        script_name = xstrdup(s);

    char **args = argv;
    while (argc > 1 && args[1][0] == '-') {
        char option = args[1][1];
        switch (option) {
        case 'd':
            debug_enabled = 1;
            break;
        default:
            break;
        }
        ++args;
        --argc;
    }

    req = read_request();

    return process_request(req);
}

static char *
read_post_request(void)
{
    char *s;

    if ((s = getenv("REQUEST_METHOD")) == nullptr)
        return nullptr;

    if (0 != strcasecmp(s, "POST"))
        return nullptr;

    if ((s = getenv("CONTENT_LENGTH")) == nullptr)
        return nullptr;

    if (*s == '-') // negative length content huh?
        return nullptr;

    uint64_t len;

    char *endptr = s+ strlen(s);
    if ((len = strtoll(s, &endptr, 10)) <= 0)
        return nullptr;

    // limit the input to something reasonable.
    // 4KB should be enough for the GET/POST data length, but may be extended.
    size_t bufLen = (len < 4096 ? len : 4095);
    char *buf = (char *)xmalloc(bufLen + 1);

    size_t readLen = fread(buf, 1, bufLen, stdin);
    if (readLen == 0) {
        xfree(buf);
        return nullptr;
    }
    buf[readLen] = '\0';
    len -= readLen;

    // purge the remainder of the request entity
    while (len > 0 && readLen) {
        char temp[65535];
        readLen = fread(temp, 1, 65535, stdin);
        len -= readLen;
    }

    return buf;
}

static char *
read_get_request(void)
{
    char *s;

    if ((s = getenv("QUERY_STRING")) == nullptr)
        return nullptr;

    return xstrdup(s);
}

static cachemgr_request *
read_request(void)
{
    char *buf;

    cachemgr_request *req;
    char *s;
    char *t = nullptr;
    char *q;

    if ((buf = read_post_request()) != nullptr)
        (void) 0;
    else if ((buf = read_get_request()) != nullptr)
        (void) 0;
    else
        return nullptr;

#if _SQUID_WINDOWS_

    if (strlen(buf) == 0 || strlen(buf) == 4000)
#else

    if (strlen(buf) == 0)
#endif
    {
        xfree(buf);
        return nullptr;
    }

    req = (cachemgr_request *)xcalloc(1, sizeof(cachemgr_request));

    for (s = strtok(buf, "&"); s != nullptr; s = strtok(nullptr, "&")) {
        safe_free(t);
        t = xstrdup(s);

        if ((q = strchr(t, '=')) == nullptr)
            continue;

        *q = '\0';
        ++q;

        rfc1738_unescape(t);

        rfc1738_unescape(q);

        if (0 == strcmp(t, "server") && strlen(q))
            req->server = xstrdup(q);
        else if (0 == strcmp(t, "host") && strlen(q))
            req->hostname = xstrdup(q);
        else if (0 == strcmp(t, "port") && strlen(q))
            req->port = atoi(q);
        else if (0 == strcmp(t, "user_name") && strlen(q))
            req->user_name = xstrdup(q);
        else if (0 == strcmp(t, "passwd") && strlen(q))
            req->passwd = xstrdup(q);
        else if (0 == strcmp(t, "auth") && strlen(q))
            req->pub_auth = xstrdup(q), decode_pub_auth(req);
        else if (0 == strcmp(t, "operation"))
            req->action = xstrdup(q);
        else if (0 == strcmp(t, "workers") && strlen(q))
            req->workers = xstrdup(q);
        else if (0 == strcmp(t, "processes") && strlen(q))
            req->processes = xstrdup(q);
    }
    safe_free(t);

    if (req->server && !req->hostname) {
        char *p;
        req->hostname = strtok(req->server, ":");

        if ((p = strtok(nullptr, ":")))
            req->port = atoi(p);
    }

    make_pub_auth(req);
    debug("cmgr: got req: host: '%s' port: %d uname: '%s' passwd: '%s' auth: '%s' oper: '%s' workers: '%s' processes: '%s'\n",
          safe_str(req->hostname), req->port, safe_str(req->user_name), safe_str(req->passwd), safe_str(req->pub_auth), safe_str(req->action), safe_str(req->workers), safe_str(req->processes));
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
    debug("cmgr: encoding for pub...\n");

    if (!req->passwd || !strlen(req->passwd))
        return;

    auto *rfc1738_username = xstrdup(rfc1738_escape(safe_str(req->user_name)));
    auto *rfc1738_passwd = xstrdup(rfc1738_escape(req->passwd));

    /* host | time | user | passwd */
    const int bufLen = snprintf(buf, sizeof(buf), "%s|%d|%s|%s",
                                req->hostname,
                                (int) now,
                                rfc1738_username,
                                rfc1738_passwd);
    debug("cmgr: pre-encoded for pub: %s\n", buf);

    safe_free(rfc1738_username);
    safe_free(rfc1738_passwd);

    const int encodedLen = base64_encode_len(bufLen);
    req->pub_auth = (char *) xmalloc(encodedLen);
    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);
    size_t blen = base64_encode_update(&ctx, req->pub_auth, bufLen, reinterpret_cast<uint8_t*>(buf));
    blen += base64_encode_final(&ctx, req->pub_auth + blen);
    req->pub_auth[blen] = '\0';
    debug("cmgr: encoded: '%s'\n", req->pub_auth);
}

static void
decode_pub_auth(cachemgr_request * req)
{
    const char *host_name;
    const char *time_str;

    debug("cmgr: decoding pub: '%s'\n", safe_str(req->pub_auth));
    safe_free(req->passwd);

    if (!req->pub_auth || strlen(req->pub_auth) < 4 + strlen(safe_str(req->hostname)))
        return;

    char *buf = static_cast<char*>(xmalloc(BASE64_DECODE_LENGTH(strlen(req->pub_auth))+1));
    struct base64_decode_ctx ctx;
    base64_decode_init(&ctx);
    size_t decodedLen = 0;
    if (!base64_decode_update(&ctx, &decodedLen, reinterpret_cast<uint8_t*>(buf), strlen(req->pub_auth), req->pub_auth) ||
            !base64_decode_final(&ctx)) {
        debug("cmgr: base64 decode failure. Incomplete auth token string.\n");
        xfree(buf);
        return;
    }
    buf[decodedLen] = '\0';

    debug("cmgr: length ok\n");

    /* parse ( a lot of memory leaks, but that is cachemgr style :) */
    if ((host_name = strtok(buf, "|")) == nullptr) {
        xfree(buf);
        return;
    }

    debug("cmgr: decoded host: '%s'\n", host_name);

    if ((time_str = strtok(nullptr, "|")) == nullptr) {
        xfree(buf);
        return;
    }

    debug("cmgr: decoded time: '%s' (now: %d)\n", time_str, (int) now);

    char *user_name;
    if ((user_name = strtok(nullptr, "|")) == nullptr) {
        xfree(buf);
        return;
    }
    rfc1738_unescape(user_name);

    debug("cmgr: decoded uname: '%s'\n", user_name);

    char *passwd;
    if ((passwd = strtok(nullptr, "|")) == nullptr) {
        xfree(buf);
        return;
    }
    rfc1738_unescape(passwd);

    debug("cmgr: decoded passwd: '%s'\n", passwd);

    /* verify freshness and validity */
    if (atoi(time_str) + passwd_ttl < now) {
        xfree(buf);
        return;
    }

    if (strcasecmp(host_name, req->hostname)) {
        xfree(buf);
        return;
    }

    debug("cmgr: verified auth. info.\n");

    /* ok, accept */
    safe_free(req->user_name);

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

    if (!req->passwd)
        return "";

    int bufLen = snprintf(buf, sizeof(buf), "%s:%s",
                          req->user_name ? req->user_name : "",
                          req->passwd);

    int encodedLen = base64_encode_len(bufLen);
    if (encodedLen <= 0)
        return "";

    char *str64 = static_cast<char *>(xmalloc(encodedLen));
    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);
    size_t blen = base64_encode_update(&ctx, str64, bufLen, reinterpret_cast<uint8_t*>(buf));
    blen += base64_encode_final(&ctx, str64+blen);
    str64[blen] = '\0';

    stringLength += snprintf(buf, sizeof(buf), "Authorization: Basic %.*s\r\n", (int)blen, str64);

    assert(stringLength < sizeof(buf));

    snprintf(&buf[stringLength], sizeof(buf) - stringLength, "Proxy-Authorization: Basic %.*s\r\n", (int)blen, str64);

    xfree(str64);
    return buf;
}

static int
check_target_acl(const char *hostname, int port)
{
    char config_line[BUFSIZ];
    FILE *fp = nullptr;
    int ret = 0;
    fp = fopen("cachemgr.conf", "r");

    if (fp == nullptr)
        fp = fopen(DEFAULT_CACHEMGR_CONFIG, "r");

    if (fp == nullptr) {
#ifdef CACHEMGR_HOSTNAME_DEFINED
        // TODO: simplify and maybe get rid of CACHEMGR_HOSTNAME altogether
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
        char *token = nullptr;
        strtok(config_line, " \r\n\t");

        if (config_line[0] == '#')
            continue;

        if (config_line[0] == '\0')
            continue;

        if ((token = strtok(config_line, ":")) == nullptr)
            continue;

#if HAVE_FNMATCH_H

        if (fnmatch(token, hostname, 0) != 0)
            continue;

#else

        if (strcmp(token, hostname) != 0)
            continue;

#endif

        if ((token = strtok(nullptr, ":")) != nullptr) {
            int i;

            if (strcmp(token, "*") == 0)

                ;   /* Wildcard port specification */
            else if (strcmp(token, "any") == 0)

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


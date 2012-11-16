/*
 * DEBUG: section --    WWW Client
 * AUTHOR: Harvest Derived
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

#include "squid.h"
#include "base64.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "rfc1123.h"
#include "SquidTime.h"

#if _SQUID_WINDOWS_
/** \cond AUTODOCS-IGNORE */
using namespace Squid;
/** \endcond */
#endif

#if _SQUID_WINDOWS_
#include <io.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_GSSAPI
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif /* HAVE_GSSAPI_GSSAPI_H/HAVE_GSSAPI_H */
#if !HAVE_HEIMDAL_KERBEROS
#if HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif
#if HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif
#if HAVE_GSSAPI_GSSAPI_EXT_H
#include <gssapi/gssapi_ext.h>
#endif
#endif

#ifndef gss_nt_service_name
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#endif

#ifndef gss_mech_spnego
static gss_OID_desc _gss_mech_spnego = {6, (void *) "\x2b\x06\x01\x05\x05\x02"};
gss_OID gss_mech_spnego = &_gss_mech_spnego;
#endif
#endif /* HAVE_GSSAPI */

#ifndef BUFSIZ
#define BUFSIZ		8192
#endif
#ifndef MESSAGELEN
#define MESSAGELEN	65536
#endif
#ifndef HEADERLEN
#define HEADERLEN	65536
#endif

typedef void SIGHDLR(int sig);

/* Local functions */
static int client_comm_bind(int, const Ip::Address &);

static int client_comm_connect(int, const Ip::Address &, struct timeval *);
static void usage(const char *progname);

static int Now(struct timeval *);
SIGHDLR catchSignal;
SIGHDLR pipe_handler;
static void set_our_signal(void);
static ssize_t myread(int fd, void *buf, size_t len);
static ssize_t mywrite(int fd, void *buf, size_t len);

#if HAVE_GSSAPI
static int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char *function);
static char *GSSAPI_token(const char *server);
#endif

static int put_fd;
static char *put_file = NULL;

static struct stat sb;
int total_bytes = 0;
int io_timeout = 120;

#if _SQUID_WINDOWS_
void
Win32SockCleanup(void)
{
    WSACleanup();
    return;
}
#endif

static void
usage(const char *progname)
{
    fprintf(stderr,
            "Version: %s\n"
            "Usage: %s [-arsv] [-A 'string'] [-g count] [-h remote host] [-H 'string'] [-i IMS] [-I ping-interval] [-j 'Host-header']"
            "[-k] [-l local-host] [-m method] "
#if HAVE_GSSAPI
            "[-n] [-N] "
#endif
            "[-p port] [-P file] [-t count] [-T timeout] [-u proxy-user] [-U www-user] "
            "[-V version] [-w proxy-password] [-W www-password] url\n"
            "\n"
            "Options:\n"
            "    -a           Do NOT include Accept: header.\n"
            "    -A           User-Agent: header. Use \"\" to omit.\n"
            "    -g count     Ping mode, perform \"count\" iterations (0 to loop until interrupted).\n"
            "    -h host      Retrieve URL from cache on hostname.  Default is localhost.\n"
            "    -H 'string'  Extra headers to send. Use '\\n' for new lines.\n"
            "    -i IMS       If-Modified-Since time (in Epoch seconds).\n"
            "    -I interval  Ping interval in seconds (default 1 second).\n"
            "    -j hosthdr   Host header content\n"
            "    -k           Keep the connection active. Default is to do only one request then close.\n"
            "    -l host      Specify a local IP address to bind to.  Default is none.\n"
            "    -m method    Request method, default is GET.\n"
#if HAVE_GSSAPI
            "    -n           Proxy Negotiate(Kerberos) authentication\n"
            "    -N           WWW Negotiate(Kerberos) authentication\n"
#endif
            "    -p port      Port number of cache.  Default is %d.\n"
            "    -P file      PUT request. Using the named file\n"
            "    -r           Force cache to reload URL.\n"
            "    -s           Silent.  Do not print data to stdout.\n"
            "    -t count     Trace count cache-hops\n"
            "    -T timeout   Timeout value (seconds) for read/write operations.\n"
            "    -u user      Proxy authentication username\n"
            "    -U user      WWW authentication username\n"
            "    -v           Verbose. Print outgoing message to stderr.\n"
            "    -V version   HTTP Version. Use '-' for HTTP/0.9 omitted case\n"
            "    -w password  Proxy authentication password\n"
            "    -W password  WWW authentication password\n",
            VERSION, progname, CACHE_HTTP_PORT);
    exit(1);
}

static int interrupted = 0;
int
main(int argc, char *argv[])
{
    int conn, c, len, bytesWritten;
    int port, to_stdout, reload;
    int ping, pcount;
    int keep_alive = 0;
    int opt_noaccept = 0;
    bool opt_verbose = false;
#if HAVE_GSSAPI
    int www_neg = 0, proxy_neg = 0;
#endif
    const char *hostname, *localhost;
    Ip::Address iaddr;
    char url[BUFSIZ], msg[MESSAGELEN], buf[BUFSIZ];
    char extra_hdrs[HEADERLEN];
    const char *method = "GET";
    extern char *optarg;
    time_t ims = 0;
    int max_forwards = -1;

    struct timeval tv1, tv2;
    int i = 0, loops;
    long ping_int;
    long ping_min = 0, ping_max = 0, ping_sum = 0, ping_mean = 0;
    const char *proxy_user = NULL;
    const char *proxy_password = NULL;
    const char *www_user = NULL;
    const char *www_password = NULL;
    const char *host = NULL;
    const char *version = "1.0";
    const char *useragent = NULL;

    /* set the defaults */
    hostname = "localhost";
    localhost = NULL;
    extra_hdrs[0] = '\0';
    port = CACHE_HTTP_PORT;
    to_stdout = 1;
    reload = 0;
    ping = 0;
    pcount = 0;
    ping_int = 1 * 1000;

    Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.
    if (argc < 2) {
        usage(argv[0]);		/* need URL */
    } else if (argc >= 2) {
        strncpy(url, argv[argc - 1], BUFSIZ);
        url[BUFSIZ - 1] = '\0';

        if (url[0] == '-')
            usage(argv[0]);
#if HAVE_GSSAPI
        while ((c = getopt(argc, argv, "aA:h:j:V:l:P:i:km:p:rsvt:g:p:I:H:T:u:U:w:W:nN?")) != -1)
#else
        while ((c = getopt(argc, argv, "aA:h:j:V:l:P:i:km:p:rsvt:g:p:I:H:T:u:U:w:W:?")) != -1)
#endif
            switch (c) {

            case 'a':
                opt_noaccept = 1;
                break;

            case 'A':
                useragent = optarg;
                break;

            case 'h':		/* remote host */
                hostname = optarg;
                break;

            case 'j':
                host = optarg;
                break;

            case 'V':
                version = optarg;
                break;

            case 'l':		/* local host */
                localhost = optarg;
                break;

            case 's':		/* silent */
                to_stdout = 0;
                break;

            case 'k':		/* backward compat */
                keep_alive = 1;
                break;

            case 'r':		/* reload */
                reload = 1;
                break;

            case 'p':		/* port number */
                sscanf(optarg, "%d", &port);
                if (port < 1)
                    port = CACHE_HTTP_PORT;	/* default */
                break;

            case 'P':
                put_file = xstrdup(optarg);
                break;

            case 'i':		/* IMS */
                ims = (time_t) atoi(optarg);
                break;

            case 'm':
                method = xstrdup(optarg);
                break;

            case 't':
                method = xstrdup("TRACE");
                max_forwards = atoi(optarg);
                break;

            case 'g':
                ping = 1;
                pcount = atoi(optarg);
                to_stdout = 0;
                break;

            case 'I':
                if ((ping_int = atoi(optarg) * 1000) <= 0)
                    usage(argv[0]);
                break;

            case 'H':
                if (strlen(optarg)) {
                    char *t;
                    strncpy(extra_hdrs, optarg, sizeof(extra_hdrs));
                    while ((t = strstr(extra_hdrs, "\\n")))
                        *t = '\r', *(t + 1) = '\n';
                }
                break;

            case 'T':
                io_timeout = atoi(optarg);
                break;

            case 'u':
                proxy_user = optarg;
                break;

            case 'w':
                proxy_password = optarg;
                break;

            case 'U':
                www_user = optarg;
                break;

            case 'W':
                www_password = optarg;
                break;

#if HAVE_GSSAPI
            case 'n':
                proxy_neg = 1;
                break;

            case 'N':
                www_neg = 1;
                break;
#endif
            case 'v':
                /* undocumented: may increase verb-level by giving more -v's */
                opt_verbose=true;
                break;

            case '?':		/* usage */

            default:
                usage(argv[0]);
                break;
            }
    }
#if _SQUID_WINDOWS_
    {
        WSADATA wsaData;
        WSAStartup(2, &wsaData);
        atexit(Win32SockCleanup);
    }
#endif
    /* Build the HTTP request */
    if (strncmp(url, "mgr:", 4) == 0) {
        char *t = xstrdup(url + 4);
        const char *at = NULL;
        if (!strrchr(t, '@')) { // ignore any -w password if @ is explicit already.
            at = proxy_password;
        }
        // embed the -w proxy password into old-style cachemgr URLs
        if (at)
            snprintf(url, BUFSIZ, "cache_object://%s/%s@%s", hostname, t, at);
        else
            snprintf(url, BUFSIZ, "cache_object://%s/%s", hostname, t);
        xfree(t);
    }
    if (put_file) {
        put_fd = open(put_file, O_RDONLY);
        set_our_signal();

        if (put_fd < 0) {
            fprintf(stderr, "%s: can't open file (%s)\n", argv[0],
                    xstrerror());
            exit(-1);
        }
#if _SQUID_WINDOWS_
        setmode(put_fd, O_BINARY);
#endif

        if (fstat(put_fd, &sb) < 0) {
            fprintf(stderr, "%s: can't identify length of file (%s)\n", argv[0], xstrerror());
        }
    }

    if (!host) {
        char *newhost = strstr(url, "://");
        if (newhost) {
            char *t;
            newhost += 3;
            newhost = xstrdup(newhost);
            t = newhost + strcspn(newhost, "@/?");
            if (*t == '@') {
                newhost = t + 1;
                t = newhost + strcspn(newhost, "@/?");
            }
            *t = '\0';
            host = newhost;
        }
    }

    if (version[0] == '-' || !version[0]) {
        /* HTTP/0.9, no headers, no version */
        snprintf(msg, BUFSIZ, "%s %s\r\n", method, url);
    } else {
        if (!xisdigit(version[0])) // not HTTP/n.n
            snprintf(msg, BUFSIZ, "%s %s %s\r\n", method, url, version);
        else
            snprintf(msg, BUFSIZ, "%s %s HTTP/%s\r\n", method, url, version);

        if (host) {
            snprintf(buf, BUFSIZ, "Host: %s\r\n", host);
            strcat(msg,buf);
        }

        if (useragent == NULL) {
            snprintf(buf, BUFSIZ, "User-Agent: squidclient/%s\r\n", VERSION);
            strcat(msg,buf);
        } else if (useragent[0] != '\0') {
            snprintf(buf, BUFSIZ, "User-Agent: %s\r\n", useragent);
            strcat(msg,buf);
        }

        if (reload) {
            snprintf(buf, BUFSIZ, "Cache-Control: no-cache\r\n");
            strcat(msg, buf);
        }
        if (put_fd > 0) {
            snprintf(buf, BUFSIZ, "Content-length: %" PRId64 "\r\n", (int64_t) sb.st_size);
            strcat(msg, buf);
        }
        if (opt_noaccept == 0) {
            snprintf(buf, BUFSIZ, "Accept: */*\r\n");
            strcat(msg, buf);
        }
        if (ims) {
            snprintf(buf, BUFSIZ, "If-Modified-Since: %s\r\n", mkrfc1123(ims));
            strcat(msg, buf);
        }
        if (max_forwards > -1) {
            snprintf(buf, BUFSIZ, "Max-Forwards: %d\r\n", max_forwards);
            strcat(msg, buf);
        }
        if (proxy_user) {
            const char *user = proxy_user;
            const char *password = proxy_password;
#if HAVE_GETPASS
            if (!password)
                password = getpass("Proxy password: ");
#endif
            if (!password) {
                fprintf(stderr, "ERROR: Proxy password missing\n");
                exit(1);
            }
            snprintf(buf, BUFSIZ, "%s:%s", user, password);
            snprintf(buf, BUFSIZ, "Proxy-Authorization: Basic %s\r\n", old_base64_encode(buf));
            strcat(msg, buf);
        }
        if (www_user) {
            const char *user = www_user;
            const char *password = www_password;
#if HAVE_GETPASS
            if (!password)
                password = getpass("WWW password: ");
#endif
            if (!password) {
                fprintf(stderr, "ERROR: WWW password missing\n");
                exit(1);
            }
            snprintf(buf, BUFSIZ, "%s:%s", user, password);
            snprintf(buf, BUFSIZ, "Authorization: Basic %s\r\n", old_base64_encode(buf));
            strcat(msg, buf);
        }
#if HAVE_GSSAPI
        if (www_neg) {
            if (host) {
                snprintf(buf, BUFSIZ, "Authorization: Negotiate %s\r\n", GSSAPI_token(host));
                strcat(msg, buf);
            } else
                fprintf(stderr, "ERROR: server host missing\n");
        }
        if (proxy_neg) {
            if (hostname) {
                snprintf(buf, BUFSIZ, "Proxy-Authorization: Negotiate %s\r\n", GSSAPI_token(hostname));
                strcat(msg, buf);
            } else
                fprintf(stderr, "ERROR: proxy server host missing\n");
        }
#endif

        /* HTTP/1.0 may need keep-alive explicitly */
        if (strcmp(version, "1.0") == 0 && keep_alive)
            strcat(msg, "Connection: keep-alive\r\n");

        /* HTTP/1.1 may need close explicitly */
        if (!keep_alive)
            strcat(msg, "Connection: close\r\n");

        strcat(msg, extra_hdrs);
        strcat(msg, "\r\n");
    }

    if (opt_verbose)
        fprintf(stderr, "Request:'%s'\n", msg);

    if (ping) {
#if HAVE_SIGACTION

        struct sigaction sa, osa;

        if (sigaction(SIGINT, NULL, &osa) == 0 && osa.sa_handler == SIG_DFL) {
            sa.sa_handler = catchSignal;
            sa.sa_flags = 0;
            sigemptyset(&sa.sa_mask);
            (void) sigaction(SIGINT, &sa, NULL);
        }
#else
        void (*osig) (int);

        if ((osig = signal(SIGINT, catchSignal)) != SIG_DFL)
            (void) signal(SIGINT, osig);

#endif

    }
    loops = ping ? pcount : 1;

    for (i = 0; loops == 0 || i < loops; ++i) {
        int fsize = 0;
        struct addrinfo *AI = NULL;

        if (opt_verbose)
            fprintf(stderr, "Resolving... %s\n", hostname);

        /* Connect to the server */

        if (localhost) {
            if ( !iaddr.GetHostByName(localhost) ) {
                fprintf(stderr, "client: ERROR: Cannot resolve %s: Host unknown.\n", localhost);
                exit(1);
            }
        } else {
            /* Process the remote host name to locate the Protocol required
               in case we are being asked to link to another version of squid */
            if ( !iaddr.GetHostByName(hostname) ) {
                fprintf(stderr, "client: ERROR: Cannot resolve %s: Host unknown.\n", hostname);
                exit(1);
            }
        }

        iaddr.GetAddrInfo(AI);
        if ((conn = socket(AI->ai_family, AI->ai_socktype, 0)) < 0) {
            perror("client: socket");
            iaddr.FreeAddrInfo(AI);
            exit(1);
        }
        iaddr.FreeAddrInfo(AI);

        if (localhost && client_comm_bind(conn, iaddr) < 0) {
            perror("client: bind");
            exit(1);
        }

        iaddr.SetEmpty();
        if ( !iaddr.GetHostByName(hostname) ) {
            fprintf(stderr, "client: ERROR: Cannot resolve %s: Host unknown.\n", hostname);
            exit(1);
        }

        iaddr.SetPort(port);

        if (opt_verbose) {
            char ipbuf[MAX_IPSTRLEN];
            fprintf(stderr, "Connecting... %s(%s)\n", hostname, iaddr.NtoA(ipbuf, MAX_IPSTRLEN));
        }

        if (client_comm_connect(conn, iaddr, ping ? &tv1 : NULL) < 0) {
            char hostnameBuf[MAX_IPSTRLEN];
            iaddr.ToURL(hostnameBuf, MAX_IPSTRLEN);
            if (errno == 0) {
                fprintf(stderr, "client: ERROR: Cannot connect to %s: Host unknown.\n", hostnameBuf);
            } else {
                char tbuf[BUFSIZ];
                snprintf(tbuf, BUFSIZ, "client: ERROR: Cannot connect to %s", hostnameBuf);
                perror(tbuf);
            }
            exit(1);
        }
        if (opt_verbose) {
            char ipbuf[MAX_IPSTRLEN];
            fprintf(stderr, "Connected to: %s (%s)\n", hostname, iaddr.NtoA(ipbuf, MAX_IPSTRLEN));
        }

        /* Send the HTTP request */
        bytesWritten = mywrite(conn, msg, strlen(msg));

        if (bytesWritten < 0) {
            perror("client: ERROR: write");
            exit(1);
        } else if ((unsigned) bytesWritten != strlen(msg)) {
            fprintf(stderr, "client: ERROR: Cannot send request?: %s\n", msg);
            exit(1);
        }

        if (put_file) {
            int x;
            lseek(put_fd, 0, SEEK_SET);
            while ((x = read(put_fd, buf, sizeof(buf))) > 0) {

                x = mywrite(conn, buf, x);

                total_bytes += x;

                if (x <= 0)
                    break;
            }

            if (x != 0)
                fprintf(stderr, "client: ERROR: Cannot send file.\n");
        }
        /* Read the data */

#if _SQUID_WINDOWS_
        setmode(1, O_BINARY);
#endif

        while ((len = myread(conn, buf, sizeof(buf))) > 0) {
            fsize += len;

            if (to_stdout && fwrite(buf, len, 1, stdout) != 1)
                perror("client: ERROR writing to stdout");
        }

#if _SQUID_WINDOWS_
        setmode(1, O_TEXT);
#endif

        (void) close(conn);	/* done with socket */

        if (interrupted)
            break;

        if (ping) {

            struct tm *tmp;
            time_t t2s;
            long elapsed_msec;

            (void) Now(&tv2);
            elapsed_msec = tvSubMsec(tv1, tv2);
            t2s = tv2.tv_sec;
            tmp = localtime(&t2s);
            fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d [%d]: %ld.%03ld secs, %f KB/s\n",
                    tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
                    tmp->tm_hour, tmp->tm_min, tmp->tm_sec, i + 1,
                    elapsed_msec / 1000, elapsed_msec % 1000,
                    elapsed_msec ? (double) fsize / elapsed_msec : -1.0);

            if (i == 0 || elapsed_msec < ping_min)
                ping_min = elapsed_msec;

            if (i == 0 || elapsed_msec > ping_max)
                ping_max = elapsed_msec;

            ping_sum += elapsed_msec;

            /* Delay until next "ping_int" boundary */
            if ((loops == 0 || i + 1 < loops) && elapsed_msec < ping_int) {

                struct timeval tvs;
                long msec_left = ping_int - elapsed_msec;

                tvs.tv_sec = msec_left / 1000;
                tvs.tv_usec = (msec_left % 1000) * 1000;
                select(0, NULL, NULL, NULL, &tvs);
            }
        }
    }

    if (ping && i) {
        ping_mean = ping_sum / i;
        fprintf(stderr, "%d requests, round-trip (secs) min/avg/max = "
                "%ld.%03ld/%ld.%03ld/%ld.%03ld\n", i,
                ping_min / 1000, ping_min % 1000, ping_mean / 1000, ping_mean % 1000,
                ping_max / 1000, ping_max % 1000);
    }
    exit(0);
    /*NOTREACHED */
    return 0;
}

static int
client_comm_bind(int sock, const Ip::Address &addr)
{

    int res;

    static struct addrinfo *AI = NULL;

    /* Set up the source socket address from which to send. */

    addr.GetAddrInfo(AI);

    res = bind(sock, AI->ai_addr, AI->ai_addrlen);

    addr.FreeAddrInfo(AI);

    return res;
}

static int
client_comm_connect(int sock, const Ip::Address &addr, struct timeval *tvp)
{
    int res;
    static struct addrinfo *AI = NULL;

    /* Set up the destination socket address for message to send to. */

    addr.GetAddrInfo(AI);

    res = connect(sock, AI->ai_addr, AI->ai_addrlen);

    addr.FreeAddrInfo(AI);

    if (tvp)
        (void) Now(tvp);

    return res;
}

static int
Now(struct timeval *tp)
{
#if GETTIMEOFDAY_NO_TZP
    return gettimeofday(tp);
#else

    return gettimeofday(tp, NULL);
#endif
}				/* ARGSUSED */

void
catchSignal(int sig)
{
    interrupted = 1;
    fprintf(stderr, "Interrupted.\n");
}

void
pipe_handler(int sig)
{
    fprintf(stderr, "SIGPIPE received.\n");
}

static void
set_our_signal(void)
{
#if HAVE_SIGACTION

    struct sigaction sa;
    sa.sa_handler = pipe_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        fprintf(stderr, "Cannot set PIPE signal.\n");
        exit(-1);
    }
#else
    signal(SIGPIPE, pipe_handler);

#endif

}

static ssize_t
myread(int fd, void *buf, size_t len)
{
#if _SQUID_WINDOWS_
    return recv(fd, buf, len, 0);
#else
    alarm(io_timeout);
    return read(fd, buf, len);
#endif
}

static ssize_t
mywrite(int fd, void *buf, size_t len)
{
#if _SQUID_WINDOWS_
    return send(fd, buf, len, 0);
#else
    alarm(io_timeout);
    return write(fd, buf, len);
#endif
}

#if HAVE_GSSAPI
/*
 * Check return valuse major_status, minor_status for error and print error description
 * in case of an error.
 * Returns 1 in case of gssapi error
 *         0 in case of no gssapi error
 */
#define BUFFER_SIZE 8192
static int
check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, const char *function)
{
    if (GSS_ERROR(major_status)) {
        OM_uint32 maj_stat, min_stat;
        OM_uint32 msg_ctx = 0;
        gss_buffer_desc status_string;
        char buf[BUFFER_SIZE];
        size_t len;

        len = 0;
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert major status code (GSS-API error) to text */
            maj_stat = gss_display_status(&min_stat, major_status,
                                          GSS_C_GSS_CODE,
                                          GSS_C_NULL_OID,
                                          &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                snprintf(buf + len, BUFFER_SIZE-len, "%s", (char *) status_string.value);
                len += status_string.length;
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        snprintf(buf + len, BUFFER_SIZE-len, "%s", ". ");
        len += 2;
        msg_ctx = 0;
        while (!msg_ctx) {
            /* convert minor status code (underlying routine error) to text */
            maj_stat = gss_display_status(&min_stat, minor_status,
                                          GSS_C_MECH_CODE,
                                          GSS_C_NULL_OID,
                                          &msg_ctx, &status_string);
            if (maj_stat == GSS_S_COMPLETE) {
                snprintf(buf + len, BUFFER_SIZE-len,"%s", (char *) status_string.value);
                len += status_string.length;
                gss_release_buffer(&min_stat, &status_string);
                break;
            }
            gss_release_buffer(&min_stat, &status_string);
        }
        fprintf(stderr, "%s failed: %s\n", function, buf);
        return (1);
    }
    return (0);
}

/*
 * Get gssapi token for service HTTP/<server>
 * User has to initiate a kinit user@DOMAIN on commandline first for the
 * function to be successful
 * Returns base64 encoded token if successful
 *         string "ERROR" if unsuccessful
 */
static char *
GSSAPI_token(const char *server)
{
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t server_name = GSS_C_NO_NAME;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    char *token = NULL;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    if (!server) {
        fprintf(stderr, "Error: No server name\n");
        return (char *)"ERROR";
    }
    service.value = xmalloc(strlen("HTTP") + strlen(server) + 2);
    snprintf((char *) service.value, strlen("HTTP") + strlen(server) + 2, "%s@%s", "HTTP", server);
    service.length = strlen((char *) service.value);

    major_status = gss_import_name(&minor_status, &service,
                                   gss_nt_service_name, &server_name);

    if (!check_gss_err(major_status, minor_status, "gss_import_name()")) {

        major_status = gss_init_sec_context(&minor_status,
                                            GSS_C_NO_CREDENTIAL,
                                            &gss_context,
                                            server_name,
                                            gss_mech_spnego,
                                            0,
                                            0,
                                            GSS_C_NO_CHANNEL_BINDINGS,
                                            &input_token,
                                            NULL,
                                            &output_token,
                                            NULL,
                                            NULL);

        if (!check_gss_err(major_status, minor_status, "gss_init_sec_context()")) {

            if (output_token.length)
                token = (char *) base64_encode_bin((const char *) output_token.value, output_token.length);
        }
    }

    if (!output_token.length)
        token = (char *) "ERROR";
    gss_delete_sec_context(&minor_status, &gss_context, NULL);
    gss_release_buffer(&minor_status, &service);
    gss_release_buffer(&minor_status, &input_token);
    gss_release_buffer(&minor_status, &output_token);
    gss_release_name(&minor_status, &server_name);

    return token;
}
#endif

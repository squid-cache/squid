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
#include "tools/squidclient/gssapi_support.h"
#include "tools/squidclient/Parameters.h"
#include "tools/squidclient/Ping.h"

#if _SQUID_WINDOWS_
/** \cond AUTODOCS-IGNORE */
using namespace Squid;
/** \endcond */
#endif

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#if _SQUID_WINDOWS_
#include <io.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
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

#ifndef BUFSIZ
#define BUFSIZ		8192
#endif
#ifndef MESSAGELEN
#define MESSAGELEN	65536
#endif
#ifndef HEADERLEN
#define HEADERLEN	65536
#endif

/// display debug messages at varying verbosity levels
#define debugVerbose(LEVEL, MESSAGE) \
    while ((LEVEL) <= scParams.verbosityLevel) {std::cerr << MESSAGE << std::endl; break;}

/* Local functions */
static int client_comm_bind(int, const Ip::Address &);

static int client_comm_connect(int, const Ip::Address &);
static void usage(const char *progname);

void pipe_handler(int sig);
static void set_our_signal(void);
static ssize_t myread(int fd, void *buf, size_t len);
static ssize_t mywrite(int fd, void *buf, size_t len);

Parameters scParams;

static int put_fd;
static char *put_file = NULL;

static struct stat sb;
int total_bytes = 0;
int io_timeout = 120;

#if _SQUID_AIX_
/* Bug 3854: AIX 6.1 tries to link in this fde.h global symbol
 * despite squidclient not using any of the fd_* code.
 */
fde *fde::Table = NULL;
#endif

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
    std::cerr << "Version: " << VERSION << std::endl
              << "Usage: " << progname << " [Basic Options] [HTTP Options]" << std::endl
              << std::endl
              << "Basic Options:" << std::endl
              << "    -h host         Send message to server on 'host'.  Default is localhost." << std::endl
              << "    -l host         Specify a local IP address to bind to.  Default is none." << std::endl
              << "    -p port         Port number on server to contact. Default is " << CACHE_HTTP_PORT << "." << std::endl
              << "    -s | --quiet    Silent.  Do not print response message to stdout." << std::endl
              << "    -T timeout      Timeout value (seconds) for read/write operations" << std::endl
              << "    -v | --verbose  Verbose debugging. Repeat (-vv) to increase output level." << std::endl
              << "                    Levels:" << std::endl
              << "                      1 - Print outgoing request message to stderr." << std::endl
              << "                      2 - Print action trace to stderr." << std::endl
              << "    --help          Display this help text." << std::endl
              << std::endl;
    Ping::Config.usage();
    std::cerr
        << "HTTP Options:" << std::endl
        << "    -a           Do NOT include Accept: header." << std::endl
        << "    -A           User-Agent: header. Use \"\" to omit." << std::endl
        << "    -H 'string'  Extra headers to send. Use '\\n' for new lines." << std::endl
        << "    -i IMS       If-Modified-Since time (in Epoch seconds)." << std::endl
        << "    -j hosthdr   Host header content" << std::endl
        << "    -k           Keep the connection active. Default is to do only one request then close." << std::endl
        << "    -m method    Request method, default is GET." << std::endl
#if HAVE_GSSAPI
        << "    -n           Proxy Negotiate(Kerberos) authentication" << std::endl
        << "    -N           WWW Negotiate(Kerberos) authentication" << std::endl
#endif
        << "    -P file      Send content from the named file as request payload" << std::endl
        << "    -r           Force cache to reload URL" << std::endl
        << "    -t count     Trace count cache-hops" << std::endl
        << "    -u user      Proxy authentication username" << std::endl
        << "    -U user      WWW authentication username" << std::endl
        << "    -V version   HTTP Version. Use '-' for HTTP/0.9 omitted case" << std::endl
        << "    -w password  Proxy authentication password" << std::endl
        << "    -W password  WWW authentication password" << std::endl
        ;
    exit(1);
}

int
main(int argc, char *argv[])
{
    int conn, len, bytesWritten;
    uint16_t port;
    bool to_stdout, reload;
    int keep_alive = 0;
    int opt_noaccept = 0;
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
    to_stdout = true;
    reload = false;

    Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.
    if (argc < 2 || argv[argc-1][0] == '-') {
        usage(argv[0]);		/* need URL */
    } else if (argc >= 2) {
        strncpy(url, argv[argc - 1], BUFSIZ);
        url[BUFSIZ - 1] = '\0';

        int optIndex = 0;
        const char *shortOpStr = "aA:h:j:V:l:P:i:kmnN:p:rsvt:p:H:T:u:U:w:W:?";

        // options for controlling squidclient
        static struct option basicOptions[] = {
            /* These are the generic options for squidclient itself */
            {"help",    no_argument, 0, '?'},
            {"verbose", no_argument, 0, 'v'},
            {"quiet",   no_argument, 0, 's'},
            {"ping",    no_argument, 0, '\1'},
            {0, 0, 0, 0}
        };

        int c;
        while ((c = getopt_long(argc, argv, shortOpStr, basicOptions, &optIndex)) != -1) {

            // modules parse their own specific options
            switch (c) {
            case '\1':
                to_stdout = 0;
                if (Ping::Config.parseCommandOpts(argc, argv, c, optIndex))
                    continue;
                break;

            default: // fall through to next switch
                break;
            }

            switch (c) {

            case '\0': // dummy value for end-of-options
                break;

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
                to_stdout = false;
                break;

            case 'k':		/* backward compat */
                keep_alive = 1;
                break;

            case 'r':		/* reload */
                reload = true;
                break;

            case 'p':		/* port number */
                sscanf(optarg, "%hd", &port);
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

            case 'n':
#if HAVE_GSSAPI
                proxy_neg = 1;
#else
                std::cerr << "ERROR: Negotiate authentication not supported." << std::endl;
                usage(argv[0]);
#endif
                break;

            case 'N':
#if HAVE_GSSAPI
                www_neg = 1;
#else
                std::cerr << "ERROR: Negotiate authentication not supported." << std::endl;
                usage(argv[0]);
#endif
                break;

            case 'v':
                /* undocumented: may increase verb-level by giving more -v's */
                ++scParams.verbosityLevel;
                debugVerbose(2, "verbosity level set to " << scParams.verbosityLevel);
                break;

            case '?':		/* usage */

            default:
                usage(argv[0]);
                break;
            }
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
            std::cerr << "ERROR: can't open file (" << xstrerror() << ")" << std::endl;
            exit(-1);
        }
#if _SQUID_WINDOWS_
        setmode(put_fd, O_BINARY);
#endif

        if (fstat(put_fd, &sb) < 0) {
            std::cerr << "ERROR: can't identify length of file (" << xstrerror() << ")" << std::endl;
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
                std::cerr << "ERROR: Proxy password missing" << std::endl;
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
                std::cerr << "ERROR: WWW password missing" << std::endl;
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
                std::cerr << "ERROR: server host missing" << std::endl;
        }
        if (proxy_neg) {
            if (hostname) {
                snprintf(buf, BUFSIZ, "Proxy-Authorization: Negotiate %s\r\n", GSSAPI_token(hostname));
                strcat(msg, buf);
            } else
                std::cerr << "ERROR: proxy server host missing" << std::endl;
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

    debugVerbose(1, "Request:" << std::endl << msg << std::endl << ".");

    uint32_t loops = Ping::Init();

    for (uint32_t i = 0; loops == 0 || i < loops; ++i) {
        size_t fsize = 0;
        struct addrinfo *AI = NULL;

        debugVerbose(2, "Resolving... " << hostname);

        /* Connect to the server */

        if (localhost) {
            if ( !iaddr.GetHostByName(localhost) ) {
                std::cerr << "ERROR: Cannot resolve " << localhost << ": Host unknown." << std::endl;
                exit(1);
            }
        } else {
            /* Process the remote host name to locate the Protocol required
               in case we are being asked to link to another version of squid */
            if ( !iaddr.GetHostByName(hostname) ) {
                std::cerr << "ERROR: Cannot resolve " << hostname << ": Host unknown." << std::endl;
                exit(1);
            }
        }

        iaddr.getAddrInfo(AI);
        if ((conn = socket(AI->ai_family, AI->ai_socktype, 0)) < 0) {
            std::cerr << "ERROR: could not open socket to " << iaddr << std::endl;
            Ip::Address::FreeAddrInfo(AI);
            exit(1);
        }
        Ip::Address::FreeAddrInfo(AI);

        if (localhost && client_comm_bind(conn, iaddr) < 0) {
            std::cerr << "ERROR: could not bind socket to " << iaddr << std::endl;
            exit(1);
        }

        iaddr.setEmpty();
        if ( !iaddr.GetHostByName(hostname) ) {
            std::cerr << "ERROR: Cannot resolve " << hostname << ": Host unknown." << std::endl;
            exit(1);
        }

        iaddr.port(port);

        debugVerbose(2, "Connecting... " << hostname << " (" << iaddr << ")");

        if (client_comm_connect(conn, iaddr) < 0) {
            char hostnameBuf[MAX_IPSTRLEN];
            iaddr.toUrl(hostnameBuf, MAX_IPSTRLEN);
            std::cerr << "ERROR: Cannot connect to " << hostnameBuf
                      << (!errno ?": Host unknown." : "") << std::endl;
            exit(1);
        }
        debugVerbose(2, "Connected to: " << hostname << " (" << iaddr << ")");

        /* Send the HTTP request */
        debugVerbose(2, "Sending HTTP request ... ");
        bytesWritten = mywrite(conn, msg, strlen(msg));

        if (bytesWritten < 0) {
            std::cerr << "ERROR: write" << std::endl;
            exit(1);
        } else if ((unsigned) bytesWritten != strlen(msg)) {
            std::cerr << "ERROR: Cannot send request?: " << std::endl << msg << std::endl;
            exit(1);
        }
        debugVerbose(2, "done.");

        if (put_file) {
            debugVerbose(1, "Sending HTTP request payload ...");
            int x;
            lseek(put_fd, 0, SEEK_SET);
            while ((x = read(put_fd, buf, sizeof(buf))) > 0) {

                x = mywrite(conn, buf, x);

                total_bytes += x;

                if (x <= 0)
                    break;
            }

            if (x != 0)
                std::cerr << "ERROR: Cannot send file." << std::endl;
            else
                debugVerbose(1, "done.");
        }
        /* Read the data */

#if _SQUID_WINDOWS_
        setmode(1, O_BINARY);
#endif

        while ((len = myread(conn, buf, sizeof(buf))) > 0) {
            fsize += len;

            if (to_stdout && fwrite(buf, len, 1, stdout) != 1)
                std::cerr << "ERROR: writing to stdout: " << xstrerror() << std::endl;
        }

#if _SQUID_WINDOWS_
        setmode(1, O_TEXT);
#endif

        (void) close(conn);	/* done with socket */

        if (Ping::LoopDone(i))
            break;

        Ping::TimerStop(fsize);
    }

    Ping::DisplayStats();
    return 0;
}

/// Set up the source socket address from which to send.
static int
client_comm_bind(int sock, const Ip::Address &addr)
{
    static struct addrinfo *AI = NULL;
    addr.getAddrInfo(AI);
    int res = bind(sock, AI->ai_addr, AI->ai_addrlen);
    Ip::Address::FreeAddrInfo(AI);
    return res;
}

/// Set up the destination socket address for message to send to.
static int
client_comm_connect(int sock, const Ip::Address &addr)
{
    static struct addrinfo *AI = NULL;
    addr.getAddrInfo(AI);
    int res = connect(sock, AI->ai_addr, AI->ai_addrlen);
    Ip::Address::FreeAddrInfo(AI);
    Ping::TimerStart();
    return res;
}

void
pipe_handler(int sig)
{
    std::cerr << "SIGPIPE received." << std::endl;
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
        std::cerr << "ERROR: Cannot set PIPE signal." << std::endl;
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

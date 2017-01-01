/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base64.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "rfc1123.h"
#include "tools/squidclient/gssapi_support.h"
#include "tools/squidclient/Parameters.h"
#include "tools/squidclient/Ping.h"
#include "tools/squidclient/Transport.h"

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
#define BUFSIZ      8192
#endif
#ifndef MESSAGELEN
#define MESSAGELEN  65536
#endif
#ifndef HEADERLEN
#define HEADERLEN   65536
#endif

/* Local functions */
static void usage(const char *progname);

void pipe_handler(int sig);
static void set_our_signal(void);

Parameters scParams;

static int put_fd;
static char *put_file = NULL;

static struct stat sb;
int total_bytes = 0;

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
              << std::endl;
    std::cerr
            << "    -s | --quiet    Silent.  Do not print response message to stdout." << std::endl
            << "    -v | --verbose  Verbose debugging. Repeat (-vv) to increase output level." << std::endl
            << "                    Levels:" << std::endl
            << "                      1 - Print outgoing request message to stderr." << std::endl
            << "                      2 - Print action trace to stderr." << std::endl
            << "    --help          Display this help text." << std::endl
            << std::endl;
    Transport::Config.usage();
    Ping::Config.usage();
    std::cerr
            << "HTTP Options:" << std::endl
            << "    -a           Do NOT include Accept: header." << std::endl
            << "    -A           User-Agent: header. Use \"\" to omit." << std::endl
            << "    -H 'string'  Extra headers to send. Supports '\\\\', '\\n', '\\r' and '\\t'." << std::endl
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

static void
shellUnescape(char *buf)
{
    if (!buf)
        return;

    unsigned char *p, *d;

    d = p = reinterpret_cast<unsigned char *>(buf);

    while (auto ch = *p) {

        if (ch == '\\') {
            ++p;

            switch (*p) {
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            case '\\':
                ch = '\\';
                break;
            default:
                ch = *p;
                debugVerbose(1, "Warning: unsupported shell code '\\" << ch << "'");
                break;
            }

            *d = ch;

            if (!ch)
                continue;

        } else {
            *d = *p;
        }

        ++p;
        ++d;
    }

    *d = '\0';
}

int
main(int argc, char *argv[])
{
    int len, bytesWritten;
    bool to_stdout, reload;
    int keep_alive = 0;
    int opt_noaccept = 0;
#if HAVE_GSSAPI
    int www_neg = 0, proxy_neg = 0;
#endif
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
    extra_hdrs[0] = '\0';
    to_stdout = true;
    reload = false;

    Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.
    if (argc < 2 || argv[argc-1][0] == '-') {
        usage(argv[0]);     /* need URL */
    } else if (argc >= 2) {
        strncpy(url, argv[argc - 1], BUFSIZ);
        url[BUFSIZ - 1] = '\0';

        int optIndex = 0;
        const char *shortOpStr = "aA:h:j:V:l:P:i:km:nNp:rsvt:H:T:u:U:w:W:?";

        // options for controlling squidclient
        static struct option basicOptions[] = {
            /* These are the generic options for squidclient itself */
            {"help",    no_argument, 0, '?'},
            {"verbose", no_argument, 0, 'v'},
            {"quiet",   no_argument, 0, 's'},
            {"host",    required_argument, 0, 'h'},
            {"local",   required_argument, 0, 'l'},
            {"port",    required_argument, 0, 'p'},
            {"ping",    no_argument, 0, '\1'},
            {"https",   no_argument, 0, '\3'},
            {0, 0, 0, 0}
        };

        int c;
        while ((c = getopt_long(argc, argv, shortOpStr, basicOptions, &optIndex)) != -1) {

            // modules parse their own specific options
            switch (c) {
            case '\1':
                to_stdout = 0;
                Ping::Config.parseCommandOpts(argc, argv, c, optIndex);
                continue;

            case 'h':       /* remote host */
            case 'l':       /* local host */
            case 'p':       /* port number */
                // rewind and let the Transport::Config parser handle
                optind -= 2;

            case '\3': // request over a TLS connection
                Transport::Config.parseCommandOpts(argc, argv, c, optIndex);
                continue;

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

            case 'j':
                host = optarg;
                break;

            case 'V':
                version = optarg;
                break;

            case 's':       /* silent */
                to_stdout = false;
                break;

            case 'k':       /* backward compat */
                keep_alive = 1;
                break;

            case 'r':       /* reload */
                reload = true;
                break;

            case 'P':
                put_file = xstrdup(optarg);
                break;

            case 'i':       /* IMS */
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
                    strncpy(extra_hdrs, optarg, sizeof(extra_hdrs));
                    shellUnescape(extra_hdrs);
                }
                break;

            case 'T':
                Transport::Config.ioTimeout = atoi(optarg);
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

            case '?':       /* usage */

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
            snprintf(url, BUFSIZ, "cache_object://%s/%s@%s", Transport::Config.hostname, t, at);
        else
            snprintf(url, BUFSIZ, "cache_object://%s/%s", Transport::Config.hostname, t);
        xfree(t);
    }
    if (put_file) {
        put_fd = open(put_file, O_RDONLY);
        set_our_signal();

        if (put_fd < 0) {
            int xerrno = errno;
            std::cerr << "ERROR: can't open file (" << xstrerr(xerrno) << ")" << std::endl;
            exit(-1);
        }
#if _SQUID_WINDOWS_
        setmode(put_fd, O_BINARY);
#endif

        if (fstat(put_fd, &sb) < 0) {
            int xerrno = errno;
            std::cerr << "ERROR: can't identify length of file (" << xstrerr(xerrno) << ")" << std::endl;
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
        struct base64_encode_ctx ctx;
        base64_encode_init(&ctx);
        size_t blen;
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
            uint8_t *pwdBuf = new uint8_t[base64_encode_len(strlen(user)+1+strlen(password))];
            blen = base64_encode_update(&ctx, pwdBuf, strlen(user), reinterpret_cast<const uint8_t*>(user));
            blen += base64_encode_update(&ctx, pwdBuf+blen, 1, reinterpret_cast<const uint8_t*>(":"));
            blen += base64_encode_update(&ctx, pwdBuf+blen, strlen(password), reinterpret_cast<const uint8_t*>(password));
            blen += base64_encode_final(&ctx, pwdBuf+blen);
            snprintf(buf, BUFSIZ, "Proxy-Authorization: Basic %.*s\r\n", (int)blen, reinterpret_cast<char*>(pwdBuf));
            strcat(msg, buf);
            delete[] pwdBuf;
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
            uint8_t *pwdBuf = new uint8_t[base64_encode_len(strlen(user)+1+strlen(password))];
            blen = base64_encode_update(&ctx, pwdBuf, strlen(user), reinterpret_cast<const uint8_t*>(user));
            blen += base64_encode_update(&ctx, pwdBuf+blen, 1, reinterpret_cast<const uint8_t*>(":"));
            blen += base64_encode_update(&ctx, pwdBuf+blen, strlen(password), reinterpret_cast<const uint8_t*>(password));
            blen += base64_encode_final(&ctx, pwdBuf+blen);
            snprintf(buf, BUFSIZ, "Authorization: Basic %.*s\r\n", (int)blen, reinterpret_cast<char*>(pwdBuf));
            strcat(msg, buf);
            delete[] pwdBuf;
        }
#if HAVE_GSSAPI
        if (www_neg) {
            if (host) {
                const char *token = GSSAPI_token(host);
                snprintf(buf, BUFSIZ, "Authorization: Negotiate %s\r\n", token);
                strcat(msg, buf);
                delete[] token;
            } else
                std::cerr << "ERROR: server host missing" << std::endl;
        }
        if (proxy_neg) {
            if (Transport::Config.hostname) {
                const char *token = GSSAPI_token(Transport::Config.hostname);
                snprintf(buf, BUFSIZ, "Proxy-Authorization: Negotiate %s\r\n", token);
                strcat(msg, buf);
                delete[] token;
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

        if (!Transport::Connect())
            continue;

        /* Send the HTTP request */
        debugVerbose(2, "Sending HTTP request ... ");
        bytesWritten = Transport::Write(msg, strlen(msg));

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

                x = Transport::Write(buf, x);

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

        while ((len = Transport::Read(buf, sizeof(buf))) > 0) {
            fsize += len;

            if (to_stdout && fwrite(buf, len, 1, stdout) != 1) {
                int xerrno = errno;
                std::cerr << "ERROR: writing to stdout: " << xstrerr(xerrno) << std::endl;
            }
        }

#if USE_GNUTLS
        if (Transport::Config.tlsEnabled) {
            if (len == 0) {
                std::cerr << "- Peer has closed the TLS connection" << std::endl;
            } else if (!gnutls_error_is_fatal(len)) {
                std::cerr << "WARNING: " << gnutls_strerror(len) << std::endl;
            } else {
                std::cerr << "ERROR: " << gnutls_strerror(len) << std::endl;
            }
        }
#endif

#if _SQUID_WINDOWS_
        setmode(1, O_TEXT);
#endif

        Transport::CloseConnection();

        if (Ping::LoopDone(i))
            break;

        Ping::TimerStop(fsize);
    }

    Ping::DisplayStats();
    Transport::ShutdownTls();
    return 0;
}

void
pipe_handler(int)
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


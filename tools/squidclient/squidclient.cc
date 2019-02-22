/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sstream>
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
    exit(EXIT_FAILURE);
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

/// [Proxy-]Authorization header producer
class Authorization
{
public:
    Authorization(const char *aHeader, const char *aDestination):
        header(aHeader), destination(aDestination) {}

    /// finalizes and writes the right HTTP header to the given stream
    void commit(std::ostream &os);

    std::string header; ///< HTTP header name to send
    std::string destination; ///< used when describing password
    const char *user = nullptr; ///< user name to encode and send
    const char *password = nullptr; ///< user password to encode and send
};

void
Authorization::commit(std::ostream &os)
{
#if HAVE_GETPASS
    if (!password)
        password = getpass((destination + " password: ").c_str());
#endif
    if (!password) {
        std::cerr << "ERROR: " << destination << " password missing\n";
        exit(EXIT_FAILURE);
    }

    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);
    const auto bcapacity = base64_encode_len(strlen(user) + 1 + strlen(password));
    const auto buf = new char[bcapacity];

    size_t bsize = 0;
    bsize += base64_encode_update(&ctx, buf, strlen(user), reinterpret_cast<const uint8_t*>(user));
    bsize += base64_encode_update(&ctx, buf+bsize, 1, reinterpret_cast<const uint8_t*>(":"));
    bsize += base64_encode_update(&ctx, buf+bsize, strlen(password), reinterpret_cast<const uint8_t*>(password));
    bsize += base64_encode_final(&ctx, buf+bsize);
    assert(bsize <= bcapacity); // paranoid and late but better than nothing

    os << header << ": Basic ";
    os.write(buf, bsize);
    os << "\r\n";

    delete[] buf;
}

static Authorization ProxyAuthorization("Proxy-Authorization", "proxy");
static Authorization OriginAuthorization("Authorization", "origin server");

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
    char url[BUFSIZ];
    char buf[BUFSIZ];
    char *extra_hdrs = nullptr;
    const char *method = "GET";
    extern char *optarg;
    time_t ims = 0;
    int max_forwards = -1;

    const char *host = NULL;
    const char *version = "1.0";
    const char *useragent = NULL;

    /* set the defaults */
    to_stdout = true;
    reload = false;

    Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.
    if (argc < 2 || argv[argc-1][0] == '-') {
        usage(argv[0]);     /* need URL */
    } else if (argc >= 2) {
        strncpy(url, argv[argc - 1], sizeof(url));
        url[sizeof(url) - 1] = '\0';

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
                    if (extra_hdrs) {
                        std::cerr << "ERROR: multiple -H options not supported. Discarding previous value." << std::endl;
                        xfree(extra_hdrs);
                    }
                    extra_hdrs = xstrdup(optarg);
                    shellUnescape(extra_hdrs);
                }
                break;

            case 'T':
                Transport::Config.ioTimeout = atoi(optarg);
                break;

            case 'u':
                ProxyAuthorization.user = optarg;
                break;

            case 'w':
                ProxyAuthorization.password = optarg;
                break;

            case 'U':
                OriginAuthorization.user = optarg;
                break;

            case 'W':
                OriginAuthorization.password = optarg;
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
            at = ProxyAuthorization.password;
        }
        // embed the -w proxy password into old-style cachemgr URLs
        if (at)
            snprintf(url, sizeof(url), "cache_object://%s/%s@%s", Transport::Config.hostname, t, at);
        else
            snprintf(url, sizeof(url), "cache_object://%s/%s", Transport::Config.hostname, t);
        xfree(t);
    }
    if (put_file) {
        put_fd = open(put_file, O_RDONLY);
        set_our_signal();

        if (put_fd < 0) {
            int xerrno = errno;
            std::cerr << "ERROR: can't open file (" << xstrerr(xerrno) << ")" << std::endl;
            exit(EXIT_FAILURE);
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

    std::stringstream msg;

    if (version[0] == '-' || !version[0]) {
        /* HTTP/0.9, no headers, no version */
        msg << method << " " << url << "\r\n";
    } else {
        const auto versionImpliesHttp = xisdigit(version[0]); // is HTTP/n.n
        msg << method << " "
            << url << " "
            << (versionImpliesHttp ? "HTTP/" : "") << version
            << "\r\n";

        if (host) {
            msg << "Host: " << host << "\r\n";
        }

        if (!useragent) {
            msg  << "User-Agent: squidclient/" << VERSION << "\r\n";
        } else if (useragent[0] != '\0') {
            msg << "User-Agent: " << useragent << "\r\n";
        } // else custom: no value U-A header

        if (reload) {
            msg << "Cache-Control: no-cache\r\n";
        }
        if (put_fd > 0) {
            msg << "Content-length: " << sb.st_size << "\r\n";
        }
        if (opt_noaccept == 0) {
            msg << "Accept: */*\r\n";
        }
        if (ims) {
            msg << "If-Modified-Since: " << mkrfc1123(ims) << "\r\n";
        }
        if (max_forwards > -1) {
            msg << "Max-Forwards: " << max_forwards << "\r\n";
        }
        if (ProxyAuthorization.user)
            ProxyAuthorization.commit(msg);
        if (OriginAuthorization.user)
            OriginAuthorization.commit(msg);
#if HAVE_GSSAPI
        if (www_neg) {
            if (host) {
                const char *token = GSSAPI_token(host);
                msg << "Proxy-Authorization: Negotiate " << token << "\r\n";
                delete[] token;
            } else
                std::cerr << "ERROR: server host missing" << std::endl;
        }
        if (proxy_neg) {
            if (Transport::Config.hostname) {
                const char *token = GSSAPI_token(Transport::Config.hostname);
                msg << "Proxy-Authorization: Negotiate " << token << "\r\n";
                delete[] token;
            } else
                std::cerr << "ERROR: proxy server host missing" << std::endl;
        }
#endif

        /* HTTP/1.0 may need keep-alive explicitly */
        if (strcmp(version, "1.0") == 0 && keep_alive)
            msg << "Connection: keep-alive\r\n";

        /* HTTP/1.1 may need close explicitly */
        if (!keep_alive)
            msg << "Connection: close\r\n";

        if (extra_hdrs) {
            msg << extra_hdrs;
            safe_free(extra_hdrs);
        }
        msg << "\r\n"; // empty line ends MIME header block
    }

    msg.flush();
    const auto messageHeader = msg.str();
    debugVerbose(1, "Request:" << std::endl << messageHeader << std::endl << ".");

    uint32_t loops = Ping::Init();

    for (uint32_t i = 0; loops == 0 || i < loops; ++i) {
        size_t fsize = 0;

        if (!Transport::Connect())
            continue;

        /* Send the HTTP request */
        debugVerbose(2, "Sending HTTP request ... ");
        bytesWritten = Transport::Write(messageHeader.data(), messageHeader.length());

        if (bytesWritten < 0) {
            std::cerr << "ERROR: write" << std::endl;
            exit(EXIT_FAILURE);
        } else if (static_cast<size_t>(bytesWritten) != messageHeader.length()) {
            std::cerr << "ERROR: Failed to send the following request: " << std::endl
                      << messageHeader << std::endl;
            exit(EXIT_FAILURE);
        }
        debugVerbose(2, "done.");

        if (put_file) {
            debugVerbose(1, "Sending HTTP request payload ...");
            int x;
            if ((x = lseek(put_fd, 0, SEEK_SET)) < 0) {
                int xerrno = errno;
                std::cerr << "ERROR: lseek: " << xstrerr(xerrno) << std::endl;

            } else while ((x = read(put_fd, buf, sizeof(buf))) > 0) {

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
    return EXIT_SUCCESS;
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
        exit(EXIT_FAILURE);
    }
#else
    signal(SIGPIPE, pipe_handler);
#endif
}


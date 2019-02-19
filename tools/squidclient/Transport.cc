/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "tools/squidclient/Ping.h"
#include "tools/squidclient/Transport.h"

#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_GNUTLS_X509_H
#include <gnutls/x509.h>
#endif
#include <iostream>

Transport::TheConfig Transport::Config;

/// the current server connection FD
int conn = -1;

void
Transport::TheConfig::usage()
{
    std::cerr << "Connection Settings" << std::endl
              << "  -h | --host host     Send message to server on 'host'.  Default is localhost." << std::endl
              << "  -l | --local host    Specify a local IP address to bind to.  Default is none." << std::endl
              << "  -p | --port port     Port number on server to contact. Default is " << CACHE_HTTP_PORT << "." << std::endl
              << "  -T timeout           Timeout in seconds for read/write operations" << std::endl
#if USE_GNUTLS
              << "  --https              Use TLS/SSL on the HTTP connection" << std::endl
              << std::endl
              << "  TLS options:" << std::endl
              << "    --anonymous-tls    Use Anonymous TLS. Sets default parameters:" << std::endl
              << "                         \"PERFORMANCE:+ANON-ECDH:+ANON-DH\"" << std::endl
              << "    --params=\"...\"   Use the given parameters." << std::endl
              << "    --cert=FILE        Path to a PEM file holding the client X.509 certificate chain." << std::endl
              << "                       May be repeated if there are multiple certificates to use for the server." << std::endl
              << "    --trusted-ca=PATH  Path to a PEM file holding trusted CA certificate(s)." << std::endl
              << "                       May be repeated." << std::endl
              << "                       Example path: \"/etc/ssl/certs/ca-certificates.crt\"" << std::endl
#endif
              << std::endl;
}

bool
Transport::TheConfig::parseCommandOpts(int argc, char *argv[], int c, int &optIndex)
{
    bool tls = false;
    const char *shortOpStr = "h:l:p:T:?";

    // options for controlling squidclient transport connection
    static struct option longOptions[] = {
        {"anonymous-tls",no_argument, 0, '\1'},
        {"https",        no_argument, 0, '\3'},
        {"trusted-ca",   required_argument, 0, 'A'},
        {"cert",         required_argument, 0, 'C'},
        {"host",         required_argument, 0, 'h'},
        {"local",        required_argument, 0, 'l'},
        {"port",         required_argument, 0, 'p'},
        {"params",       required_argument, 0, 'P'},
        {0, 0, 0, 0}
    };

    int saved_opterr = opterr;
    opterr = 0; // suppress errors from getopt
    do {
        switch (c) {
        case '\1':
            tls = true;
            tlsAnonymous = true;
            params = "PERFORMANCE:+ANON-ECDH:+ANON-DH";
            break;

        case '\3':
            tls = true;
            break;

        case 'A':
            tls = true;
            caFiles.push_back(std::string(optarg));
            break;

        case 'C':
            tls = true;
            certFiles.push_back(std::string(optarg));
            break;

        case 'h':
            hostname = optarg;
            break;

        case 'l':
            localHost = optarg;
            break;

        case 'p':           /* port number */
            sscanf(optarg, "%hd", &port);
            if (port < 1)
                port = CACHE_HTTP_PORT;     /* default */
            break;

        case 'P':
            tls = true;
            params = optarg;
            break;

        case 'T':
            ioTimeout = atoi(optarg);
            break;

        default:
            if (tls)
                Transport::InitTls();

            // rewind and let the caller handle unknown options
            --optind;
            opterr = saved_opterr;
            return true;
        }
    } while ((c = getopt_long(argc, argv, shortOpStr, longOptions, &optIndex)) != -1);

    if (tls)
        Transport::InitTls();

    opterr = saved_opterr;
    return false;
}

/// Set up the source socket address from which to send.
static int
client_comm_bind(int sock, const Ip::Address &addr)
{
    static struct addrinfo *AI = NULL;
    addr.getAddrInfo(AI);
    int res = bind(sock, AI->ai_addr, AI->ai_addrlen);
    Ip::Address::FreeAddr(AI);
    return res;
}

static void
resolveDestination(Ip::Address &iaddr)
{
    struct addrinfo *AI = NULL;

    debugVerbose(2, "Transport detected: IPv4" <<
                 ((Ip::EnableIpv6 & IPV6_SPECIAL_V4MAPPING) ? "-mapped " : "") <<
                 (Ip::EnableIpv6 == IPV6_OFF ? "-only" : " and IPv6") <<
                 ((Ip::EnableIpv6 & IPV6_SPECIAL_SPLITSTACK) ? " split-stack" : ""));

    if (Transport::Config.localHost) {
        debugVerbose(2, "Resolving " << Transport::Config.localHost << " ...");

        if ( !iaddr.GetHostByName(Transport::Config.localHost) ) {
            std::cerr << "ERROR: Cannot resolve " << Transport::Config.localHost << ": Host unknown." << std::endl;
            exit(1);
        }
    } else {
        debugVerbose(2, "Resolving " << Transport::Config.hostname << " ...");
        /* Process the remote host name to locate the Protocol required
           in case we are being asked to link to another version of squid */
        if ( !iaddr.GetHostByName(Transport::Config.hostname) ) {
            std::cerr << "ERROR: Cannot resolve " << Transport::Config.hostname << ": Host unknown." << std::endl;
            exit(1);
        }
    }

    iaddr.getAddrInfo(AI);
    if ((conn = socket(AI->ai_family, AI->ai_socktype, 0)) < 0) {
        std::cerr << "ERROR: could not open socket to " << iaddr << std::endl;
        Ip::Address::FreeAddr(AI);
        exit(1);
    }
    Ip::Address::FreeAddr(AI);

    if (Transport::Config.localHost) {
        if (client_comm_bind(conn, iaddr) < 0) {
            std::cerr << "ERROR: could not bind socket to " << iaddr << std::endl;
            exit(1);
        }

        iaddr.setEmpty();

        debugVerbose(2, "Resolving... " << Transport::Config.hostname);

        if ( !iaddr.GetHostByName(Transport::Config.hostname) ) {
            std::cerr << "ERROR: Cannot resolve " << Transport::Config.hostname << ": Host unknown." << std::endl;
            exit(1);
        }
    }

    iaddr.port(Transport::Config.port);
}

/// Set up the destination socket address for message to send to.
static int
client_comm_connect(int sock, const Ip::Address &addr)
{
    static struct addrinfo *AI = NULL;
    addr.getAddrInfo(AI);
    int res = connect(sock, AI->ai_addr, AI->ai_addrlen);
    Ip::Address::FreeAddr(AI);
    Ping::TimerStart();
    return res;
}

bool
Transport::Connect()
{
    Ip::Address iaddr;
    resolveDestination(iaddr);

    debugVerbose(2, "Connecting... " << Config.hostname << " (" << iaddr << ")");

    if (client_comm_connect(conn, iaddr) < 0) {
        char hostnameBuf[MAX_IPSTRLEN];
        iaddr.toUrl(hostnameBuf, MAX_IPSTRLEN);
        std::cerr << "ERROR: Cannot connect to " << hostnameBuf
                  << (!errno ?": Host unknown." : "") << std::endl;
        exit(1);
    }
    debugVerbose(2, "Connected to: " << Config.hostname << " (" << iaddr << ")");

    // do any TLS setup that might be needed
    if (!Transport::MaybeStartTls(Config.hostname))
        return false;

    return true;
}

ssize_t
Transport::Write(const void *buf, size_t len)
{
    if (conn < 0)
        return -1;

    if (Config.tlsEnabled) {
#if USE_GNUTLS
        gnutls_record_send(Config.session, buf, len);
        return len;
#else
        return 0;
#endif
    } else {

#if _SQUID_WINDOWS_
        return send(conn, buf, len, 0);
#else
        alarm(Config.ioTimeout);
        return write(conn, buf, len);
#endif
    }
}

ssize_t
Transport::Read(void *buf, size_t len)
{
    if (conn < 0)
        return -1;

    if (Config.tlsEnabled) {
#if USE_GNUTLS
        return gnutls_record_recv(Config.session, buf, len);
#else
        return 0;
#endif
    } else {

#if _SQUID_WINDOWS_
        return recv(conn, buf, len, 0);
#else
        alarm(Config.ioTimeout);
        return read(conn, buf, len);
#endif
    }
}

void
Transport::CloseConnection()
{
    (void) close(conn);
    conn = -1;
}

#if USE_GNUTLS
/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int
verifyByCA(gnutls_session_t session)
{
    /* read hostname */
    const char *hostname = static_cast<const char*>(gnutls_session_get_ptr(session));

    /* This verification function uses the trusted CAs in the credentials
     * structure. So you must have installed one or more CA certificates.
     */
    unsigned int status;
    if (gnutls_certificate_verify_peers3(session, hostname, &status) < 0) {
        std::cerr << "VERIFY peers failure";
        return GNUTLS_E_CERTIFICATE_ERROR;
    }

    gnutls_certificate_type_t type = gnutls_certificate_type_get(session);
    gnutls_datum_t out;
    if (gnutls_certificate_verification_status_print(status, type, &out, 0) < 0) {
        std::cerr << "VERIFY status failure";
        return GNUTLS_E_CERTIFICATE_ERROR;
    }

    std::cerr << "VERIFY DATUM: " << out.data << std::endl;
    gnutls_free(out.data);

    if (status != 0)        /* Certificate is not trusted */
        return GNUTLS_E_CERTIFICATE_ERROR;

    /* notify gnutls to continue handshake normally */
    return GNUTLS_E_SUCCESS;
}

static int
verifyTlsCertificate(gnutls_session_t session)
{
    // XXX: 1) try to verify using DANE -> Secure Authenticated Connection

    // 2) try to verify using CA
    if (verifyByCA(session) == GNUTLS_E_SUCCESS) {
        std::cerr << "SUCCESS: CA verified Encrypted Connection" << std::endl;
        return GNUTLS_E_SUCCESS;
    }

    // 3) fails both is insecure, but show the results anyway.
    std::cerr << "WARNING: Insecure Connection" << std::endl;
    return GNUTLS_E_SUCCESS;
}
#endif

#if USE_GNUTLS
static void
gnutlsDebugHandler(int level, const char *msg)
{
    debugVerbose(level, "GnuTLS: " << msg);
}
#endif

void
Transport::InitTls()
{
#if USE_GNUTLS
    debugVerbose(3, "Initializing TLS library...");
    // NP: gnutls init is re-entrant and lock-counted with deinit but not thread safe.
    if (gnutls_global_init() != GNUTLS_E_SUCCESS) {
        int xerrno = errno;
        std::cerr << "FATAL ERROR: TLS Initialize failed: " << xstrerr(xerrno) << std::endl;
        exit(1);
    }

    Config.tlsEnabled = true;

#if USE_GNUTLS
    gnutls_global_set_log_function(&gnutlsDebugHandler);
    gnutls_global_set_log_level(scParams.verbosityLevel);
#endif

    // Initialize for anonymous TLS
    gnutls_anon_allocate_client_credentials(&Config.anonCredentials);

    // Initialize for X.509 certificate exchange
    gnutls_certificate_allocate_credentials(&Config.certCredentials);
    for (std::list<std::string>::const_iterator i = Config.caFiles.begin(); i != Config.caFiles.end(); ++i) {
        int x = gnutls_certificate_set_x509_trust_file(Config.certCredentials, (*i).c_str(), GNUTLS_X509_FMT_PEM);
        if (x < 0) {
            debugVerbose(3, "WARNING: Failed to load Certificate Authorities from " << *i);
        } else {
            debugVerbose(3, "Loaded " << x << " Certificate Authorities from " << *i);
        }
    }
    gnutls_certificate_set_verify_function(Config.certCredentials, verifyTlsCertificate);

    for (std::list<std::string>::const_iterator i = Config.certFiles.begin(); i != Config.certFiles.end(); ++i) {
        if (gnutls_certificate_set_x509_key_file(Transport::Config.certCredentials, (*i).c_str(), (*i).c_str(), GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
            debugVerbose(3, "WARNING: Failed to load Certificate from " << *i);
        } else {
            debugVerbose(3, "Loaded Certificate from " << *i);
        }
    }

#else
    std::cerr << "ERROR: TLS support not available." << std::endl;
#endif
}

#if USE_GNUTLS

// perform the actual handshake exchange with remote server
static bool
doTlsHandshake(const char *type)
{
    // setup the connection for TLS
    gnutls_transport_set_int(Transport::Config.session, conn);
    gnutls_handshake_set_timeout(Transport::Config.session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    debugVerbose(2, type << " TLS handshake ... ");

    int ret = 0;
    do {
        ret = gnutls_handshake(Transport::Config.session);
    } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

    if (ret < 0) {
        std::cerr << "ERROR: " << type << " TLS Handshake failed (" << ret << ") "
                  << gnutls_alert_get_name(gnutls_alert_get(Transport::Config.session))
                  << std::endl;
        gnutls_perror(ret);
        gnutls_deinit(Transport::Config.session);
        return false;
    }

    char *desc = gnutls_session_get_desc(Transport::Config.session);
    debugVerbose(3, "TLS Session info: " << std::endl << desc << std::endl);
    gnutls_free(desc);
    return true;
}

static bool
loadTlsParameters()
{
    const char *err = NULL;
    int x;
    if ((x = gnutls_priority_set_direct(Transport::Config.session, Transport::Config.params, &err)) != GNUTLS_E_SUCCESS) {
        if (x == GNUTLS_E_INVALID_REQUEST)
            std::cerr << "ERROR: Syntax error at: " << err << std::endl;
        gnutls_perror(x);
        return false;
    }
    return true;
}

// attempt an anonymous TLS handshake
// this encrypts the connection but does not secure it
// so many public servers do not support this handshake type.
static bool
tryTlsAnonymous()
{
    if (!loadTlsParameters())
        return false;

    // put the anonymous credentials to the current session
    int x;
    if ((x = gnutls_credentials_set(Transport::Config.session, GNUTLS_CRD_ANON, Transport::Config.anonCredentials)) != GNUTLS_E_SUCCESS) {
        std::cerr << "ERROR: Anonymous TLS credentials setup failed (" << x << ") " << std::endl;
        gnutls_perror(x);
        return false;
    }

    return doTlsHandshake("Anonymous");
}

// attempt a X.509 certificate exchange
// this both encrypts and authenticates the connection
static bool
tryTlsCertificate(const char *hostname)
{
    gnutls_session_set_ptr(Transport::Config.session, (void *) hostname);
    gnutls_server_name_set(Transport::Config.session, GNUTLS_NAME_DNS, hostname, strlen(hostname));

    if (!loadTlsParameters())
        return false;

    // put the X.509 credentials to the current session
    gnutls_credentials_set(Transport::Config.session, GNUTLS_CRD_CERTIFICATE, Transport::Config.certCredentials);

    // setup the connection for TLS
    gnutls_transport_set_int(Transport::Config.session, conn);
    gnutls_handshake_set_timeout(Transport::Config.session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    return doTlsHandshake("X.509");
}
#endif

bool
Transport::MaybeStartTls(const char *hostname)
{
#if USE_GNUTLS
    if (Config.tlsEnabled) {

        // Initialize TLS session
        gnutls_init(&Transport::Config.session, GNUTLS_CLIENT);

        if (Transport::Config.tlsAnonymous && !tryTlsAnonymous()) {
            gnutls_deinit(Config.session);
            return false;
        }

        if (!tryTlsCertificate(hostname)) {
            gnutls_deinit(Config.session);
            return false;
        }
    }
#endif
    return true;
}

void
Transport::ShutdownTls()
{
#if USE_GNUTLS
    if (!Config.tlsEnabled)
        return;

    debugVerbose(3, "Shutting down TLS library...");

    // release any existing session and credentials
    gnutls_deinit(Config.session);
    gnutls_anon_free_client_credentials(Config.anonCredentials);
    gnutls_certificate_free_credentials(Config.certCredentials);

    // NP: gnutls init is re-entrant and lock-counted with deinit but not thread safe.
    gnutls_global_deinit();
    Config.tlsEnabled = false;
#endif
}


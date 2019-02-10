/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TOOLS_SQUIDCLIENT_TRANSPORT_H
#define SQUID_TOOLS_SQUIDCLIENT_TRANSPORT_H

#include "tools/squidclient/Parameters.h"

#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#include <list>
#include <string>

namespace Transport
{

/// parameters controlling outgoing connection
class TheConfig
{
public:
    TheConfig() :
        ioTimeout(120),
        localHost(NULL),
        port(CACHE_HTTP_PORT),
        tlsEnabled(false),
        tlsAnonymous(false) {
        params = "NORMAL";
        hostname = "localhost";
    }

// TODO: implicit transport options depending on the protocol-specific options
//     ie --https enables TLS connection settings

    /// display Transport Options command line help to stderr
    void usage();

    /**
     * parse transport related command line options
     * \return true if there are other options still to parse
     */
    bool parseCommandOpts(int argc, char *argv[], int c, int &optIndex);

    /// I/O operation timeout
    int ioTimeout;

    /// the local hostname to bind as for outgoing IP
    const char *localHost;

    /// the destination server host name to contact
    const char *hostname;

    /// port on the server to contact
    uint16_t port;

    /// whether to enable TLS on the server connnection
    bool tlsEnabled;

    /// whether to do anonymous TLS (non-authenticated)
    bool tlsAnonymous;

    /// The TLS parameters (list of ciphers, versions, flags)
    /// Default is "NORMAL" unless tlsAnonymous is used,
    /// in which case it becomes "PERFORMANCE:+ANON-ECDH:+ANON-DH".
    /// see http://gnutls.org/manual/html_node/Priority-Strings.html
    const char *params;

    // client certificate PEM file(s)
    std::list<std::string> certFiles;

    // client trusted x509 certificate authorities file
    std::list<std::string> caFiles;

#if USE_GNUTLS
    /// anonymous client credentials
    gnutls_anon_client_credentials_t anonCredentials;

    // client x509 certificate credentials
    gnutls_certificate_credentials_t certCredentials;

    /// TLS session state
    gnutls_session_t session;
#endif
};

extern TheConfig Config;

/// locate and connect to the configured server
bool Connect();

/// close the current connection
void CloseConnection();

/// Initialize TLS library environment when necessary.
void InitTls();

/// perform TLS handshake on the currently open connection if
/// TLS library has been initialized.
/// return false on errors, true otherwise even if TLS not performed.
bool MaybeStartTls(const char *hostname);

/// De-initialize TLS library environment when necessary.
void ShutdownTls();

/// write len bytes to the currently open connection.
/// \return the number of bytes written, or -1 on errors
ssize_t Write(const void *buf, size_t len);

/// read up to len bytes from the currently open connection.
/// \return the number of bytes read, or -1 on errors
ssize_t Read(void *buf, size_t len);

} // namespace Transport

#endif /* SQUID_TOOLS_SQUIDCLIENT_TRANSPORT_H */


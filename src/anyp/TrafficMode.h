/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_TRAFFIC_MODE_H
#define SQUID_ANYP_TRAFFIC_MODE_H

namespace AnyP
{

/// POD representation of TrafficMode flags
class TrafficModeFlags
{
public:
    /// a parsed port type (http_port, https_port or ftp_port)
    typedef enum { httpPort, httpsPort, ftpPort } PortKind;

    explicit TrafficModeFlags(const PortKind aPortKind): portKind(aPortKind) {}

    /** marks HTTP accelerator (reverse/surrogate proxy) traffic
     *
     * Indicating the following are required:
     *  - URL translation from relative to absolute form
     *  - restriction to origin peer relay recommended
     */
    bool accelSurrogate = false;

    /** marks ports receiving PROXY protocol traffic
     *
     * Indicating the following are required:
     *  - PROXY protocol magic header
     *  - src/dst IP retrieved from magic PROXY header
     *  - indirect client IP trust verification is mandatory
     *  - TLS is not supported
     */
    bool proxySurrogate = false;

    /** marks NAT intercepted traffic
     *
     * Indicating the following are required:
     *  - NAT lookups
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - Squid authentication prohibited
     */
    bool natIntercept = false;

    /** marks TPROXY intercepted traffic
     *
     * Indicating the following are required:
     *  - src/dst IP inversion must be performed
     *  - client IP should be spoofed if possible
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - Squid authentication prohibited
     */
    bool tproxyIntercept = false;

    /** marks intercept and decryption of CONNECT (tunnel) SSL traffic
     *
     * Indicating the following are required:
     *  - decryption of CONNECT request
     *  - URL translation from relative to absolute form
     *  - Squid authentication prohibited on unwrapped requests (only on the CONNECT tunnel)
     *  - encrypted outbound server connections
     *  - peer relay prohibited. TODO: re-encrypt and re-wrap with CONNECT
     */
    bool tunnelSslBumping = false;

    PortKind portKind; ///< the parsed port type value
};

/**
 * Set of 'mode' flags defining types of traffic which can be received.
 *
 * Use to determine the processing steps which need to be applied
 * to this traffic under any special circumstances which may apply.
 */
class TrafficMode
{
public:
    explicit TrafficMode(const TrafficModeFlags::PortKind aPortKind) : flags_(aPortKind) {}
    /// This port handles traffic that has been intercepted prior to being delivered
    /// to the TCP client of the accepted connection and/or to us. This port mode
    /// alone does not imply that the client of the accepted TCP connection was not
    /// connecting directly to this port (since commit 151ba0d).
    bool interceptedSomewhere() const { return flags_.natIntercept || flags_.tproxyIntercept || proxySurrogateHttpsSslBump(); }

    /// The client of the accepted TCP connection was connecting directly to this proxy port.
    bool forwarded() const { return !interceptedSomewhere() && !flags_.accelSurrogate; }

    /// whether the PROXY protocol header is required
    bool proxySurrogate() const { return flags_.proxySurrogate; }

    /// The client of the accepted connection was not connecting to this port,
    /// but Squid used NAT interception to accept the client connection.
    /// The accepted traffic may have been intercepted earlier as well!
    bool natInterceptLocally() const {
        return flags_.natIntercept && !proxySurrogate();
    }

    /// The client of the accepted connection was not connecting to this port,
    /// but Squid used TPROXY interception to accept the connection.
    /// The accepted traffic may have been intercepted earlier as well!
    bool tproxyInterceptLocally() const {
        return flags_.tproxyIntercept && !proxySurrogate();
    }

    /// whether the reverse proxy is configured
    bool accelSurrogate() const { return flags_.accelSurrogate; }

    bool tunnelSslBumping() const { return flags_.tunnelSslBumping; }

    TrafficModeFlags &rawConfig() { return flags_; }

    std::ostream &print(std::ostream &) const;

private:
    /// \returns true for HTTPS ports with SSL bump receiving PROXY protocol traffic
    bool proxySurrogateHttpsSslBump() const {
        return flags_.proxySurrogate && flags_.tunnelSslBumping && flags_.portKind == TrafficModeFlags::httpsPort;
    }

    TrafficModeFlags flags_;
};

inline std::ostream &
TrafficMode::print(std::ostream &os) const
{
    if (flags_.natIntercept)
        os << " NAT intercepted";
    else if (flags_.tproxyIntercept)
        os << " TPROXY intercepted";
    else if (flags_.accelSurrogate)
        os << " reverse-proxy";
    else
        os << " forward-proxy";

    if (flags_.tunnelSslBumping)
        os << " SSL bumped";
    if (proxySurrogate())
        os << " (with PROXY protocol header)";

    return os;
}

inline std::ostream &
operator <<(std::ostream &os, const TrafficMode &flags)
{
    return flags.print(os);
}

} // namespace AnyP

#endif


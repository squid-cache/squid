/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 73    HTTP Request */

#ifndef SQUID_REQUESTFLAGS_H_
#define SQUID_REQUESTFLAGS_H_

/** request-related flags
 *
 * Contains both flags marking a request's current state,
 * and flags requesting some processing to be done at a later stage.
 * TODO: better distinguish the two cases.
 */
class RequestFlags
{
public:
    /** true if the response to this request may not be READ from cache */
    bool noCache = false;
    /** request is if-modified-since */
    bool ims = false;
    /** request is authenticated */
    bool auth = false;
    /** do not use keytabs for peer Kerberos authentication */
    bool auth_no_keytab = false;
    /** he response to the request may be stored in the cache */
    bool cachable = false;
    /** the request can be forwarded through the hierarchy */
    bool hierarchical = false;
    /** a loop was detected on this request */
    bool loopDetected = false;
    /** the connection can be kept alive */
    bool proxyKeepalive = false;
    /** content has expired, need to refresh it */
    bool refresh = false;
    /** request was redirected by redirectors */
    bool redirected = false;
    /** the requested object needs to be validated. See client_side_reply.cc
     * for further information.
     */
    bool needValidation = false;
    /** whether we should fail if validation fails */
    bool failOnValidationError = false;
    /** reply is stale if it is a hit */
    bool staleIfHit = false;
    /** request to override no-cache directives
     *
     * always use noCacheHack() for reading.
     * \note only meaningful if USE_HTTP_VIOLATIONS is defined at build time
     */
    bool nocacheHack = false;
    /** this request is accelerated (reverse-proxy) */
    bool accelerated = false;
    /** if set, ignore Cache-Control headers */
    bool ignoreCc = false;
    /** set for intercepted requests */
    bool intercepted = false;
    /** set if the Host: header passed verification */
    bool hostVerified = false;
    /// Set for requests handled by a "tproxy" port.
    bool interceptTproxy = false;
    /// The client IP address should be spoofed when connecting to the web server.
    /// This applies to TPROXY traffic that has not had spoofing disabled through
    /// the spoof_client_ip squid.conf ACL.
    bool spoofClientIp = false;
    /** set if the request is internal (\see ClientHttpRequest::flags.internal)*/
    bool internal = false;
    /** if set, request to try very hard to keep the connection alive */
    bool mustKeepalive = false;
    /** set if the rquest wants connection oriented auth */
    bool connectionAuth = false;
    /** set if connection oriented auth can not be supported */
    bool connectionAuthDisabled = false;
    // XXX This is set in clientCheckPinning but never tested
    /** Request wants connection oriented auth */
    bool connectionProxyAuth = false;
    /** set if the request was sent on a pinned connection */
    bool pinned = false;
    /** Authentication was already sent upstream (e.g. due tcp-level auth) */
    bool authSent = false;
    /** Deny direct forwarding unless overriden by always_direct
     * Used in accelerator mode */
    bool noDirect = false;
    /** Reply with chunked transfer encoding */
    bool chunkedReply = false;
    /** set if stream error has occurred */
    bool streamError = false;
    /** internal ssl-bump request to get server cert */
    bool sslPeek = false;
    /** set if X-Forwarded-For checking is complete
     *
     * do not read directly; use doneFollowXff for reading
     */
    bool done_follow_x_forwarded_for = false;
    /** set for ssl-bumped requests */
    bool sslBumped = false;
    /// carries a representation of an FTP command [received on ftp_port]
    bool ftpNative = false;
    bool destinationIpLookedUp = false;
    /** request to reset the TCP stream */
    bool resetTcp = false;
    /** set if the request is ranged */
    bool isRanged = false;

    /// whether to forward via TunnelStateData (instead of FwdState)
    bool forceTunnel = false;

    /** clone the flags, resetting to default those which are not safe in
     *  a related (e.g. ICAP-adapted) request.
     */
    RequestFlags cloneAdaptationImmune() const;

    // if FOLLOW_X_FORWARDED_FOR is not set, we always return "done".
    bool doneFollowXff() const {
        return done_follow_x_forwarded_for || !FOLLOW_X_FORWARDED_FOR;
    }

    // if USE_HTTP_VIOLATIONS is not set, never allow this
    bool noCacheHack() const {
        return USE_HTTP_VIOLATIONS && nocacheHack;
    }
};

#endif /* SQUID_REQUESTFLAGS_H_ */


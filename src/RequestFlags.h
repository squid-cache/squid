/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
 * The bit-field contains both flags marking a request's current state,
 * and flags requesting some processing to be done at a later stage.
 * TODO: better distinguish the two cases.
 */
class RequestFlags
{
public:
    RequestFlags() {
        memset(this,0,sizeof(RequestFlags));
    }

    /** true if the response to this request may not be READ from cache */
    bool noCache :1;
    /** request is if-modified-since */
    bool ims :1;
    /** request is authenticated */
    bool auth :1;
    /** he response to the request may be stored in the cache */
    bool cachable :1;
    /** the request can be forwarded through the hierarchy */
    bool hierarchical :1;
    /** a loop was detected on this request */
    bool loopDetected :1;
    /** the connection can be kept alive */
    bool proxyKeepalive :1;
    /* this should be killed, also in httpstateflags */
    bool proxying :1;
    /** content has expired, need to refresh it */
    bool refresh :1;
    /** request was redirected by redirectors */
    bool redirected :1;
    /** the requested object needs to be validated. See client_side_reply.cc
     * for further information.
     */
    bool needValidation :1;
    /** whether we should fail if validation fails */
    bool failOnValidationError :1;
    /** reply is stale if it is a hit */
    bool staleIfHit :1;
    /** request to override no-cache directives
     *
     * always use noCacheHack() for reading.
     * \note only meaningful if USE_HTTP_VIOLATIONS is defined at build time
     */
    bool nocacheHack :1;
    /** this request is accelerated (reverse-proxy) */
    bool accelerated :1;
    /** if set, ignore Cache-Control headers */
    bool ignoreCc :1;
    /** set for intercepted requests */
    bool intercepted :1;
    /** set if the Host: header passed verification */
    bool hostVerified :1;
    /// Set for requests handled by a "tproxy" port.
    bool interceptTproxy :1;
    /// The client IP address should be spoofed when connecting to the web server.
    /// This applies to TPROXY traffic that has not had spoofing disabled through
    /// the spoof_client_ip squid.conf ACL.
    bool spoofClientIp :1;
    /** set if the request is internal (\see ClientHttpRequest::flags.internal)*/
    bool internal :1;
    /** set for internally-generated requests */
    //XXX this is set in in clientBeginRequest, but never tested.
    bool internalClient :1;
    /** if set, request to try very hard to keep the connection alive */
    bool mustKeepalive :1;
    /** set if the rquest wants connection oriented auth */
    bool connectionAuth :1;
    /** set if connection oriented auth can not be supported */
    bool connectionAuthDisabled :1;
    /** Request wants connection oriented auth */
    // XXX This is set in clientCheckPinning but never tested
    bool connectionProxyAuth :1;
    /** set if the request was sent on a pinned connection */
    bool pinned :1;
    /** Authentication was already sent upstream (e.g. due tcp-level auth) */
    bool authSent :1;
    /** Deny direct forwarding unless overriden by always_direct
     * Used in accelerator mode */
    bool noDirect :1;
    /** Reply with chunked transfer encoding */
    bool chunkedReply :1;
    /** set if stream error has occured */
    bool streamError :1;
    /** internal ssl-bump request to get server cert */
    bool sslPeek :1;
    /** set if X-Forwarded-For checking is complete
     *
     * do not read directly; use doneFollowXff for reading
     */
    bool done_follow_x_forwarded_for :1;
    /** set for ssl-bumped requests */
    bool sslBumped :1;
    /// carries a representation of an FTP command [received on ftp_port]
    bool ftpNative :1;
    bool destinationIpLookedUp:1;
    /** request to reset the TCP stream */
    bool resetTcp:1;
    /** set if the request is ranged */
    bool isRanged :1;

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


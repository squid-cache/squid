#ifndef SQUID_REQUESTFLAGS_H_
#define SQUID_REQUESTFLAGS_H_
/*
 * DEBUG: section 73    HTTP Request
 * AUTHOR: Duane Wessels
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

class RequestFlags {
public:
    RequestFlags():
        nocache(0), ims(0), auth(0), cachable(0),
        hierarchical(0), loopdetect(false), proxy_keepalive(false), proxying_(false),
        refresh_(false), redirected(false), need_validation(false),
        fail_on_validation_err(false), stale_if_hit(false), nocache_hack(false), accelerated_(false),
        ignore_cc(false), intercepted_(false), hostVerified_(false), spoof_client_ip(false),
        internal(false), internalclient(false), must_keepalive(false), connection_auth_wanted(false), connection_auth_disabled(false), connection_proxy_auth(false), pinned_(false),
        canRePin_(false), authSent_(false), noDirect_(false), chunkedReply_(false),
        streamError_(false), sslPeek_(false),
        doneFollowXForwardedFor(!FOLLOW_X_FORWARDED_FOR),
        sslBumped_(false), destinationIPLookedUp_(false), resetTCP_(false),
        isRanged_(false)
    {}

    unsigned int nocache :1; ///< whether the response to this request may be READ from cache
    unsigned int ims :1;
    unsigned int auth :1;
    unsigned int cachable :1; ///< whether the response to thie request may be stored in the cache
    unsigned int hierarchical :1;

    // When adding new flags, please update cloneAdaptationImmune() as needed.
    bool resetTCP() const;
    void setResetTCP();
    void clearResetTCP();
    void destinationIPLookupCompleted();
    bool destinationIPLookedUp() const;
    // returns a partial copy of the flags that includes only those flags
    // that are safe for a related (e.g., ICAP-adapted) request to inherit
    RequestFlags cloneAdaptationImmune() const;

    bool isRanged() const;
    void setRanged();
    void clearRanged();

    bool sslBumped() const { return sslBumped_; }
    void setSslBumped(bool newValue=true) { sslBumped_=newValue; }
    void clearSslBumpeD() { sslBumped_=false; }

    bool doneFollowXFF() const { return doneFollowXForwardedFor; }
    void setDoneFollowXFF() {
        doneFollowXForwardedFor = true;
    }
    void clearDoneFollowXFF() {
        /* do not allow clearing if FOLLOW_X_FORWARDED_FOR is unset */
        doneFollowXForwardedFor = false || !FOLLOW_X_FORWARDED_FOR;
    }

    bool sslPeek() const { return sslPeek_; }
    void setSslPeek() { sslPeek_=true; }
    void clearSslPeek() { sslPeek_=false; }

    bool hadStreamError() const { return streamError_; }
    void setStreamError() { streamError_ = true; }
    void clearStreamError() { streamError_ = false; }

    bool isReplyChunked() const { return chunkedReply_; }
    void markReplyChunked() { chunkedReply_ = true; }

    void setNoDirect() { noDirect_=true; }
    bool noDirect() const{ return noDirect_; }

    bool authSent() const { return authSent_; }
    void markAuthSent() { authSent_=true;}

    bool canRePin() const { return canRePin_; }
    void allowRepinning() { canRePin_=true; }

    void markPinned() { pinned_ = true; }
    void clearPinned() { pinned_ = false; }
    bool pinned() const { return pinned_; }

    //XXX: oddly this is set in client_side_request.cc, but never checked.
    bool wantConnectionProxyAuth() const { return connection_proxy_auth; }
    void requestConnectionProxyAuth() { connection_proxy_auth=true; }

    void disableConnectionAuth() { connection_auth_disabled=true; }
    bool connectionAuthDisabled() const { return connection_auth_disabled; }

    void wantConnectionAuth() { connection_auth_wanted=true; }
    bool connectionAuthWanted() const { return connection_auth_wanted; }

    void setMustKeepalive() { must_keepalive = true; }
    bool mustKeepalive() const { return must_keepalive; }

    //XXX: oddly this is set in client_side_request.cc but never checked.
    void setInternalClient() { internalclient=true;}

    void markInternal() { internal=true; }
    bool isInternal() const { return internal; }

    bool spoofClientIp() const { return spoof_client_ip; }
    void setSpoofClientIp() { spoof_client_ip = true; }

    bool hostVerified() const { return hostVerified_; }
    void markHostVerified() { hostVerified_=true; }

    bool intercepted() const { return intercepted_;  }
    void markIntercepted() { intercepted_=true; }

    bool ignoringCacheControl() const { return ignore_cc; }
    void ignoreCacheControl() { ignore_cc=true; }

    bool accelerated() const { return accelerated_; }
    void markAccelerated() { accelerated_ = true; }

    /* nocache_hack is only enabled if USE_HTTP_VIOLATIONS is set at build-time.
     * Compilers will have an easy time optimizing to a NOP otherwise. */
    void hackNocache() { if (USE_HTTP_VIOLATIONS) nocache_hack=true; }
    bool noCacheHackEnabled() const { return USE_HTTP_VIOLATIONS && nocache_hack; }

    void setStaleIfHit() { stale_if_hit=true; }
    void clearStaleIfHit() { stale_if_hit=false; }
    bool staleIfHit() const { return stale_if_hit; }

    void setFailOnValidationError() { fail_on_validation_err=true; }
    bool failOnValidationError() const { return fail_on_validation_err; }

    bool validationNeeded() const { return need_validation; }
    void setNeedValidation()  { need_validation=true; }

    bool isRedirected() const { return redirected; }
    void markRedirected() { redirected=true; }

    bool refresh() const { return refresh_; }
    void setRefresh() { refresh_ = true; }

    bool proxying() const { return proxying_; }
    void setProxying() { proxying_ = true; }
    void clearProxying() { proxying_ = false; }

    bool proxyKeepalive() const { return proxy_keepalive; }
    void setProxyKeepalive() { proxy_keepalive=true;}
    void clearProxyKeepalive() { proxy_keepalive=false; }

    bool loopDetect() const { return loopdetect; }
    void setLoopDetect() { loopdetect = 1; }
private:
    bool loopdetect :1;
    bool proxy_keepalive :1;
    bool proxying_ :1; /* this should be killed, also in httpstateflags */
    bool refresh_ :1;
    bool redirected :1;
    bool need_validation :1;
    bool fail_on_validation_err :1; ///< whether we should fail if validation fails
    bool stale_if_hit :1; ///< reply is stale if it is a hit
    /* for changing/ignoring no-cache requests. Unused unless USE_HTTP_VIOLATIONS */
    bool nocache_hack :1;
    bool accelerated_ :1; ///<request is accelerated
    bool ignore_cc :1; ///< ignore Cache-Control
    bool intercepted_ :1; ///< intercepted request
    bool hostVerified_ :1; ///< whether the Host: header passed verification
    bool spoof_client_ip :1; ///< spoof client ip if possible
    bool internal :1;
    bool internalclient :1;
    bool must_keepalive :1;
    bool connection_auth_wanted :1; /** Request wants connection oriented auth */
    bool connection_auth_disabled :1; ///< Connection oriented auth can't be supported
    bool connection_proxy_auth :1; ///< Request wants connection oriented auth
    bool pinned_ :1; ///< Request sent on a pinned connection
    bool canRePin_ :1; ///< OK to reopen a failed pinned connection
    bool authSent_ :1; ///< Authentication was forwarded
    /** Deny direct forwarding unless overriden by always_direct.
     * Used in accelerator mode */
    bool noDirect_ :1;
    bool chunkedReply_ :1; ///< Reply with chunked transfer encoding
    bool streamError_ :1; ///< Whether stream error has occured
    bool sslPeek_ :1; ///< internal ssl-bump request to get server cert
    /* doneFollowXForwardedFor is set by default to the opposite of
     * compilation option FOLLOW_X_FORWARDED_FOR (so that it returns
     * always "done" if the build option is disabled).
     */
    bool doneFollowXForwardedFor :1;
    bool sslBumped_ :1; /**< ssl-bumped request*/
    bool destinationIPLookedUp_:1;
    bool resetTCP_:1;                ///< request to reset the TCP stream
    bool isRanged_ :1;
};

#endif /* SQUID_REQUESTFLAGS_H_ */

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

class RequestFlags
{
public:
    RequestFlags() {
        memset(this,0,sizeof(RequestFlags));
    }

    bool nocache :1; ///< whether the response to this request may be READ from cache
    bool ims :1;
    bool auth :1;
    bool cachable :1; ///< whether the response to thie request may be stored in the cache
    bool hierarchical :1;
    bool loopdetect :1;
    bool proxy_keepalive :1;
    bool proxying :1; /* this should be killed, also in httpstateflags */
    bool refresh :1;
    bool redirected :1;
    bool need_validation :1;
    bool fail_on_validation_err :1; ///< whether we should fail if validation fails
    bool stale_if_hit :1; ///< reply is stale if it is a hit
#if USE_HTTP_VIOLATIONS
    /* for changing/ignoring no-cache requests */
    /* TODO: remove the conditional definition, move ifdef to setter */
    bool nocache_hack :1;
#endif
    bool accelerated :1;
    bool ignore_cc :1;
    bool intercepted :1; ///< intercepted request
    bool hostVerified :1; ///< whether the Host: header passed verification
    bool spoof_client_ip :1; /**< spoof client ip if possible */
    bool internal :1;
    bool internalclient :1;
    bool must_keepalive :1;
    bool connection_auth :1; /** Request wants connection oriented auth */
    bool connection_auth_disabled :1; /** Connection oriented auth can not be supported */
    bool connection_proxy_auth :1; /** Request wants connection oriented auth */
    bool pinned :1; /* Request sent on a pinned connection */
    bool canRePin :1; ///< OK to reopen a failed pinned connection
    bool auth_sent :1; /* Authentication forwarded */
    bool no_direct :1; /* Deny direct forwarding unless overriden by always_direct. Used in accelerator mode */
    bool chunked_reply :1; /**< Reply with chunked transfer encoding */
    bool stream_error :1; /**< Whether stream error has occured */
    bool sslPeek :1; ///< internal ssl-bump request to get server cert
    /* done_follow_x_forwarded_for set by default to the opposite of
     * compilation option FOLLOW_X_FORWARDED_FOR (so that it returns
     * always "done" if the build option is disabled.
     */
    bool done_follow_x_forwarded_for :1;
    bool sslBumped_ :1; /**< ssl-bumped request*/
    bool destinationIPLookedUp_:1;
    bool resetTCP_:1;                ///< request to reset the TCP stream
    bool isRanged_ :1;

    // When adding new flags, please update cloneAdaptationImmune() as needed.
    // returns a partial copy of the flags that includes only those flags
    // that are safe for a related (e.g., ICAP-adapted) request to inherit
    RequestFlags cloneAdaptationImmune() const;

    // if FOLLOW_X_FORWARDED_FOR is not set, we always return "done".
    bool doneFollowXff() const {
        return done_follow_x_forwarded_for || !FOLLOW_X_FORWARDED_FOR;
    }
};

#endif /* SQUID_REQUESTFLAGS_H_ */

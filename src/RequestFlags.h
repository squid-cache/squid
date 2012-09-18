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
    RequestFlags():
        nocache(0), ims(0), auth(0), cachable(0),
        hierarchical(0), loopdetect(0), proxy_keepalive(0), proxying(0),
        refresh(0), redirected(0), need_validation(0),
        fail_on_validation_err(0), stale_if_hit(0), accelerated(0),
        ignore_cc(0), intercepted(0), hostVerified(0), spoof_client_ip(0),
        internal(0), internalclient(0), must_keepalive(0), pinned(0),
        canRePin(0), chunked_reply(0), stream_error(0), sslPeek(0),
        done_follow_x_forwarded_for(!FOLLOW_X_FORWARDED_FOR),
        sslBumped_(false), destinationIPLookedUp_(false), resetTCP_(false),
        isRanged_(false) {
#if USE_HTTP_VIOLATIONS
        nocache_hack = 0;
#endif
    }

    unsigned int nocache :1; ///< whether the response to this request may be READ from cache
    unsigned int ims :1;
    unsigned int auth :1;
    unsigned int cachable :1; ///< whether the response to thie request may be stored in the cache
    unsigned int hierarchical :1;
    unsigned int loopdetect :1;
    unsigned int proxy_keepalive :1;
    unsigned int proxying :1; /* this should be killed, also in httpstateflags */
    unsigned int refresh :1;
    unsigned int redirected :1;
    unsigned int need_validation :1;
    unsigned int fail_on_validation_err :1; ///< whether we should fail if validation fails
    unsigned int stale_if_hit :1; ///< reply is stale if it is a hit
#if USE_HTTP_VIOLATIONS
    /* for changing/ignoring no-cache requests */
    /* TODO: remove the conditional definition, move ifdef to setter */
    unsigned int nocache_hack :1;
#endif
    unsigned int accelerated :1;
    unsigned int ignore_cc :1;
    unsigned int intercepted :1; ///< intercepted request
    unsigned int hostVerified :1; ///< whether the Host: header passed verification
    unsigned int spoof_client_ip :1; /**< spoof client ip if possible */
    unsigned int internal :1;
    unsigned int internalclient :1;
    unsigned int must_keepalive :1;
    unsigned int connection_auth :1; /** Request wants connection oriented auth */
    unsigned int connection_auth_disabled :1; /** Connection oriented auth can not be supported */
    unsigned int connection_proxy_auth :1; /** Request wants connection oriented auth */
    unsigned int pinned :1; /* Request sent on a pinned connection */
    unsigned int canRePin :1; ///< OK to reopen a failed pinned connection
    unsigned int auth_sent :1; /* Authentication forwarded */
    unsigned int no_direct :1; /* Deny direct forwarding unless overriden by always_direct. Used in accelerator mode */
    unsigned int chunked_reply :1; /**< Reply with chunked transfer encoding */
    unsigned int stream_error :1; /**< Whether stream error has occured */
    unsigned int sslPeek :1; ///< internal ssl-bump request to get server cert

#if FOLLOW_X_FORWARDED_FOR
    /* TODO: move from conditional definition to conditional setting */
#endif /* FOLLOW_X_FORWARDED_FOR */

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

    bool doneFollowXFF() const { return done_follow_x_forwarded_for; }
    void setDoneFollowXFF() {
        done_follow_x_forwarded_for = true;
    }
    void clearDoneFollowXFF() {
        /* do not allow clearing if FOLLOW_X_FORWARDED_FOR is unset */
        done_follow_x_forwarded_for = false || !FOLLOW_X_FORWARDED_FOR;
    }
private:

    /* done_follow_x_forwarded_for set by default to the opposite of
     * compilation option FOLLOW_X_FORWARDED_FOR (so that it returns
     * always "done" if the build option is disabled.
     */
    bool done_follow_x_forwarded_for :1;
    bool sslBumped_ :1; /**< ssl-bumped request*/
    bool destinationIPLookedUp_:1;
    bool resetTCP_:1;                ///< request to reset the TCP stream
    bool isRanged_ :1;
};

#endif /* SQUID_REQUESTFLAGS_H_ */

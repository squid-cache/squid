/*
 * HttpHdrCc.h
 *
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
 */

#ifndef SQUID_HTTPHDRCC_H
#define SQUID_HTTPHDRCC_H

#include "config.h"
#include "MemPool.h"
#include "SquidString.h"

/** Http Cache-Control header representation
 *
 * Store and parse the Cache-Control HTTP header.
 */
class HttpHdrCc
{

public:
	static const int32_t MAX_AGE_UNKNOWN=-1; //max-age is unset
	static const int32_t S_MAXAGE_UNKNOWN=-1; //s-maxage is unset
	static const int32_t MAX_STALE_UNKNOWN=-1; //max-stale is unset
	static const int32_t MAX_STALE_ALWAYS=-2; //max-stale is set to no value
	static const int32_t STALE_IF_ERROR_UNKNOWN=-1; //stale_if_error is unset
	static const int32_t MIN_FRESH_UNKNOWN=-1; //min_fresh is unset

    HttpHdrCc() :
            mask(0), max_age(MAX_AGE_UNKNOWN), s_maxage(S_MAXAGE_UNKNOWN),
            max_stale(MAX_STALE_UNKNOWN), stale_if_error(STALE_IF_ERROR_UNKNOWN),
            min_fresh(MIN_FRESH_UNKNOWN) {}

    /// reset data-members to default state
    void clear();

    /// parse a header-string and fill in appropriate values.
    bool parse(const String & s);

    //manipulation for Cache-Control: public header
    inline bool havePublic() const {return isSet(CC_PUBLIC);}
    inline bool Public() const {return isSet(CC_PUBLIC);}
    inline void Public(bool newval) {setMask(CC_PUBLIC,newval);}
    inline void clearPublic() {setMask(CC_PUBLIC,false);}

    //manipulation for Cache-Control: private header
    inline bool havePrivate() const {return isSet(CC_PRIVATE);}
    inline bool Private() const {return isSet(CC_PRIVATE);}
    inline void Private(bool newval) {setMask(CC_PRIVATE,newval);}
    inline void clearPrivate() {setMask(CC_PRIVATE,false);}

    //manipulation for Cache-Control: no-cache header
    inline bool haveNoCache() const {return isSet(CC_NO_CACHE);}
    inline bool noCache() const {return isSet(CC_NO_CACHE);}
    inline void noCache(bool newval) {setMask(CC_NO_CACHE,newval);}
    inline void clearNoCache() {setMask(CC_NO_CACHE,false);}

    //manipulation for Cache-Control: no-store header
    inline bool haveNoStore() const {return isSet(CC_NO_STORE);}
    inline bool noStore() const {return isSet(CC_NO_STORE);}
    inline void noStore(bool newval) {setMask(CC_NO_STORE,newval);}
    inline void clearNoStore() {setMask(CC_NO_STORE,false);}

    //manipulation for Cache-Control: no-transform header
    inline bool haveNoTransform() const {return isSet(CC_NO_TRANSFORM);}
    inline bool noTransform() const {return isSet(CC_NO_TRANSFORM);}
    inline void noTransform(bool newval) {setMask(CC_NO_TRANSFORM,newval);}
    inline void clearNoTransform() {setMask(CC_NO_TRANSFORM,false);}

    //manipulation for Cache-Control: must-revalidate header
    inline bool haveMustRevalidate() const {return isSet(CC_MUST_REVALIDATE);}
    inline bool mustRevalidate() const {return isSet(CC_MUST_REVALIDATE);}
    inline void mustRevalidate(bool newval) {setMask(CC_MUST_REVALIDATE,newval);}
    inline void clearMustRevalidate() {setMask(CC_MUST_REVALIDATE,false);}

    //manipulation for Cache-Control: proxy-revalidate header
    inline bool haveProxyRevalidate() const {return isSet(CC_PROXY_REVALIDATE);}
    inline bool proxyRevalidate() const {return isSet(CC_PROXY_REVALIDATE);}
    inline void proxyRevalidate(bool newval) {setMask(CC_PROXY_REVALIDATE,newval);}
    inline void clearProxyRevalidate() {setMask(CC_PROXY_REVALIDATE,false);}

    //manipulation for Cache-Control: max-age header
    inline bool haveMaxAge() const {return isSet(CC_MAX_AGE);}
    inline int32_t maxAge() const { return max_age;}
    inline void maxAge(int32_t newval) {if (newval < 0) return; max_age = newval; setMask(CC_MAX_AGE); }
    inline void clearMaxAge() {max_age=MAX_AGE_UNKNOWN; setMask(CC_MAX_AGE,false);}

    //manipulation for Cache-Control: s-maxage header
    inline bool haveSMaxAge() const {return isSet(CC_S_MAXAGE);}
    inline int32_t sMaxAge() const { return s_maxage;}
    inline void sMaxAge(int32_t newval) {if (newval < 0) return; s_maxage = newval; setMask(CC_S_MAXAGE); }
    inline void clearSMaxAge() {s_maxage=MAX_AGE_UNKNOWN; setMask(CC_S_MAXAGE,false);}

    //manipulation for Cache-Control: max-stale header
    inline bool haveMaxStale() const {return isSet(CC_MAX_STALE);}
    inline int32_t maxStale() const { return max_stale;}
    // max-stale has a special value (MAX_STALE_ALWAYS) which correspond to having
    // the directive without a numeric specification, and directs to consider the object
    // as always-expired.
    inline void maxStale(int32_t newval) {
        if (newval < 0 && newval != CC_MAX_STALE) return;
        max_stale = newval; setMask(CC_MAX_STALE); }
    inline void clearMaxStale() {max_stale=MAX_STALE_UNKNOWN; setMask(CC_MAX_STALE,false);}

    //manipulation for Cache-Control:min-fresh header
    inline bool haveMinFresh() const {return isSet(CC_MIN_FRESH);}
    inline int32_t minFresh() const { return min_fresh;}
    inline void minFresh(int32_t newval) {if (newval < 0) return; min_fresh = newval; setMask(CC_MIN_FRESH); }
    inline void clearMinFresh() {min_fresh=MIN_FRESH_UNKNOWN; setMask(CC_MIN_FRESH,false);}

    //manipulation for Cache-Control: only-if-cached header
    inline bool haveOnlyIfCached() const {return isSet(CC_ONLY_IF_CACHED);}
    inline bool onlyIfCached() const {return isSet(CC_ONLY_IF_CACHED);}
    inline void onlyIfCached(bool newval) {setMask(CC_ONLY_IF_CACHED,newval);}
    inline void clearOnlyIfCached() {setMask(CC_ONLY_IF_CACHED,false);}

    //manipulation for Cache-Control: stale-if-error header
    inline bool haveStaleIfError() const {return isSet(CC_STALE_IF_ERROR);}
    inline int32_t staleIfError() const { return stale_if_error;}
    inline void staleIfError(int32_t newval) {if (newval < 0) return; stale_if_error = newval; setMask(CC_STALE_IF_ERROR); }
    inline void clearStaleIfError() {stale_if_error=STALE_IF_ERROR_UNKNOWN; setMask(CC_STALE_IF_ERROR,false);}

    /// check whether the attribute value supplied by id is set
    _SQUID_INLINE_ bool isSet(http_hdr_cc_type id) const;

    void packInto(Packer * p) const;

    MEMPROXY_CLASS(HttpHdrCc);

    /** bit-mask representing what header values are set among those
     * recognized by squid.
     *
     * managed via EBIT_SET/TEST/CLR
     */
private:
    int32_t mask;
    int32_t max_age;
    int32_t s_maxage;
    int32_t max_stale;
    int32_t stale_if_error;
    int32_t min_fresh;
    /// low-level part of the public set method, performs no checks
    _SQUID_INLINE_ void setMask(http_hdr_cc_type id, bool newval=true);

public:
    /**comma-separated representation of the header values which were
     * received but are not recognized.
     */
    String other;
};

MEMPROXY_CLASS_INLINE(HttpHdrCc);

#if _USE_INLINE_
#include "HttpHdrCc.cci"
#endif

#endif /* SQUID_HTTPHDRCC_H */

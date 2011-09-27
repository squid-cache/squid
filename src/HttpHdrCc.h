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

    //manipulation for Cache-Control: XXX header
    //inline bool haveXXX() const {return isSet();}
    //inline bool XXX() const {return isSet();}
    //inline void XXX(bool newval) {setMask(,newval);}
    //inline void clearXXX() {setMask(,false);}

    //manipulation for Cache-Control: public header
    inline bool havePublic() const {return isSet(CC_PUBLIC);}
    inline bool getPublic() const {return isSet(CC_PUBLIC);}
    inline void setPublic(bool newval) {setMask(CC_PUBLIC,newval);}
    inline void clearPublic() {setMask(CC_PUBLIC,false);}

    //manipulation for Cache-Control: private header
    inline bool havePrivate() const {return isSet(CC_PRIVATE);}
    inline bool getPrivate() const {return isSet(CC_PRIVATE);}
    inline void setPrivate(bool newval) {setMask(CC_PRIVATE,newval);}
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
    inline void maxAge(int32_t max_age) {this->max_age = max_age; setMask(CC_MAX_AGE); }
    inline void clearMaxAge() {max_age=MAX_AGE_UNKNOWN; setMask(CC_MAX_AGE,false);}


    /// s-maxage setter. Clear by setting to S_MAXAGE_UNKNOWN
    _SQUID_INLINE_ void sMaxAge(int32_t s_maxage);
    _SQUID_INLINE_ int32_t sMaxAge() const;

    /// max-stale setter. Clear by setting to MAX_STALE_UNKNOWN
    _SQUID_INLINE_ void setMaxStale(int32_t max_stale);
    _SQUID_INLINE_ int32_t getMaxStale() const;

    /// stale-if-error setter. Clear by setting to STALE_IF_ERROR_UNKNOWN
    _SQUID_INLINE_ void setStaleIfError(int32_t stale_if_error);
    _SQUID_INLINE_ int32_t getStaleIfError() const;

    /// min-fresh setter. Clear by setting to MIN_FRESH_UNKNOWN
    _SQUID_INLINE_ void setMinFresh(int32_t min_fresh);
    _SQUID_INLINE_ int32_t getMinFresh() const;

    /// set an attribute value or clear it (by supplying false as the second argument)
    _SQUID_INLINE_ void set(http_hdr_cc_type id, bool newval=true);
    /// check whether the attribute value supplied by id is set
    _SQUID_INLINE_ bool isSet(http_hdr_cc_type id) const;

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
